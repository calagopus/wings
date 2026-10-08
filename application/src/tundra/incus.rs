use super::{TundraManager, daemon};
use crate::routes::State;
use anyhow::{Context, ensure};
use std::process::Stdio;

pub async fn stop(manager: &TundraManager) -> anyhow::Result<()> {
    if !manager.disabled() {
        return Ok(());
    }
    if let Some(mut child) = manager.child.lock().await.take() {
        child
            .kill()
            .await
            .context("stopping the Incus Tundra node")?;
    }
    manager.hub.disconnect();
    Ok(())
}

pub async fn ensure(state: &State, manager: &TundraManager) -> anyhow::Result<()> {
    if !manager.serving() {
        return Ok(());
    }
    let cfg = state.config.load();
    let Some(own) = manager.cached().and_then(|snapshot| {
        snapshot
            .nodes
            .iter()
            .find(|node| node.uuid == cfg.uuid)
            .cloned()
    }) else {
        return Ok(());
    };
    ensure!(
        cfg.tundra.binary.as_path(&cfg).as_os_str().is_empty(),
        "Incus private networking uses the bundled Tundra node; leave tundra.binary empty"
    );
    let executable = std::env::current_exe()?;
    let hosts = cfg
        .system
        .vmount_directory
        .as_path(&cfg)
        .join("{server}")
        .join("hosts");
    let mut rendered: serde_json::Value = serde_norway::from_str(&daemon::render_config(
        manager,
        own.tunnel_port,
        cfg.tundra.metrics_port,
        &hosts,
    )?)?;
    *rendered
        .get_mut("restart")
        .and_then(|restart| restart.get_mut("binary_path"))
        .context("Tundra restart configuration missing")? = executable.display().to_string().into();
    let path = manager.data_dir.join("config.yml");
    let changed = daemon::sync_config(&path, &serde_norway::to_string(&rendered)?)?;
    let mut slot = manager.child.lock().await;
    if let Some(child) = slot.as_mut() {
        if child.try_wait()?.is_none() && !changed {
            return Ok(());
        }
        if child.try_wait()?.is_none() {
            child.kill().await?;
        }
        *slot = None;
    }
    if !manager.serving() {
        return Ok(());
    }
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("--config")
        .arg(path)
        .env("WINGS_TUNDRA_CHILD", "1")
        .env("WINGS_INCUS_SOCKET", &cfg.runtime.incus.socket)
        .env("WINGS_INCUS_PROJECT", &cfg.runtime.incus.project)
        .env("WINGS_INCUS_OWNER", format!("wings:{}", cfg.uuid))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let parent = rustix::process::getpid();
    unsafe {
        command.pre_exec(move || {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
            if rustix::process::getppid() != Some(parent) {
                return Err(std::io::Error::from_raw_os_error(3));
            }
            Ok(())
        });
    }
    *slot = Some(
        command
            .spawn()
            .context("starting the bundled Incus Tundra node")?,
    );
    tracing::info!(
        tunnel_port = own.tunnel_port,
        "started the Incus Tundra node"
    );
    Ok(())
}
