//! Console input, written straight to the instance's terminal as docker does.
//!
//! The Incus console API is not used: it writes `ESC c` into the input whenever a session ends,
//! and allows only one session at a time. Instead Wings borrows the master side of the console
//! terminal from the liblxc monitor process that owns it.

use anyhow::{Context, ensure};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fd::OwnedFd,
    process::{Pid, PidfdFlags, PidfdGetfdFlags},
};
use std::os::unix::fs::MetadataExt;

/// The major device number of the first 256 pseudoterminals.
const PTY_MAJOR: u32 = 136;
const WRITE_CHUNK: usize = 1024;
const WRITE_TIMEOUT: Timespec = Timespec {
    tv_sec: 5,
    tv_nsec: 0,
};

pub(super) struct Terminal {
    master: OwnedFd,
}

/// The parent of a process, from the contents of its `/proc/<pid>/stat`.
fn parent(stat: &str) -> Option<i32> {
    // The command name is in parentheses and may itself contain spaces and parentheses.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The number of the terminal an open pseudoterminal master controls.
fn terminal_index(fdinfo: &str) -> Option<u32> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("tty-index:"))?
        .trim()
        .parse()
        .ok()
}

impl Terminal {
    /// Opens the console of the instance whose first process has the host PID `init`.
    pub(super) fn open(init: u32, instance: &str) -> anyhow::Result<Self> {
        let console = std::fs::metadata(format!("/proc/{init}/root/dev/console"))
            .context("finding the instance console")?
            .rdev();
        let major = rustix::fs::major(console);
        ensure!(major >= PTY_MAJOR, "the instance console is not a terminal");
        let index = (major - PTY_MAJOR) * 256 + rustix::fs::minor(console);

        let monitor = parent(&std::fs::read_to_string(format!("/proc/{init}/stat"))?)
            .context("finding the instance monitor")?;
        // Make sure the PID still belongs to this instance before taking anything from it.
        let command = std::fs::read(format!("/proc/{monitor}/cmdline"))?;
        let command = String::from_utf8_lossy(&command);
        ensure!(
            command.starts_with("[lxc monitor]")
                && command.trim_end_matches(['\0', ' ']).ends_with(instance),
            "process {monitor} is not the monitor of {instance}"
        );
        let pidfd = rustix::process::pidfd_open(
            Pid::from_raw(monitor).context("invalid monitor PID")?,
            PidfdFlags::empty(),
        )
        .context("opening the instance monitor")?;

        for entry in std::fs::read_dir(format!("/proc/{monitor}/fd"))? {
            let entry = entry?;
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if !target.ends_with("ptmx") {
                continue;
            }
            let name = entry.file_name();
            let Ok(info) = std::fs::read_to_string(format!(
                "/proc/{monitor}/fdinfo/{}",
                name.to_string_lossy()
            )) else {
                continue;
            };
            if terminal_index(&info) != Some(index) {
                continue;
            }
            let descriptor = name.to_string_lossy().parse()?;
            let master = rustix::process::pidfd_getfd(&pidfd, descriptor, PidfdGetfdFlags::empty())
                .context("taking the console terminal from the instance monitor")?;
            let size = rustix::termios::Winsize {
                ws_row: 40,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if let Err(err) = rustix::termios::tcsetwinsize(&master, size) {
                tracing::debug!(instance, "could not set the console size: {err}");
            }
            return Ok(Self { master });
        }
        anyhow::bail!("the console terminal of {instance} was not found")
    }

    /// Types `data` into the console. Blocks while the terminal's input buffer is full.
    pub(super) fn write(&self, data: &[u8]) -> std::io::Result<()> {
        for mut chunk in data.chunks(WRITE_CHUNK) {
            while !chunk.is_empty() {
                // The descriptor is shared with the monitor, so it cannot be made non-blocking.
                let mut ready = [PollFd::new(&self.master, PollFlags::OUT)];
                if rustix::event::poll(&mut ready, Some(&WRITE_TIMEOUT))? == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the server is not reading its console input",
                    ));
                }
                let written = rustix::io::write(&self.master, chunk)?;
                chunk = chunk.get(written..).unwrap_or_default();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_information_is_parsed() {
        assert_eq!(parent("42 (a) b) c) S 7 42 42 0"), Some(7));
        assert_eq!(parent("garbage"), None);
        assert_eq!(terminal_index("pos:\t0\ntty-index:\t3\n"), Some(3));
        assert_eq!(terminal_index("pos:\t0\n"), None);
    }
}
