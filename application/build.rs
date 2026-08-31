use serde::Deserialize;
use std::{fs::File, io::Write, path::Path, process::Command};

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FUSEQUOTA_RELEASE");
    println!("cargo:rerun-if-env-changed=FUSEQUOTA_BINARY_PATH");

    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_env =
        std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=CARGO_TARGET={target_arch}-{target_env}");

    handle_git_info();
    handle_fusequota(&target_arch, &target_os);
    handle_seccomp();
}

#[allow(clippy::panic)]
fn handle_fusequota(target_arch: &str, target_os: &str) {
    let release_env = std::env::var("FUSEQUOTA_RELEASE").unwrap_or_default();
    let binary_path_env = std::env::var("FUSEQUOTA_BINARY_PATH").unwrap_or_default();

    let bin_dir = Path::new("bins");
    if !bin_dir.exists() {
        std::fs::create_dir_all(bin_dir).ok();
    }

    let bin_path = bin_dir.join("fusequota");
    let version_path = bin_dir.join("fusequota.version");

    if !binary_path_env.is_empty() {
        let source_data = std::fs::read(&binary_path_env).unwrap_or_else(|err| {
            panic!("Failed to read FUSEQUOTA_BINARY_PATH {binary_path_env}: {err}")
        });

        println!(
            "cargo:warning=Compressing fusequota from local path {binary_path_env} ({} bytes)...",
            source_data.len()
        );

        let compressed_data = zstd::encode_all(source_data.as_slice(), 22)
            .expect("Failed to compress binary with zstd");

        let mut file = File::create(&bin_path).expect("Failed to create bin");
        file.write_all(&compressed_data)
            .expect("Failed to write compressed bin");

        let version = if release_env.is_empty() {
            "nightly".to_string()
        } else {
            release_env
        };
        std::fs::write(&version_path, &version).ok();

        println!("cargo:rustc-env=FUSEQUOTA_VERSION={version}");
        return;
    }

    let existing_version = std::fs::read_to_string(&version_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let mut final_version = existing_version.clone();

    let has_usable_bin = std::fs::metadata(&bin_path).is_ok_and(|meta| meta.len() > 0);

    let should_check_github = if release_env.starts_with("latest") {
        true
    } else if release_env.is_empty() && has_usable_bin {
        false
    } else {
        !has_usable_bin || (!release_env.is_empty() && release_env != existing_version)
    };

    if should_check_github
        && target_os == "linux"
        && let Some((tag, url)) = fetch_release_metadata(target_arch)
        && (tag != existing_version || release_env.starts_with("latest"))
        && let Ok(mut resp) = ureq::get(url).call()
        && resp.status().is_success()
    {
        println!(
            "cargo:warning=Downloading and compressing fusequota version {tag} for {target_arch} from GitHub..."
        );

        let compressed_data = zstd::encode_all(resp.body_mut().as_reader(), 22)
            .expect("Failed to compress binary with zstd");

        println!(
            "cargo:warning=Compressed binary size: {} bytes -> {} bytes",
            resp.headers()
                .get("Content-Length")
                .map_or("?", |v| v.to_str().unwrap_or("?")),
            compressed_data.len()
        );

        let mut file = File::create(&bin_path).expect("Failed to create bin");
        file.write_all(&compressed_data)
            .expect("Failed to write compressed bin");

        std::fs::write(&version_path, &tag).ok();
        final_version = tag;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755)).ok();
        }
    }

    if !std::fs::metadata(&bin_path).is_ok_and(|meta| meta.len() > 0) {
        if target_os == "linux" {
            panic!(
                "failed to obtain a fusequota binary for {target_arch}, refusing to build without one, set FUSEQUOTA_BINARY_PATH to build from a local binary"
            );
        }

        File::create(&bin_path).ok();
    }

    println!("cargo:rustc-env=FUSEQUOTA_VERSION={final_version}");
}

fn fetch_release_metadata(arch: &str) -> Option<(String, String)> {
    let mut resp = ureq::get("https://api.github.com/repos/calagopus/fusequota/releases/latest")
        .header("User-Agent", "rust-build-script")
        .call()
        .ok()?;
    let release: GithubRelease = serde_json::from_reader(resp.body_mut().as_reader()).ok()?;

    let release_arch = match arch {
        "powerpc64" => "ppc64le",
        arch => arch,
    };

    let expected_name = format!("fusequota-{release_arch}-linux");
    let asset = release
        .assets
        .into_iter()
        .find(|a| a.name == expected_name)?;

    Some((release.tag_name, asset.browser_download_url))
}

fn handle_git_info() {
    let is_git_repo = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    let mut git_hash = "unknown".to_string();

    if is_git_repo {
        println!("cargo:rerun-if-changed=../.git/HEAD");

        if let Ok(head) = std::fs::read_to_string("../.git/HEAD")
            && head.starts_with("ref: ")
        {
            let head_ref = head.trim_start_matches("ref: ").trim();
            println!("cargo:rerun-if-changed=../.git/{head_ref}");
            println!(
                "cargo:rustc-env=CARGO_GIT_BRANCH={}",
                head_ref.rsplit('/').next().unwrap_or("unknown")
            );
        } else {
            println!("cargo:rustc-env=CARGO_GIT_BRANCH=unknown");
        }
        println!("cargo:rerun-if-changed=../.git/index");

        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            && output.status.success()
        {
            git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    println!("cargo:rustc-env=CARGO_GIT_COMMIT={git_hash}");
}

fn handle_seccomp() {
    println!("cargo:rerun-if-changed=seccomp.json");
    let seccomp_path = Path::new("seccomp.json");
    if seccomp_path.exists() {
        let seccomp = std::fs::read_to_string(seccomp_path).expect("Failed to read seccomp.json");
        let val: serde_json::Value =
            serde_json::from_str(&seccomp).expect("Failed to parse seccomp.json");
        let seccomp_min = serde_json::to_string(&val).expect("Failed to serialize");
        std::fs::write("seccomp.min.json", seccomp_min).expect("Failed to write seccomp.min.json");
    }
}
