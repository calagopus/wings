use anyhow::Context;
use sha2::Digest;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

pub const PROVIDER: &str = env!("WINGS_UPGRADE_PROVIDER");
pub const REPOSITORY: &str = env!("WINGS_UPGRADE_REPOSITORY");
pub const API_URL: &str = env!("WINGS_UPGRADE_API_URL");

const MAX_BINARY_SIZE: u64 = 512 * 1024 * 1024;
const SMOKE_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CHECK_TTL: Duration = Duration::from_secs(30 * 60);
const CHECK_FAILURE_TTL: Duration = Duration::from_secs(5 * 60);

#[cfg(windows)]
const PREVIOUS_PID_ENV: &str = "WINGS_UPGRADE_PREVIOUS_PID";

pub enum VersionRequest {
    Latest,
    Exact(semver::Version),
}

impl std::str::FromStr for VersionRequest {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("latest") {
            Ok(Self::Latest)
        } else {
            semver::Version::parse(s.strip_prefix('v').unwrap_or(s)).map(Self::Exact)
        }
    }
}

pub struct Release {
    pub version: semver::Version,
    download_url: String,
    accept: Option<&'static str>,
    sha256: [u8; 32],
    size: u64,
}

#[derive(Clone, Copy)]
pub enum ReleaseProvider {
    Github,
}

impl ReleaseProvider {
    /// The compiled provider, if it publishes assets for this platform at all.
    pub fn available() -> Option<Self> {
        asset_name()?;

        match PROVIDER {
            "github" => Some(Self::Github),
            _ => None,
        }
    }

    /// `Ok(None)` when the release or the asset for this platform does not exist.
    pub async fn resolve(
        self,
        client: &reqwest::Client,
        version: &VersionRequest,
        token: Option<&str>,
    ) -> Result<Option<Release>, anyhow::Error> {
        let asset_name = asset_name().context("no release assets are built for this platform")?;

        match self {
            Self::Github => github::resolve(client, version, &asset_name, token).await,
        }
    }
}

mod github {
    use super::{Release, VersionRequest};
    use anyhow::Context;
    use serde::Deserialize;

    const TAG_PREFIX: &str = "release-";

    #[derive(Deserialize)]
    struct GithubRelease {
        tag_name: String,
        assets: Vec<GithubAsset>,
    }

    #[derive(Deserialize)]
    struct GithubAsset {
        name: String,
        url: String,
        size: u64,
        digest: Option<String>,
    }

    pub async fn resolve(
        client: &reqwest::Client,
        version: &VersionRequest,
        asset_name: &str,
        token: Option<&str>,
    ) -> Result<Option<Release>, anyhow::Error> {
        let url = match version {
            VersionRequest::Latest => {
                format!(
                    "{}/repos/{}/releases/latest",
                    super::API_URL,
                    super::REPOSITORY
                )
            }
            VersionRequest::Exact(version) => format!(
                "{}/repos/{}/releases/tags/{TAG_PREFIX}{version}",
                super::API_URL,
                super::REPOSITORY
            ),
        };

        let mut request = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await.map_err(|err| err.without_url())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let release: GithubRelease = response
            .error_for_status()
            .map_err(|err| err.without_url())?
            .json()
            .await
            .map_err(|err| err.without_url())?;

        let version = release
            .tag_name
            .strip_prefix(TAG_PREFIX)
            .and_then(|version| semver::Version::parse(version).ok())
            .with_context(|| format!("release tag {:?} is not a version", release.tag_name))?;

        let Some(asset) = release.assets.into_iter().find(|a| a.name == asset_name) else {
            return Ok(None);
        };

        let sha256 = asset
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .and_then(|digest| hex::decode(digest).ok())
            .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
            .with_context(|| format!("release asset {asset_name} has no sha256 digest"))?;

        Ok(Some(Release {
            version,
            download_url: asset.url,
            accept: Some("application/octet-stream"),
            sha256,
            size: asset.size,
        }))
    }
}

#[derive(Clone)]
pub struct Check {
    pub latest: Option<semver::Version>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

type CheckCache = HashMap<Option<[u8; 32]>, (Instant, Result<Check, String>)>;

static CHECKS: LazyLock<tokio::sync::Mutex<CheckCache>> = LazyLock::new(Default::default);

pub async fn check(
    provider: ReleaseProvider,
    client: &reqwest::Client,
    token: Option<&str>,
    force: bool,
) -> Result<Check, String> {
    let key = token.map(|token| <[u8; 32]>::from(sha2::Sha256::digest(token)));

    let mut checks = CHECKS.lock().await;
    if !force
        && let Some((at, result)) = checks.get(&key)
        && at.elapsed()
            < if result.is_ok() {
                CHECK_TTL
            } else {
                CHECK_FAILURE_TTL
            }
    {
        return result.clone();
    }

    let result = provider
        .resolve(client, &VersionRequest::Latest, token)
        .await
        .map(|release| Check {
            latest: release.map(|release| release.version),
            checked_at: chrono::Utc::now(),
        })
        .map_err(|err| format!("{err:#}"));
    checks.insert(key, (Instant::now(), result.clone()));

    result
}

fn asset_name() -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
        "powerpc64" => return None,
        arch => arch,
    };

    match std::env::consts::OS {
        "linux" => Some(format!("wings-rs-{arch}-linux")),
        "windows" => Some(format!("wings-rs-{arch}-windows.exe")),
        _ => None,
    }
}

pub fn current_version() -> Result<semver::Version, anyhow::Error> {
    Ok(semver::Version::parse(crate::VERSION)?)
}

pub fn executable() -> Result<PathBuf, anyhow::Error> {
    let executable = std::env::current_exe()?;
    if executable.to_string_lossy().ends_with(" (deleted)") {
        return Err(anyhow::anyhow!(
            "the running binary was replaced on disk, restart wings first"
        ));
    }

    Ok(executable)
}

fn on_api_origin(url: &str) -> bool {
    match (url::Url::parse(url), url::Url::parse(API_URL)) {
        (Ok(url), Ok(api)) => url.origin() == api.origin(),
        _ => false,
    }
}

pub async fn download(
    client: &reqwest::Client,
    release: &Release,
    token: Option<&str>,
    executable: &Path,
) -> Result<tempfile::TempPath, anyhow::Error> {
    if release.size > MAX_BINARY_SIZE {
        return Err(anyhow::anyhow!(
            "release asset is larger than {MAX_BINARY_SIZE} bytes"
        ));
    }

    let directory = executable
        .parent()
        .context("executable has no parent directory")?;
    let staged = tempfile::Builder::new()
        .prefix(".wings-upgrade-")
        .tempfile_in(directory)?;
    let (file, path) = staged.into_parts();
    let mut file = tokio::fs::File::from_std(file);

    let mut request = client.get(&release.download_url);
    if let Some(accept) = release.accept {
        request = request.header(reqwest::header::ACCEPT, accept);
    }
    if let Some(token) = token
        && on_api_origin(&release.download_url)
    {
        request = request.bearer_auth(token);
    }

    let mut response = request
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|err| err.without_url())?;

    let mut hasher = sha2::Sha256::new();
    let mut written = 0u64;

    while let Some(chunk) = response.chunk().await.map_err(|err| err.without_url())? {
        written += chunk.len() as u64;
        if written > release.size {
            return Err(anyhow::anyhow!(
                "release asset is larger than the provider reported"
            ));
        }

        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }

    if written != release.size {
        return Err(anyhow::anyhow!(
            "release asset is {written} bytes, the provider reported {}",
            release.size
        ));
    }
    if hasher.finalize().as_slice() != release.sha256 {
        return Err(anyhow::anyhow!(
            "release asset does not match the provider's sha256 digest"
        ));
    }

    file.flush().await?;
    file.sync_all().await?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    Ok(path)
}

pub async fn smoke_test(path: &Path, version: &semver::Version) -> Result<(), anyhow::Error> {
    let mut attempts = 0;
    let output = loop {
        let output = tokio::time::timeout(
            SMOKE_TEST_TIMEOUT,
            tokio::process::Command::new(path)
                .arg("--version")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("new binary did not answer --version in time")?;

        match output {
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 5 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            output => break output.context("failed to run new binary")?,
        }
    };

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "new binary exited with {} on --version",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let reported = stdout
        .split_whitespace()
        .nth(1)
        .and_then(|reported| reported.split(':').next())
        .unwrap_or_default();
    if semver::Version::parse(reported).ok().as_ref() != Some(version) {
        return Err(anyhow::anyhow!(
            "new binary reports version {reported:?}, expected {version}"
        ));
    }

    Ok(())
}

#[cfg(unix)]
pub fn replace_and_restart(staged: tempfile::TempPath, executable: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;

    if let Err(err) = staged.persist(executable) {
        return err.error.into();
    }

    let mut args = std::env::args_os();
    let mut command = std::process::Command::new(executable);
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }

    command.args(args).exec().into()
}

#[cfg(windows)]
pub fn replace_and_restart(staged: tempfile::TempPath, executable: &Path) -> anyhow::Error {
    if let Err(err) = self_replace::self_replace(&staged) {
        return err.into();
    }
    drop(staged);

    match std::process::Command::new(executable)
        .args(std::env::args_os().skip(1))
        .env(PREVIOUS_PID_ENV, std::process::id().to_string())
        .spawn()
    {
        Ok(_) => std::process::exit(0),
        Err(err) => err.into(),
    }
}

#[cfg(windows)]
pub fn wait_for_previous_process() {
    let Some(pid) = std::env::var(PREVIOUS_PID_ENV)
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
    else {
        return;
    };

    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    while std::time::Instant::now() < deadline {
        system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if system.process(pid).is_none() {
            return;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn serve_once(body: Vec<u8>) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/asset", listener.local_addr().unwrap());

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;

            String::from_utf8_lossy(&head).into_owned()
        });

        (url, handle)
    }

    fn release(download_url: String, payload: &[u8], size: u64) -> Release {
        Release {
            version: semver::Version::new(1, 2, 7),
            download_url,
            accept: Some("application/octet-stream"),
            sha256: sha2::Sha256::digest(payload).into(),
            size,
        }
    }

    fn staged_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".wings-upgrade-"))
            .collect()
    }

    #[cfg(unix)]
    fn write_script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("wings");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        path
    }

    // VersionRequest
    #[test]
    fn version_request_parsing() {
        for latest in ["latest", "LATEST", "Latest"] {
            assert!(matches!(
                latest.parse::<VersionRequest>(),
                Ok(VersionRequest::Latest)
            ));
        }

        let expected = semver::Version::new(1, 2, 7);
        for exact in ["1.2.7", "v1.2.7"] {
            match exact.parse::<VersionRequest>() {
                Ok(VersionRequest::Exact(version)) => assert_eq!(version, expected),
                _ => panic!("{exact} not parsed as an exact version"),
            }
        }

        match "1.3.0-pre.1".parse::<VersionRequest>() {
            Ok(VersionRequest::Exact(version)) => {
                assert_eq!(version, semver::Version::parse("1.3.0-pre.1").unwrap())
            }
            _ => panic!("pre-release not accepted"),
        }

        for invalid in ["vv1.2.3", "", "v", "garbage", "1.2", "latest1"] {
            assert!(
                invalid.parse::<VersionRequest>().is_err(),
                "{invalid:?} accepted"
            );
        }
    }

    // asset_name
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn asset_name_matches_ci_x86_64() {
        assert_eq!(asset_name().as_deref(), Some("wings-rs-x86_64-linux"));
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn asset_name_matches_ci_aarch64() {
        assert_eq!(asset_name().as_deref(), Some("wings-rs-aarch64-linux"));
    }

    // on_api_origin
    #[test]
    fn token_only_goes_to_api_origin() {
        assert!(on_api_origin(&format!(
            "{API_URL}/repos/x/y/releases/assets/1"
        )));
        assert!(!on_api_origin("https://objects.githubusercontent.com/x"));
        assert!(!on_api_origin("http://127.0.0.1:9999/assets/1"));
        assert!(!on_api_origin("not a url"));
    }

    // download
    #[test]
    fn download_accepts_matching_asset() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let payload = b"#!/bin/sh\necho new wings\n".to_vec();
            let (url, server) = serve_once(payload.clone()).await;
            let release = release(url, &payload, payload.len() as u64);

            let staged = download(
                &reqwest::Client::new(),
                &release,
                Some("secret-token"),
                &dir.path().join("wings"),
            )
            .await
            .unwrap();

            assert_eq!(staged.parent(), Some(dir.path()));
            assert_eq!(std::fs::read(&staged).unwrap(), payload);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o755);
            }

            let head = server.await.unwrap().to_ascii_lowercase();
            assert!(!head.contains("authorization"));
            assert!(head.contains("accept: application/octet-stream"));
        })
    }

    #[test]
    fn download_rejects_digest_mismatch() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let payload = b"tampered binary".to_vec();
            let (url, _server) = serve_once(payload.clone()).await;
            let release = release(url, b"expected binary", payload.len() as u64);

            let result = download(
                &reqwest::Client::new(),
                &release,
                None,
                &dir.path().join("wings"),
            )
            .await;

            assert!(result.is_err());
            assert!(staged_files(dir.path()).is_empty());
        })
    }

    #[test]
    fn download_rejects_oversized_body() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let payload = vec![7u8; 64 * 1024];
            let (url, _server) = serve_once(payload.clone()).await;
            let release = release(url, &payload, 1024);

            let result = download(
                &reqwest::Client::new(),
                &release,
                None,
                &dir.path().join("wings"),
            )
            .await;

            assert!(result.is_err());
            assert!(staged_files(dir.path()).is_empty());
        })
    }

    #[test]
    fn download_rejects_truncated_body() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let payload = vec![7u8; 1024];
            let (url, _server) = serve_once(payload[..512].to_vec()).await;
            let release = release(url, &payload, payload.len() as u64);

            let result = download(
                &reqwest::Client::new(),
                &release,
                None,
                &dir.path().join("wings"),
            )
            .await;

            assert!(result.is_err());
            assert!(staged_files(dir.path()).is_empty());
        })
    }

    #[test]
    fn download_rejects_size_over_cap_without_request() {
        tokio_test::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let release = release(
                "http://127.0.0.1:1/unreachable".to_string(),
                b"",
                512 * 1024 * 1024 + 1,
            );

            let result = download(
                &reqwest::Client::new(),
                &release,
                None,
                &dir.path().join("wings"),
            )
            .await;

            assert!(result.is_err());
            assert!(staged_files(dir.path()).is_empty());
        })
    }

    // smoke_test
    #[cfg(unix)]
    #[test]
    fn smoke_test_checks_version_output() {
        tokio_test::block_on(async {
            let expected = semver::Version::new(1, 2, 7);
            let script = |output: &str, code: u8| {
                format!(
                    "#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 3\necho '{output}'\nexit {code}\n"
                )
            };

            let cases = [
                ("calagopus-wings 1.2.7:abc@main", 0, true),
                ("calagopus-wings 1.2.7", 0, true),
                ("calagopus-wings 1.2.8:abc@main", 0, false),
                ("calagopus-wings 1.2.7", 1, false),
                ("calagopus-wings", 0, false),
            ];

            for (output, code, ok) in cases {
                let dir = tempfile::tempdir().unwrap();
                let path = write_script(dir.path(), &script(output, code));
                let result = smoke_test(&path, &expected).await;
                assert_eq!(result.is_ok(), ok, "{output:?} exit {code}: {result:?}");
            }
        })
    }
}
