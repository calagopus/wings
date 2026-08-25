use crate::routes::MimeCacheValue;
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub fn draw_progress_bar(width: usize, current: f64, total: f64) -> String {
    let progress_percentage = (current / total) * 100.0;
    let formatted_percentage = if progress_percentage.is_finite() {
        &format!("{:.2}%", progress_percentage)
    } else {
        "0.00%"
    };

    let completed_width = std::cmp::min(
        (progress_percentage / 100.0 * width as f64).round() as usize,
        width,
    );
    let remaining_width = width - completed_width;

    let bar = if completed_width == width {
        "=".repeat(width)
    } else {
        format!(
            "{}{}{}",
            "=".repeat(completed_width),
            ">",
            " ".repeat(remaining_width.saturating_sub(1))
        )
    };

    format!("[{bar}] {formatted_percentage}")
}

pub fn is_single_component_file_name(name: &str) -> bool {
    let mut components = Path::new(name).components();

    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(component)), None) => component.to_str() == Some(name),
        _ => false,
    }
}

pub fn parse_content_disposition_filename(header: &str) -> Option<String> {
    static RE_STAR: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)filename\*=utf-8''([^;]+)").expect("Failed to compile regex")
    });

    if let Some(caps) = RE_STAR.captures(header) {
        let encoded_filename = caps.get(1)?.as_str();

        if let Ok(decoded) = percent_encoding::percent_decode_str(encoded_filename).decode_utf8() {
            return Some(decoded.into_owned());
        }
    }

    static RE_LEGACY: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)filename="?([^";]+)"?"#).expect("Failed to compile regex")
    });

    if let Some(caps) = RE_LEGACY.captures(header) {
        return Some(caps.get(1)?.as_str().into());
    }

    None
}

pub fn detect_utf8_from_mime(mime: &str) -> bool {
    const ADDITIONAL_TEXT_MIME_TYPES: &[&str] = &[
        "application/json",
        "application/javascript",
        "application/xml",
        "application/x-yaml",
        "application/yaml",
        "application/toml",
        "application/sql",
        "application/x-sh",
        "application/x-httpd-php",
        "image/svg+xml",
    ];

    mime.starts_with("text/") || ADDITIONAL_TEXT_MIME_TYPES.contains(&mime)
}

pub fn detect_inner_utf8(path: &Path, mime: &str) -> bool {
    let compression_type = crate::io::compression::CompressionType::from_mime(mime);

    if matches!(
        compression_type,
        crate::io::compression::CompressionType::None
    ) {
        return false;
    }

    let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };

    if let Some(stem_mime) = new_mime_guess::from_path(file_stem).first_raw() {
        detect_utf8_from_mime(stem_mime)
    } else {
        false
    }
}

pub fn detect_mime_type(path: &Path, buffer: Option<&[u8]>) -> MimeCacheValue {
    let valid_utf8 = buffer.is_some_and(|buffer| is_valid_utf8_slice(buffer) || buffer.is_empty());

    if let Some(buffer) = buffer
        && let Some(mime) = infer::get(buffer)
    {
        MimeCacheValue {
            mime: mime.mime_type(),
            valid_utf8,
            valid_inner_utf8: detect_inner_utf8(path, mime.mime_type()),
        }
    } else if let Some(mime) = new_mime_guess::from_path(path).first_raw() {
        MimeCacheValue {
            mime,
            valid_utf8: valid_utf8 || detect_utf8_from_mime(mime),
            valid_inner_utf8: detect_inner_utf8(path, mime),
        }
    } else if valid_utf8 {
        MimeCacheValue {
            mime: "text/plain",
            valid_utf8: true,
            valid_inner_utf8: false,
        }
    } else {
        MimeCacheValue {
            mime: "application/octet-stream",
            valid_utf8: false,
            valid_inner_utf8: false,
        }
    }
}

pub fn deduplicate_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    if paths.is_empty() {
        return Vec::new();
    }

    paths.sort();
    paths.dedup();

    let mut unique = Vec::new();
    for path in paths {
        if let Some(last) = unique.last()
            && path.starts_with(last)
        {
            continue;
        }

        unique.push(path);
    }

    unique
}

#[inline]
pub fn is_valid_utf8_slice(s: &[u8]) -> bool {
    match str::from_utf8(s) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

pub async fn read_limited_multipart_field(
    field: &mut axum::extract::multipart::Field<'_>,
    max_len: usize,
) -> Result<String, anyhow::Error> {
    let mut buf = String::new();
    while let Some(chunk) = field.chunk().await? {
        if buf.len().saturating_add(chunk.len()) > max_len {
            anyhow::bail!("multipart field exceeds maximum length of {max_len} bytes");
        }
        buf.push_str(&String::from_utf8_lossy(&chunk));
    }
    Ok(buf)
}

pub fn strip_paths(value: &mut serde_json::Value, paths: &[&str]) {
    for path in paths {
        let mut cursor = &mut *value;
        let mut parts = path.split('.').peekable();

        while let Some(part) = parts.next() {
            let serde_json::Value::Object(map) = cursor else {
                break;
            };

            if parts.peek().is_none() {
                map.remove(part);
                break;
            }

            if map.get(part).is_some_and(|next| !next.is_object()) {
                map.remove(part);
                break;
            }

            match map.get_mut(part) {
                Some(next) => cursor = next,
                None => break,
            }
        }
    }
}

pub(crate) trait IntoMode {
    fn into_mode(self) -> u16;
}
macro_rules! impl_into_mode {
    ($($t:ty),*) => {
        $(impl IntoMode for $t {
            fn into_mode(self) -> u16 {
                self as u16
            }
        })*
    };
}
impl_into_mode!(i32, u16, u32, u64, usize);

/// PortablePermissions is a wrapper around a u32 representing file permissions in a portable way.
/// It only covers the lower 9 bits of the mode, which correspond to the standard Unix permission bits (rwx for user, group, and others).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortablePermissions {
    mode: u16,
}

impl PortablePermissions {
    /// Creates a new `PortablePermissions` from a given mode, masking to the lower 9 bits.
    /// This variant specifically sets the file permissions to be at least readable and writable by the owner (0o600).
    #[inline]
    pub fn from_mode_file(mode: impl IntoMode) -> Self {
        Self {
            mode: mode.into_mode() & 0o777 | 0o600,
        }
    }

    /// Creates a new `PortablePermissions` from a given mode, masking to the lower 9 bits.
    /// This variant specifically sets the directory permissions to be at least readable, writable, and executable by the owner (0o700).
    #[inline]
    pub fn from_mode_dir(mode: impl IntoMode) -> Self {
        Self {
            mode: mode.into_mode() & 0o777 | 0o700,
        }
    }

    /// Returns the underlying mode of the `PortablePermissions`.
    #[inline]
    pub fn mode(&self) -> u16 {
        self.mode
    }

    #[inline]
    pub fn into_std_permissions(self) -> Option<std::fs::Permissions> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(std::fs::Permissions::from_mode(self.mode as _))
        }
        #[cfg(windows)]
        None
    }
}

#[cfg(unix)]
impl From<std::fs::Permissions> for PortablePermissions {
    fn from(perms: std::fs::Permissions) -> Self {
        Self {
            mode: std::os::unix::fs::PermissionsExt::mode(&perms) as u16 & 0o777,
        }
    }
}

#[cfg(unix)]
impl From<cap_std::fs::Permissions> for PortablePermissions {
    fn from(perms: cap_std::fs::Permissions) -> Self {
        Self {
            mode: cap_std::fs::PermissionsExt::mode(&perms) as u16 & 0o777,
        }
    }
}

#[cfg(not(unix))]
impl From<std::fs::Permissions> for PortablePermissions {
    fn from(perms: std::fs::Permissions) -> Self {
        Self {
            mode: if perms.readonly() { 0o444 } else { 0o666 },
        }
    }
}

#[cfg(not(unix))]
impl From<cap_std::fs::Permissions> for PortablePermissions {
    fn from(perms: cap_std::fs::Permissions) -> Self {
        Self {
            mode: if perms.readonly() { 0o444 } else { 0o666 },
        }
    }
}

pub trait PortablePermissionsApplier {
    fn apply_permissions(&self, new_permissions: PortablePermissions) -> std::io::Result<()>;
}

#[cfg(unix)]
impl PortablePermissionsApplier for std::fs::File {
    fn apply_permissions(&self, new_permissions: PortablePermissions) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(new_permissions.mode as _);
        self.set_permissions(permissions)
    }
}

#[cfg(unix)]
impl PortablePermissionsApplier for cap_std::fs::File {
    fn apply_permissions(&self, new_permissions: PortablePermissions) -> std::io::Result<()> {
        use cap_std::fs::PermissionsExt;

        let permissions = cap_std::fs::Permissions::from_mode(new_permissions.mode as _);
        self.set_permissions(permissions)
    }
}

#[cfg(not(unix))]
impl PortablePermissionsApplier for std::fs::File {
    fn apply_permissions(&self, new_permissions: PortablePermissions) -> std::io::Result<()> {
        let mut permissions = self.metadata()?.permissions();
        permissions.set_readonly(new_permissions.is_readonly());
        self.set_permissions(permissions)
    }
}

#[cfg(not(unix))]
impl PortablePermissionsApplier for cap_std::fs::File {
    fn apply_permissions(&self, new_permissions: PortablePermissions) -> std::io::Result<()> {
        let mut permissions = self.metadata()?.permissions();
        permissions.set_readonly(new_permissions.is_readonly());
        self.set_permissions(permissions)
    }
}

pub trait PortableSizeExt {
    fn size_logical(&self) -> u64;
    fn size_physical(&self) -> u64;
}

#[cfg(unix)]
impl PortableSizeExt for std::fs::Metadata {
    fn size_logical(&self) -> u64 {
        self.len()
    }

    fn size_physical(&self) -> u64 {
        std::os::unix::fs::MetadataExt::blocks(self) * 512
    }
}

#[cfg(unix)]
impl PortableSizeExt for cap_std::fs::Metadata {
    fn size_logical(&self) -> u64 {
        self.len()
    }

    fn size_physical(&self) -> u64 {
        cap_std::fs::MetadataExt::blocks(self) * 512
    }
}

#[cfg(not(unix))]
impl PortableSizeExt for std::fs::Metadata {
    fn size_logical(&self) -> u64 {
        self.len()
    }

    fn size_physical(&self) -> u64 {
        self.len()
    }
}

#[cfg(not(unix))]
impl PortableSizeExt for cap_std::fs::Metadata {
    fn size_logical(&self) -> u64 {
        self.len()
    }

    fn size_physical(&self) -> u64 {
        self.len()
    }
}

pub trait StdoutTakeExt: Sized {
    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, std::io::Error>;
    fn into_stdout(mut self) -> Result<std::process::ChildStdout, std::io::Error> {
        self.take_stdout()
    }
}

impl StdoutTakeExt for std::process::Child {
    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, std::io::Error> {
        self.stdout
            .take()
            .ok_or_else(|| std::io::Error::other("No stdout available"))
    }
}

pub trait TokioStdoutTakeExt: Sized {
    fn take_stdout(&mut self) -> Result<tokio::process::ChildStdout, std::io::Error>;
    fn into_stdout(mut self) -> Result<tokio::process::ChildStdout, std::io::Error> {
        self.take_stdout()
    }
}

impl TokioStdoutTakeExt for tokio::process::Child {
    fn take_stdout(&mut self) -> Result<tokio::process::ChildStdout, std::io::Error> {
        self.stdout
            .take()
            .ok_or_else(|| std::io::Error::other("No stdout available"))
    }
}

pub trait CmpExt {
    fn cmp_ascii_case_insensitive(&self, other: &Self) -> std::cmp::Ordering;
}

impl CmpExt for str {
    fn cmp_ascii_case_insensitive(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes()
            .map(|b| b.to_ascii_lowercase())
            .cmp(other.bytes().map(|b| b.to_ascii_lowercase()))
    }
}

impl CmpExt for Path {
    fn cmp_ascii_case_insensitive(&self, other: &Self) -> std::cmp::Ordering {
        self.as_os_str()
            .as_encoded_bytes()
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .cmp(
                other
                    .as_os_str()
                    .as_encoded_bytes()
                    .iter()
                    .map(|b| b.to_ascii_lowercase()),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    // is_single_component_file_name

    #[test]
    fn single_component_accepts_plain_file_names() {
        assert!(is_single_component_file_name("loot.txt"));
        assert!(is_single_component_file_name("wings.log"));
        assert!(is_single_component_file_name("wings.log.gz"));
        assert!(is_single_component_file_name("server.tar.gz"));
        assert!(is_single_component_file_name(".env"));
        assert!(is_single_component_file_name("..hidden"));
    }

    #[test]
    fn single_component_rejects_traversal_and_separators() {
        assert!(!is_single_component_file_name("../protected.jar"));
        assert!(!is_single_component_file_name("../protected.jar/."));
        assert!(!is_single_component_file_name("a/b"));
        assert!(!is_single_component_file_name("protected.jar/"));
    }

    #[test]
    fn single_component_rejects_the_decoded_log_traversals() {
        // what `%2Fetc%2Fshadow` and `%2Froot%2F.ssh%2Fid_rsa` decode to before the join
        assert!(!is_single_component_file_name("/etc/shadow"));
        assert!(!is_single_component_file_name("/root/.ssh/id_rsa"));
        assert!(!is_single_component_file_name("/proc/self/environ"));
    }

    #[test]
    fn single_component_rejects_empty_and_dot_names() {
        assert!(!is_single_component_file_name(""));
        assert!(!is_single_component_file_name("."));
        assert!(!is_single_component_file_name(".."));
        assert!(!is_single_component_file_name("./x"));
    }

    // draw_progress_bar

    fn bar_inner(s: &str) -> &str {
        let open = s.find('[').unwrap();
        let close = s.find(']').unwrap();
        &s[open + 1..close]
    }

    #[test]
    fn progress_bar_exact_renders() {
        assert_eq!(draw_progress_bar(10, 0.0, 100.0), "[>         ] 0.00%");
        assert_eq!(draw_progress_bar(10, 50.0, 100.0), "[=====>    ] 50.00%");
        assert_eq!(draw_progress_bar(10, 100.0, 100.0), "[==========] 100.00%");
    }

    #[test]
    fn progress_bar_over_100_clamps_fill_but_not_label() {
        assert_eq!(draw_progress_bar(10, 150.0, 100.0), "[==========] 150.00%");
    }

    #[test]
    fn progress_bar_non_finite_reads_as_zero() {
        assert_eq!(draw_progress_bar(10, 0.0, 0.0), "[>         ] 0.00%");
    }

    #[test]
    fn progress_bar_inner_width_is_constant() {
        for &(cur, total, width) in &[
            (0.0, 100.0, 10),
            (37.0, 100.0, 20),
            (100.0, 100.0, 8),
            (250.0, 100.0, 12),
            (0.0, 0.0, 15),
        ] {
            assert_eq!(
                bar_inner(&draw_progress_bar(width, cur, total))
                    .chars()
                    .count(),
                width
            );
        }
    }

    // parse_content_disposition_filename

    #[test]
    fn parse_filename_legacy_quoted() {
        let got = parse_content_disposition_filename("attachment; filename=\"example.txt\"");
        assert_eq!(got.as_deref(), Some("example.txt"));
    }

    #[test]
    fn parse_filename_legacy_unquoted() {
        let got = parse_content_disposition_filename("attachment; filename=example.txt");
        assert_eq!(got.as_deref(), Some("example.txt"));
    }

    #[test]
    fn parse_filename_rfc5987_percent_decoded() {
        let got = parse_content_disposition_filename(
            "attachment; filename*=UTF-8''My%20Report%20%282%29.pdf",
        );
        assert_eq!(got.as_deref(), Some("My Report (2).pdf"));
    }

    #[test]
    fn parse_filename_star_takes_precedence() {
        let got = parse_content_disposition_filename(
            "attachment; filename=\"fallback.txt\"; filename*=utf-8''real.txt",
        );
        assert_eq!(got.as_deref(), Some("real.txt"));
    }

    #[test]
    fn parse_filename_preserves_question_mark() {
        let got = parse_content_disposition_filename("attachment; filename=\"a?b.txt\"");
        assert_eq!(got.as_deref(), Some("a?b.txt"));
    }

    #[test]
    fn parse_filename_absent_is_none() {
        assert_eq!(parse_content_disposition_filename("attachment"), None);
    }

    // deduplicate_paths

    #[test]
    fn deduplicate_empty() {
        assert!(deduplicate_paths(Vec::new()).is_empty());
    }

    #[test]
    fn deduplicate_removes_duplicates_and_descendants() {
        let input = ["/a/b", "/a", "/a/b", "/c"].map(PathBuf::from).to_vec();
        let got = deduplicate_paths(input);
        assert_eq!(got, [PathBuf::from("/a"), PathBuf::from("/c")]);
    }

    #[test]
    fn deduplicate_keeps_sibling_with_shared_string_prefix() {
        // "/ab" is not a path-descendant of "/a", so it must survive
        let got = deduplicate_paths(["/a", "/ab"].map(PathBuf::from).to_vec());
        assert_eq!(got, [PathBuf::from("/a"), PathBuf::from("/ab")]);
    }

    #[test]
    fn deduplicate_keeps_unrelated_siblings() {
        let got = deduplicate_paths(["/b", "/a"].map(PathBuf::from).to_vec());
        assert_eq!(got, [PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    // is_valid_utf8_slice

    #[test]
    fn valid_utf8_accepts_complete_and_empty() {
        assert!(is_valid_utf8_slice(b""));
        assert!(is_valid_utf8_slice("héllo 😀".as_bytes()));
    }

    #[test]
    fn valid_utf8_accepts_truncated_trailing_char() {
        assert!(is_valid_utf8_slice(b"ok\xf0\x9f\x98"));
    }

    #[test]
    fn valid_utf8_rejects_mid_sequence_garbage() {
        assert!(!is_valid_utf8_slice(b"ab\xffcd"));
        assert!(!is_valid_utf8_slice(b"\xf0\x28"));
    }

    // strip_paths

    #[test]
    fn strip_paths_top_level() {
        let mut v = serde_json::json!({"a": 1, "b": 2});
        strip_paths(&mut v, &["a"]);
        assert_eq!(v, serde_json::json!({"b": 2}));
    }

    #[test]
    fn strip_paths_nested() {
        let mut v = serde_json::json!({"a": {"b": 1, "c": 2}});
        strip_paths(&mut v, &["a.b"]);
        assert_eq!(v, serde_json::json!({"a": {"c": 2}}));
    }

    #[test]
    fn strip_paths_removes_a_non_object_standing_in_for_a_parent() {
        let mut v = serde_json::json!({"a": 5});
        strip_paths(&mut v, &["a.b"]);
        assert_eq!(v, serde_json::json!({}));
    }

    #[test]
    fn strip_paths_removes_a_nulled_parent() {
        // `json_patch::merge` treats null as a delete, so a nulled parent would drop the
        // protected leaf and let it come back as a serde default
        let mut v = serde_json::json!({"system": null});
        strip_paths(&mut v, &["system.user.uid"]);
        assert_eq!(v, serde_json::json!({}));
    }

    #[test]
    fn strip_paths_removes_a_nulled_intermediate() {
        let mut v = serde_json::json!({"system": {"user": null, "sftp": {"bind_port": 2022}}});
        strip_paths(&mut v, &["system.user.uid"]);
        assert_eq!(
            v,
            serde_json::json!({"system": {"sftp": {"bind_port": 2022}}})
        );
    }

    #[test]
    fn strip_paths_missing_intermediate_is_noop() {
        let mut v = serde_json::json!({"a": {"x": 1}});
        strip_paths(&mut v, &["a.b.c"]);
        assert_eq!(v, serde_json::json!({"a": {"x": 1}}));
    }

    #[test]
    fn strip_paths_multiple() {
        let mut v = serde_json::json!({"a": 1, "b": 2, "c": 3});
        strip_paths(&mut v, &["a", "c"]);
        assert_eq!(v, serde_json::json!({"b": 2}));
    }

    // PortablePermissions

    #[test]
    fn portable_permissions_from_mode_masks_to_lower_nine_bits() {
        assert_eq!(PortablePermissions::from_mode_file(0o7755).mode(), 0o755);
        assert_eq!(PortablePermissions::from_mode_file(0o644).mode(), 0o644);
        assert_eq!(PortablePermissions::from_mode_file(0o1777).mode(), 0o777);
    }

    #[test]
    fn portable_permissions_from_mode_file_sets_owner_read_write() {
        assert_eq!(PortablePermissions::from_mode_file(0o000).mode(), 0o600);
        assert_eq!(PortablePermissions::from_mode_file(0o400).mode(), 0o600);
        assert_eq!(PortablePermissions::from_mode_file(0o200).mode(), 0o600);
    }

    #[test]
    fn portable_permissions_from_mode_dir_sets_owner_read_write_execute() {
        assert_eq!(PortablePermissions::from_mode_dir(0o000).mode(), 0o700);
        assert_eq!(PortablePermissions::from_mode_dir(0o400).mode(), 0o700);
        assert_eq!(PortablePermissions::from_mode_dir(0o200).mode(), 0o700);
        assert_eq!(PortablePermissions::from_mode_dir(0o100).mode(), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn portable_permissions_into_std_roundtrips_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let perms = PortablePermissions::from_mode_file(0o640)
            .into_std_permissions()
            .unwrap();
        assert_eq!(perms.mode() & 0o777, 0o640);
    }

    // CmpExt

    #[test]
    fn cmp_str_is_case_insensitive() {
        assert_eq!("ABC".cmp_ascii_case_insensitive("abc"), Ordering::Equal);
        assert_eq!("abc".cmp_ascii_case_insensitive("abd"), Ordering::Less);
        assert_eq!("ab".cmp_ascii_case_insensitive("abc"), Ordering::Less);
        // folding flips the raw byte ordering of 'Z' (0x5A) vs 'a' (0x61)
        assert_eq!("Z".cmp_ascii_case_insensitive("a"), Ordering::Greater);
    }

    #[test]
    fn cmp_path_is_case_insensitive() {
        assert_eq!(
            Path::new("FOO/Bar").cmp_ascii_case_insensitive(Path::new("foo/bar")),
            Ordering::Equal,
        );
        assert_eq!(
            Path::new("a").cmp_ascii_case_insensitive(Path::new("B")),
            Ordering::Less,
        );
    }
}

/// A blocking counting semaphore, used to put backpressure on a rayon producer.
///
/// `rayon::Scope::spawn` queues work without any bound, so a producer that
/// outruns its workers keeps allocating boxed jobs - and holds whatever those
/// jobs captured - until they eventually run. A directory walk feeding one task
/// per entry can queue millions.
/// How many entries a directory walk may keep queued on a rayon pool.
///
/// High enough that the workers never starve when they keep up - at which point
/// the limit is simply never reached - and low enough that a producer which does
/// outrun them cannot grow the queue without bound.
pub const WALK_IN_FLIGHT_LIMIT: usize = 4096;

pub struct InFlightLimit {
    limit: usize,
    count: parking_lot::Mutex<usize>,
    released: parking_lot::Condvar,
}

pub struct InFlightPermit(std::sync::Arc<InFlightLimit>);

impl InFlightLimit {
    pub fn new(limit: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            limit: limit.max(1),
            count: parking_lot::Mutex::new(0),
            released: parking_lot::Condvar::new(),
        })
    }

    /// Blocks until fewer than `limit` permits are outstanding.
    ///
    /// Only ever called from the producer, which is the thread that owns the
    /// scope rather than one of its workers, so the workers stay free to drain
    /// the queue and release permits.
    pub fn acquire(self: &std::sync::Arc<Self>) -> InFlightPermit {
        let mut count = self.count.lock();
        while *count >= self.limit {
            self.released.wait(&mut count);
        }
        *count += 1;

        InFlightPermit(std::sync::Arc::clone(self))
    }
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        *self.0.count.lock() -= 1;
        self.0.released.notify_one();
    }
}
