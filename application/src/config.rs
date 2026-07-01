use anyhow::Context;
use arc_swap::ArcSwap;
use axum::{extract::ConnectInfo, http::HeaderMap};
use compact_str::ToCompactString;
use serde::{Deserialize, Serialize};
use serde_default::DefaultFromSerde;
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::BufRead,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    filter::Targets,
    fmt::writer::MakeWriterExt,
    layer::{Layered, SubscriberExt},
    util::SubscriberInitExt,
};
use utoipa::ToSchema;

fn app_name() -> String {
    #[cfg(unix)]
    {
        "Pterodactyl".to_string()
    }
    #[cfg(windows)]
    {
        "Calagopus".to_string()
    }
}
fn api_host() -> String {
    "0.0.0.0".to_string()
}
fn api_port() -> u16 {
    8080
}
fn api_server_remote_download_limit() -> usize {
    3
}
fn api_remote_download_blocked_cidrs() -> Vec<cidr::IpCidr> {
    unsafe {
        Vec::from([
            cidr::IpCidr::from_str("127.0.0.0/8").unwrap_unchecked(),
            cidr::IpCidr::from_str("10.0.0.0/8").unwrap_unchecked(),
            cidr::IpCidr::from_str("172.16.0.0/12").unwrap_unchecked(),
            cidr::IpCidr::from_str("192.168.0.0/16").unwrap_unchecked(),
            cidr::IpCidr::from_str("169.254.0.0/16").unwrap_unchecked(),
            cidr::IpCidr::from_str("::1/128").unwrap_unchecked(),
            cidr::IpCidr::from_str("fe80::/10").unwrap_unchecked(),
            cidr::IpCidr::from_str("fc00::/7").unwrap_unchecked(),
        ])
    }
}
fn api_directory_entry_limit() -> usize {
    10000
}
fn api_file_search_threads() -> usize {
    4
}
fn api_file_copy_threads() -> usize {
    4
}
fn api_file_decompression_threads() -> usize {
    2
}
fn api_file_compression_threads() -> usize {
    2
}
fn api_upload_limit() -> MiB {
    100u64.into()
}
fn api_max_jwt_uses() -> usize {
    5
}

fn system_root_directory() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings".to_string()
    }
}
fn system_log_directory() -> String {
    #[cfg(unix)]
    {
        "/var/log/pterodactyl".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\logs".to_string()
    }
}
fn system_vmount_directory() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/vmounts".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\vmounts".to_string()
    }
}
fn system_data() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/volumes".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\volumes".to_string()
    }
}
fn system_archive_directory() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/archives".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\archives".to_string()
    }
}
fn system_backup_directory() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/backups".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\backups".to_string()
    }
}
fn system_tmp_directory() -> String {
    #[cfg(unix)]
    {
        "/tmp/pterodactyl".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\tmp".to_string()
    }
}
fn system_username() -> compact_str::CompactString {
    #[cfg(unix)]
    {
        "pterodactyl".into()
    }
    #[cfg(windows)]
    {
        "calagopus-wings".into()
    }
}
fn system_timezone() -> compact_str::CompactString {
    if let Ok(tz) = std::env::var("TZ") {
        return tz.into();
    } else if let Ok(tz) = File::open("/etc/timezone") {
        let mut buf = String::new();

        if std::io::BufReader::new(tz).read_line(&mut buf).is_ok() {
            return buf.trim().to_compact_string();
        }
    }

    chrono::Local::now().offset().to_compact_string()
}
#[cfg(unix)]
fn system_passwd_directory() -> String {
    "/run/wings/etc".to_string()
}
#[cfg(unix)]
fn system_machine_id_enabled() -> bool {
    true
}
fn system_disk_check_concurrency() -> usize {
    2
}
fn system_disk_check_interval() -> u64 {
    150
}
fn system_full_disk_check_every() -> u64 {
    4
}
fn system_disk_check_use_inotify() -> bool {
    true
}
fn system_activity_send_interval() -> u64 {
    60
}
fn system_activity_send_count() -> usize {
    100
}
fn system_check_permissions_on_boot() -> bool {
    true
}
fn system_check_permissions_on_boot_threads() -> usize {
    4
}
fn system_websocket_log_count() -> usize {
    150
}

fn system_sftp_enabled() -> bool {
    true
}
fn system_sftp_bind_address() -> std::net::IpAddr {
    std::net::IpAddr::from([0, 0, 0, 0])
}
fn system_sftp_bind_port() -> u16 {
    2022
}
fn system_sftp_key_algorithm() -> String {
    "ssh-ed25519".to_string()
}
fn system_sftp_directory_entry_limit() -> u64 {
    20000
}
fn system_sftp_directory_entry_send_amount() -> usize {
    500
}

fn system_sftp_limits_authentication_password_attempts() -> usize {
    3
}
fn system_sftp_limits_authentication_pubkey_attempts() -> usize {
    20
}
fn system_sftp_limits_authentication_cooldown() -> u64 {
    60
}
fn system_sftp_limits_max_connections_per_user() -> usize {
    10
}
fn system_sftp_limits_max_channels_per_connection() -> usize {
    10
}
fn system_sftp_limits_max_handles_per_channel() -> usize {
    32
}
fn system_sftp_limits_max_handles_total() -> usize {
    1024
}

fn system_sftp_shell_enabled() -> bool {
    true
}

fn system_sftp_shell_cli_name() -> String {
    ".wings".to_string()
}

fn system_crash_detection_enabled() -> bool {
    true
}
fn system_crash_detection_detect_clean_exit_as_crash() -> bool {
    true
}
fn system_crash_detection_timeout() -> u64 {
    60
}

fn system_file_history_enabled() -> bool {
    true
}
fn system_file_history_zstd_level() -> i32 {
    19
}
fn system_file_history_anchor_interval() -> u64 {
    4
}
fn system_file_history_keep_chains() -> u64 {
    5
}
fn system_file_history_file_size_cap() -> u64 {
    1024 * 1024
}
fn system_file_history_per_file_disk_budget() -> u64 {
    5 * 1024 * 1024
}
fn system_file_history_per_server_disk_budget() -> u64 {
    200 * 1024 * 1024
}
fn system_file_history_maintenance_interval() -> u64 {
    3600
}

fn system_backup_mounting_enabled() -> bool {
    true
}
fn system_backup_mounting_path() -> String {
    ".backups".to_string()
}

fn system_backup_wings_create_threads() -> usize {
    4
}
fn system_backup_wings_restore_threads() -> usize {
    4
}

fn system_backup_s3_create_threads() -> usize {
    4
}
fn system_backup_s3_part_upload_timeout() -> u64 {
    2 * 60 * 60
}
fn system_backup_s3_retry_limit() -> u64 {
    10
}

fn system_backup_ddup_bak_create_threads() -> usize {
    4
}

fn system_backup_restic_repository() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/backups/restic".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\backups\\restic".to_string()
    }
}
fn system_backup_restic_password_file() -> String {
    #[cfg(unix)]
    {
        "/var/lib/pterodactyl/backups/restic_password".to_string()
    }
    #[cfg(windows)]
    {
        "C:\\ProgramData\\Calagopus-Wings\\backups\\restic_password".to_string()
    }
}
fn system_backup_restic_retry_lock_seconds() -> u64 {
    60
}

fn system_backup_btrfs_restore_threads() -> usize {
    4
}
fn system_backup_btrfs_create_read_only() -> bool {
    true
}

fn system_backup_zfs_restore_threads() -> usize {
    4
}

fn docker_socket() -> String {
    #[cfg(unix)]
    {
        "/var/run/docker.sock".to_string()
    }
    #[cfg(windows)]
    {
        "//./pipe/docker_engine".to_string()
    }
}
fn docker_delete_container_on_stop() -> bool {
    true
}

fn docker_network_interface() -> String {
    "172.18.0.1".to_string()
}
fn docker_network_dns() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
}
fn docker_network_name() -> String {
    #[cfg(unix)]
    {
        "pterodactyl_nw".to_string()
    }
    #[cfg(windows)]
    {
        "calagopus_nw".to_string()
    }
}
fn docker_network_driver() -> String {
    "bridge".to_string()
}
fn docker_network_mode() -> String {
    #[cfg(unix)]
    {
        "pterodactyl_nw".to_string()
    }
    #[cfg(windows)]
    {
        "calagopus_nw".to_string()
    }
}
fn docker_network_enable_icc() -> bool {
    true
}
fn docker_network_network_mtu() -> u64 {
    1500
}

fn docker_network_interfaces_v4_subnet() -> String {
    "172.18.0.0/16".to_string()
}
fn docker_network_interfaces_v4_gateway() -> String {
    "172.18.0.1".to_string()
}
fn docker_network_interfaces_v6_subnet() -> String {
    "fdba:17c8:6c94::/64".to_string()
}
fn docker_network_interfaces_v6_gateway() -> String {
    "fdba:17c8:6c94::1011".to_string()
}

fn docker_registry_image_fetch_cache_enabled() -> bool {
    true
}
fn docker_registry_image_fetch_cache_duration() -> u64 {
    5 * 60
}

fn docker_tmpfs_size() -> u64 {
    100
}
fn docker_container_pid_limit() -> u64 {
    5120
}
fn docker_container_apply_seccomp() -> bool {
    true
}

fn docker_installer_limits_timeout() -> u64 {
    30 * 60
}
fn docker_installer_limits_memory() -> MiB {
    1024u64.into()
}
fn docker_installer_limits_cpu() -> u64 {
    100
}

fn docker_overhead_default_multiplier() -> f64 {
    1.05
}

fn docker_log_config_type() -> String {
    "local".to_string()
}
fn docker_log_config_config() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("max-size".to_string(), "5m".to_string()),
        ("max-file".to_string(), "1".to_string()),
        ("compress".to_string(), "false".to_string()),
        ("mode".to_string(), "non-blocking".to_string()),
    ])
}

fn throttles_enabled() -> bool {
    true
}
fn throttles_lines() -> u64 {
    2000
}
fn throttles_line_reset_interval() -> u64 {
    100
}

fn remote_query_timeout() -> u64 {
    30
}
fn remote_query_boot_servers_per_page() -> u64 {
    50
}
fn remote_query_retry_limit() -> u64 {
    10
}

/// Represents a size in Mebibytes (MiB). The inner value is the number of MiB (not bytes!!).
#[derive(
    ToSchema, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct MiB(u64);

impl MiB {
    pub fn as_bytes(self) -> u64 {
        self.0 * 1024 * 1024
    }

    pub fn as_kib(self) -> u64 {
        self.0 * 1024
    }

    pub fn as_mib(self) -> u64 {
        self.0
    }
}

impl From<u64> for MiB {
    fn from(value: u64) -> Self {
        MiB(value)
    }
}

impl From<i64> for MiB {
    fn from(value: i64) -> Self {
        MiB(value as u64)
    }
}

nestify::nest! {
    #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)]
    pub struct InnerConfig {
        #[serde(default)]
        pub debug: bool,
        #[serde(default = "app_name")]
        pub app_name: String,
        #[serde(default)]
        pub uuid: uuid::Uuid,

        #[serde(default)]
        pub token_id: String,
        #[serde(default)]
        pub token: String,

        #[serde(default)]
        #[schema(inline)]
        pub api: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct Api {
            #[serde(default = "api_host")]
            pub host: String,
            #[serde(default = "api_port")]
            pub port: u16,

            #[serde(default)]
            #[schema(inline)]
            pub ssl: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct ApiSsl {
                #[serde(default)]
                pub enabled: bool,
                #[serde(default)]
                pub cert: String,
                #[serde(default)]
                pub key: String,
            },

            #[serde(default)]
            #[schema(inline)]
            pub redirects: HashMap<String, String>,

            #[serde(default)]
            pub disable_openapi_docs: bool,
            #[serde(default)]
            pub disable_remote_download: bool,
            #[serde(default = "api_server_remote_download_limit")]
            pub server_remote_download_limit: usize,
            #[serde(default = "api_remote_download_blocked_cidrs")]
            #[schema(value_type = Vec<String>)]
            pub remote_download_blocked_cidrs: Vec<cidr::IpCidr>,
            #[serde(default)]
            pub disable_directory_size: bool,
            #[serde(default = "api_directory_entry_limit")]
            pub directory_entry_limit: usize,
            #[serde(default)]
            pub send_offline_server_logs: bool,
            #[serde(default = "api_file_search_threads")]
            pub file_search_threads: usize,
            #[serde(default = "api_file_copy_threads")]
            pub file_copy_threads: usize,
            #[serde(default = "api_file_decompression_threads")]
            pub file_decompression_threads: usize,
            #[serde(default = "api_file_compression_threads")]
            pub file_compression_threads: usize,
            #[serde(default = "api_upload_limit")]
            pub upload_limit: MiB,
            #[serde(default = "api_max_jwt_uses")]
            pub max_jwt_uses: usize,
            #[serde(default)]
            #[schema(value_type = Vec<String>)]
            pub trusted_proxies: Vec<cidr::IpCidr>,
        },
        #[serde(default)]
        #[schema(inline)]
        pub system: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct System {
            #[serde(default = "system_root_directory")]
            pub root_directory: String,
            #[serde(default = "system_log_directory")]
            pub log_directory: String,
            #[serde(default = "system_vmount_directory")]
            pub vmount_directory: String,
            #[serde(default = "system_data", rename = "data")]
            pub data_directory: String,
            #[serde(default = "system_archive_directory")]
            pub archive_directory: String,
            #[serde(default = "system_backup_directory")]
            pub backup_directory: String,
            #[serde(default = "system_tmp_directory")]
            pub tmp_directory: String,

            #[serde(default = "system_username")]
            pub username: compact_str::CompactString,
            #[serde(default = "system_timezone")]
            pub timezone: compact_str::CompactString,

            #[serde(default)]
            #[schema(inline)]
            pub user: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemUser {
                #[serde(default)]
                #[schema(inline)]
                pub rootless: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemUserRootless {
                    #[serde(default)]
                    pub enabled: bool,
                    #[serde(default)]
                    pub container_uid: u32,
                    #[serde(default)]
                    pub container_gid: u32,
                },

                #[serde(default)]
                pub uid: u32,
                #[serde(default)]
                pub gid: u32,
            },

            #[cfg(unix)]
            #[serde(default)]
            #[schema(inline)]
            pub passwd: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemPasswd {
                #[cfg(unix)]
                #[serde(default)]
                pub enabled: bool,
                #[cfg(unix)]
                #[serde(default = "system_passwd_directory")]
                pub directory: String,
            },

            #[cfg(unix)]
            #[serde(default)]
            #[schema(inline)]
            pub machine_id: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemMachineId {
                #[cfg(unix)]
                #[serde(default = "system_machine_id_enabled")]
                pub enabled: bool,
            },

            #[serde(default = "system_disk_check_concurrency")]
            pub disk_check_concurrency: usize,
            #[serde(default = "system_disk_check_interval")]
            pub disk_check_interval: u64,
            #[serde(default = "system_full_disk_check_every")]
            pub full_disk_check_every: u64,
            #[serde(default = "system_disk_check_use_inotify")]
            pub disk_check_use_inotify: bool,
            #[serde(default)]
            pub disk_limiter_mode: crate::server::filesystem::limiter::DiskLimiterMode,
            #[serde(default = "system_activity_send_interval")]
            pub activity_send_interval: u64,
            #[serde(default = "system_activity_send_count")]
            pub activity_send_count: usize,
            #[serde(default = "system_check_permissions_on_boot")]
            pub check_permissions_on_boot: bool,
            #[serde(default = "system_check_permissions_on_boot_threads")]
            pub check_permissions_on_boot_threads: usize,
            #[serde(default = "system_websocket_log_count")]
            pub websocket_log_count: usize,

            #[serde(default)]
            #[schema(inline)]
            pub sftp: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemSftp {
                #[serde(default = "system_sftp_enabled")]
                pub enabled: bool,

                #[serde(default = "system_sftp_bind_address")]
                #[schema(value_type = String)]
                pub bind_address: std::net::IpAddr,
                #[serde(default = "system_sftp_bind_port")]
                pub bind_port: u16,

                #[serde(default)]
                pub read_only: bool,
                #[serde(default = "system_sftp_key_algorithm")]
                pub key_algorithm: String,
                #[serde(default)]
                pub disable_password_auth: bool,
                #[serde(default = "system_sftp_directory_entry_limit")]
                pub directory_entry_limit: u64,
                #[serde(default = "system_sftp_directory_entry_send_amount")]
                pub directory_entry_send_amount: usize,

                #[serde(default)]
                #[schema(inline)]
                pub limits: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemSftpLimits {
                    #[serde(default = "system_sftp_limits_authentication_password_attempts")]
                    pub authentication_password_attempts: usize,
                    #[serde(default = "system_sftp_limits_authentication_pubkey_attempts")]
                    pub authentication_pubkey_attempts: usize,
                    #[serde(default = "system_sftp_limits_authentication_cooldown")]
                    pub authentication_cooldown: u64,

                    #[serde(default = "system_sftp_limits_max_connections_per_user")]
                    pub max_connections_per_user: usize,
                    #[serde(default = "system_sftp_limits_max_channels_per_connection")]
                    pub max_channels_per_connection: usize,
                    #[serde(default = "system_sftp_limits_max_handles_per_channel")]
                    pub max_handles_per_channel: usize,
                    #[serde(default = "system_sftp_limits_max_handles_total")]
                    pub max_handles_total: usize,
                },

                #[serde(default)]
                #[schema(inline)]
                pub shell: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemSftpShell {
                    #[serde(default = "system_sftp_shell_enabled")]
                    pub enabled: bool,

                    #[serde(default)]
                    #[schema(inline)]
                    pub cli: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemSftpShellCli {
                        #[serde(default = "system_sftp_shell_cli_name")]
                        pub name: String,
                    },
                },

                #[serde(default)]
                #[schema(inline)]
                pub activity: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemSftpActivity {
                    #[serde(default)]
                    pub log_logins: bool,
                    #[serde(default)]
                    pub log_file_reads: bool,
                },
            },

            #[serde(default)]
            #[schema(inline)]
            pub crash_detection: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemCrashDetection {
                #[serde(default = "system_crash_detection_enabled")]
                pub enabled: bool,
                #[serde(default = "system_crash_detection_detect_clean_exit_as_crash")]
                pub detect_clean_exit_as_crash: bool,
                #[serde(default = "system_crash_detection_timeout")]
                pub timeout: u64,
            },

            #[serde(default)]
            #[schema(inline)]
            pub file_history: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemFileHistory {
                #[serde(default = "system_file_history_enabled")]
                pub enabled: bool,

                #[serde(default = "system_file_history_zstd_level")]
                pub zstd_level: i32,
                #[serde(default = "system_file_history_anchor_interval")]
                pub anchor_interval: u64,

                #[serde(default = "system_file_history_keep_chains")]
                pub keep_chains: u64,

                #[serde(default = "system_file_history_file_size_cap")]
                pub file_size_cap: u64,

                #[serde(default = "system_file_history_per_file_disk_budget")]
                pub per_file_disk_budget: u64,
                #[serde(default = "system_file_history_per_server_disk_budget")]
                pub per_server_disk_budget: u64,

                #[serde(default = "system_file_history_maintenance_interval")]
                pub maintenance_interval: u64,
            },

            #[serde(default)]
            #[schema(inline)]
            pub backups: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackups {
                #[serde(default)]
                pub write_limit: MiB,
                #[serde(default)]
                pub read_limit: MiB,
                #[serde(default)]
                pub compression_level: crate::io::compression::CompressionLevel,

                #[serde(default)]
                #[schema(inline)]
                pub mounting: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsMounting {
                    #[serde(default = "system_backup_mounting_enabled")]
                    pub enabled: bool,
                    #[serde(default = "system_backup_mounting_path")]
                    pub path: String,
                },

                #[serde(default)]
                #[schema(inline)]
                pub wings: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsWings {
                    #[serde(default = "system_backup_wings_create_threads")]
                    pub create_threads: usize,
                    #[serde(default = "system_backup_wings_restore_threads")]
                    pub restore_threads: usize,

                    #[serde(default)]
                    pub archive_format: crate::server::filesystem::archive::ArchiveFormat,
                },
                #[serde(default)]
                #[schema(inline)]
                pub s3: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsS3 {
                    #[serde(default = "system_backup_s3_create_threads")]
                    pub create_threads: usize,
                    #[serde(default = "system_backup_s3_part_upload_timeout")]
                    pub part_upload_timeout: u64,
                    #[serde(default = "system_backup_s3_retry_limit")]
                    pub retry_limit: u64,
                },
                #[serde(default)]
                #[schema(inline)]
                pub ddup_bak: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsDdupBak {
                    #[serde(default = "system_backup_ddup_bak_create_threads")]
                    pub create_threads: usize,

                    #[serde(default)]
                    pub compression_format: #[derive(ToSchema, Clone, Copy, Deserialize, Serialize, Default)] #[serde(rename_all = "snake_case")] pub enum SystemBackupsDdupBakCompressionFormat {
                        None,
                        #[default]
                        Deflate,
                        Gzip,
                        Brotli
                    },
                },
                #[serde(default)]
                #[schema(inline)]
                pub restic: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsRestic {
                    #[serde(default = "system_backup_restic_repository")]
                    pub repository: String,
                    #[serde(default = "system_backup_restic_password_file")]
                    pub password_file: String,

                    #[serde(default = "system_backup_restic_retry_lock_seconds")]
                    pub retry_lock_seconds: u64,
                    #[serde(default)]
                    pub environment: BTreeMap<String, String>,
                },
                #[serde(default)]
                #[schema(inline)]
                pub btrfs: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsBtrfs {
                    #[serde(default = "system_backup_btrfs_restore_threads")]
                    pub restore_threads: usize,

                    #[serde(default = "system_backup_btrfs_create_read_only")]
                    pub create_read_only: bool,
                },
                #[serde(default)]
                #[schema(inline)]
                pub zfs: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemBackupsZfs {
                    #[serde(default = "system_backup_zfs_restore_threads")]
                    pub restore_threads: usize,
                },
            },

            #[serde(default)]
            #[schema(inline)]
            pub transfers: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct SystemTransfers {
                #[serde(default)]
                pub download_limit: MiB,
            },
        },
        #[serde(default)]
        #[schema(inline)]
        pub docker: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct Docker {
            #[serde(default = "docker_socket")]
            pub socket: String,
            #[serde(default)]
            pub server_name_in_container_name: bool,
            #[serde(default = "docker_delete_container_on_stop")]
            pub delete_container_on_stop: bool,

            #[serde(default)]
            #[schema(inline)]
            pub network: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerNetwork {
                #[serde(default = "docker_network_interface")]
                pub interface: String,
                #[serde(default)]
                pub disable_interface_binding: bool,
                #[serde(default = "docker_network_dns")]
                pub dns: Vec<String>,

                #[serde(default = "docker_network_name")]
                pub name: String,
                #[serde(default)]
                pub ispn: bool,
                #[serde(default = "docker_network_driver")]
                pub driver: String,
                #[serde(default = "docker_network_mode")]
                pub mode: String,
                #[serde(default)]
                pub is_internal: bool,
                #[serde(default = "docker_network_enable_icc")]
                pub enable_icc: bool,
                #[serde(default = "docker_network_network_mtu")]
                pub network_mtu: u64,

                #[serde(default)]
                #[schema(inline)]
                pub interfaces: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerNetworkInterfaces {
                    #[serde(default)]
                    #[schema(inline)]
                    pub v4: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerNetworkInterfacesV4 {
                        #[serde(default = "docker_network_interfaces_v4_subnet")]
                        pub subnet: String,
                        #[serde(default = "docker_network_interfaces_v4_gateway")]
                        pub gateway: String,
                    },
                    #[serde(default)]
                    #[schema(inline)]
                    pub v6: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerNetworkInterfacesV6 {
                        #[serde(default = "docker_network_interfaces_v6_subnet")]
                        pub subnet: String,
                        #[serde(default = "docker_network_interfaces_v6_gateway")]
                        pub gateway: String,
                    },
                },
            },

            #[serde(default)]
            pub domainname: String,
            #[serde(default)]
            #[schema(inline)]
            pub registries: HashMap<String, #[derive(ToSchema, Deserialize, Serialize)] pub struct DockerRegistryConfiguration {
                pub username: String,
                pub password: String,
            }>,
            #[serde(default)]
            #[schema(inline)]
            pub registry_image_fetch_cache: #[derive(Clone, Copy, ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerRegistryImageFetchCache {
                #[serde(default = "docker_registry_image_fetch_cache_enabled")]
                pub enabled: bool,
                #[serde(default = "docker_registry_image_fetch_cache_duration")]
                pub duration: u64,
            },

            #[serde(default = "docker_tmpfs_size")]
            pub tmpfs_size: u64,
            #[serde(default = "docker_container_pid_limit")]
            pub container_pid_limit: u64,
            #[serde(default = "docker_container_apply_seccomp")]
            pub container_apply_seccomp: bool,

            #[serde(default)]
            #[schema(inline)]
            pub installer_limits: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerInstallerLimits {
                #[serde(default = "docker_installer_limits_timeout")]
                pub timeout: u64,

                #[serde(default = "docker_installer_limits_memory")]
                pub memory: MiB,
                #[serde(default = "docker_installer_limits_cpu")]
                /// %
                pub cpu: u64,
            },

            #[serde(default)]
            #[schema(inline)]
            pub overhead: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerOverhead {
                #[serde(default)]
                pub r#override: bool,
                #[serde(default = "docker_overhead_default_multiplier")]
                pub default_multiplier: f64,

                #[serde(default)]
                /// Memory Limit MiB -> Multiplier
                pub multipliers: BTreeMap<MiB, f64>,
            },

            #[serde(default)]
            pub userns_mode: String,

            #[serde(default)]
            #[schema(inline)]
            pub log_config: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct DockerLogConfig {
                #[serde(default = "docker_log_config_type")]
                pub r#type: String,
                #[serde(default = "docker_log_config_config")]
                pub config: BTreeMap<String, String>,
            },
        },

        #[serde(default)]
        #[schema(inline)]
        pub throttles: #[derive(ToSchema, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct Throttles {
            #[serde(default = "throttles_enabled")]
            pub enabled: bool,
            #[serde(default = "throttles_lines")]
            pub lines: u64,
            #[serde(default = "throttles_line_reset_interval")]
            /// ms
            pub line_reset_interval: u64,
        },

        #[serde(default)]
        pub remote: String,
        #[serde(default)]
        #[schema(inline)]
        pub remote_headers: BTreeMap<String, String>,
        #[serde(default)]
        #[schema(inline)]
        pub remote_query: #[derive(ToSchema, Clone, Copy, Deserialize, Serialize, DefaultFromSerde)] #[serde(default)] pub struct RemoteQuery {
            #[serde(default = "remote_query_timeout")]
            pub timeout: u64,
            #[serde(default = "remote_query_boot_servers_per_page")]
            pub boot_servers_per_page: u64,
            #[serde(default = "remote_query_retry_limit")]
            pub retry_limit: u64,
        },

        #[serde(default)]
        pub allowed_mounts: Vec<compact_str::CompactString>,
        #[serde(default)]
        pub allowed_origins: Vec<String>,

        #[serde(default)]
        pub allow_cors_private_network: bool,
        #[serde(default)]
        pub ignore_panel_config_updates: bool,
        #[serde(default)]
        pub ignore_panel_wings_upgrades: bool,
    }
}

impl DockerOverhead {
    /// ```yaml
    /// multipliers:
    ///   1024: 1.05
    ///   2048: 1.10
    /// ```
    /// means, <=1024MiB ram = 1.05 multiplier,
    /// <=2048MiB ram = 1.10 multiplier,
    /// >2048MiB ram = 1.05 multiplier (default_multiplier)
    pub fn get_multiplier(&self, memory: MiB) -> f64 {
        if !self.r#override {
            if memory.as_mib() <= 2048 {
                return 1.15;
            } else if memory.as_mib() <= 4096 {
                return 1.10;
            }

            return 1.05;
        }

        for (m, v) in self.multipliers.iter().rev() {
            if memory > *m {
                continue;
            }

            return *v;
        }

        self.default_multiplier
    }

    #[inline]
    pub fn get_memory(&self, memory: MiB) -> MiB {
        let multiplier = self.get_multiplier(memory);

        MiB((memory.as_mib() as f64 * multiplier) as u64)
    }
}

pub const FORBIDDEN_PATHS: &[&str] = &[
    "uuid",
    "token",
    "token_id",
    "remote",
    "remote_headers",
    "system.root_directory",
    "system.log_directory",
    "system.vmount_directory",
    "system.data",
    "system.archive_directory",
    "system.backup_directory",
    "system.tmp_directory",
    "system.passwd.directory",
    "system.backups.restic.repository",
    "system.backups.restic.password_file",
    "system.backups.mounting.path",
    "system.username",
    "system.user",
    "system.passwd",
    "docker.socket",
    "allowed_mounts",
];

#[allow(dead_code)]
pub struct ConfigGuard(
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
);

pub type ConfigSnapshot = arc_swap::Guard<Arc<InnerConfig>>;
type ReloadHandle =
    tracing_subscriber::reload::Handle<Targets, Layered<LevelFilter, tracing_subscriber::Registry>>;

fn log_filter(debug: bool) -> Targets {
    let crate_level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    Targets::new()
        .with_default(LevelFilter::INFO)
        .with_target("wings_rs", crate_level)
        .with_target("pbs_client", crate_level)
}

pub struct Config {
    inner: ArcSwap<InnerConfig>,
    log_reload_handle: ReloadHandle,

    pub path: String,
    pub ignore_certificate_errors: bool,
    pub disk_check_concurrency_semaphore: tokio::sync::Semaphore,
    pub client: crate::remote::client::Client,
    pub jwt: crate::remote::jwt::JwtClient,
}

impl Config {
    pub fn open(
        path: &str,
        debug: bool,
        ignore_debug: bool,
        ignore_certificate_errors: bool,
    ) -> Result<(Arc<Self>, ConfigGuard), anyhow::Error> {
        let file = File::open(path).context(format!("failed to open config file {path}"))?;
        let reader = std::io::BufReader::new(file);
        let mut inner: InnerConfig = serde_norway::from_reader(reader)
            .context(format!("failed to parse config file {path}"))?;

        Self::ensure_directories(&inner)?;

        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());

        let latest_log_path = Path::new(&inner.system.log_directory).join("wings.log");
        let latest_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&latest_log_path)
            .context("failed to open latest log file")?;

        let rolling_appender = tracing_appender::rolling::Builder::new()
            .filename_prefix("wings")
            .filename_suffix("log")
            .max_log_files(30)
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .build(&inner.system.log_directory)
            .context("failed to create rolling log file appender")?;

        let (file_appender, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(50)
            .finish(latest_file.and(rolling_appender));

        #[cfg(unix)]
        {
            Self::ensure_user(&mut inner)?;
            Self::ensure_passwd(&inner)?;
        }

        if debug {
            inner.debug = true;
        }

        Self::validate_inner(&inner)?;
        Self::save_to(path, &inner)?;

        let initial_filter = log_filter(inner.debug && !ignore_debug);
        let (reload_layer, log_reload_handle) =
            tracing_subscriber::reload::Layer::new(initial_filter);

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
                "%Y-%m-%d %H:%M:%S %z".to_string(),
            ))
            .with_writer(stdout_writer.and(file_appender))
            .with_target(false)
            .with_level(true)
            .with_file(true)
            .with_line_number(true);

        tracing_subscriber::registry()
            .with(LevelFilter::DEBUG)
            .with(reload_layer)
            .with(fmt_layer)
            .try_init()
            .context("failed to install tracing subscriber")?;

        let disk_check_concurrency_semaphore =
            tokio::sync::Semaphore::new(inner.system.disk_check_concurrency);
        let client = crate::remote::client::Client::new(&inner, ignore_certificate_errors);
        let jwt = crate::remote::jwt::JwtClient::new(&inner);

        let config = Arc::new(Self {
            inner: ArcSwap::new(Arc::new(inner)),
            log_reload_handle,

            path: path.to_string(),
            ignore_certificate_errors,
            disk_check_concurrency_semaphore,
            client,
            jwt,
        });

        Ok((config, ConfigGuard(guard, stdout_guard)))
    }

    #[cfg(test)]
    pub fn mock() -> Self {
        let inner = InnerConfig::default();
        let client = crate::remote::client::Client::new(&inner, true);
        let jwt = crate::remote::jwt::JwtClient::new(&inner);

        Self {
            inner: ArcSwap::new(Arc::new(inner)),
            log_reload_handle: tracing_subscriber::reload::Layer::new(log_filter(false)).1,
            path: String::new(),
            ignore_certificate_errors: false,
            disk_check_concurrency_semaphore: tokio::sync::Semaphore::new(1),
            client,
            jwt,
        }
    }

    #[inline]
    pub fn load(&self) -> ConfigSnapshot {
        self.inner.load()
    }

    pub fn replace(&self, new: InnerConfig) -> Result<(), anyhow::Error> {
        Self::validate_inner(&new)?;
        Self::save_to(&self.path, &new)?;

        let old_debug = self.load().debug;
        let new_debug = new.debug;

        self.inner.store(Arc::new(new));

        if old_debug != new_debug {
            self.log_reload_handle
                .modify(|filter| *filter = log_filter(new_debug))
                .context("failed to reload tracing level filter")?;
        }

        Ok(())
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn mutate_in_place(&self) -> &mut InnerConfig {
        let arc = self.inner.load();
        let ptr = Arc::as_ptr(&arc) as *mut InnerConfig;
        unsafe { &mut *ptr }
    }

    #[allow(clippy::mut_from_ref)]
    #[cfg(test)]
    pub fn mutate_in_place_for_testing(&self) -> &mut InnerConfig {
        unsafe { self.mutate_in_place() }
    }

    fn save_to(path: &str, inner: &InnerConfig) -> Result<(), anyhow::Error> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(path)
            .context(format!("failed to create config file {path}"))?;
        let writer = std::io::BufWriter::new(file);
        serde_norway::to_writer(writer, inner)
            .context(format!("failed to write config file {path}"))?;
        Ok(())
    }

    pub fn save_new(path: &str, config: InnerConfig) -> Result<(), anyhow::Error> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .context(format!("failed to create config directory {path}"))?;
        }
        Self::save_to(path, &config)
    }

    pub fn save(&self) -> Result<(), anyhow::Error> {
        let snap = self.load();
        Self::validate_inner(&snap)?;
        Self::save_to(&self.path, &snap)
    }

    #[inline]
    pub fn find_ip(
        &self,
        headers: &HeaderMap,
        connect_info: ConnectInfo<std::net::SocketAddr>,
    ) -> std::net::IpAddr {
        let cfg = self.load();

        let trusted = headers
            .get("X-Real-Ip-Token")
            .and_then(|token| token.to_str().ok())
            == Some(cfg.token.as_str())
            || cfg
                .api
                .trusted_proxies
                .iter()
                .any(|cidr| cidr.contains(&connect_info.ip()));

        if trusted {
            if let Some(forwarded) = headers.get("X-Forwarded-For")
                && let Ok(forwarded) = forwarded.to_str()
                && let Some(ip) = forwarded.split(',').next()
            {
                return ip.trim().parse().unwrap_or_else(|_| connect_info.ip());
            }

            if let Some(forwarded) = headers.get("X-Real-IP")
                && let Ok(forwarded) = forwarded.to_str()
            {
                return forwarded
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| connect_info.ip());
            }
        }

        connect_info.ip()
    }

    fn validate_inner(cfg: &InnerConfig) -> Result<(), anyhow::Error> {
        if cfg.api.send_offline_server_logs && cfg.docker.delete_container_on_stop {
            tracing::warn!(
                "you have enabled sending offline server logs, but also deleting containers on stop. This will result in no logs being sent for stopped servers."
            );
        }
        #[cfg(unix)]
        if matches!(
            cfg.system.disk_limiter_mode,
            crate::server::filesystem::limiter::DiskLimiterMode::FuseQuota
        ) && !cfg.docker.delete_container_on_stop
        {
            tracing::warn!(
                "you have enabled FUSEquota disk limiting, but also disabled deleting containers on stop. This can cause issues if you try manually starting things. this setup is not recommended."
            );
        }
        #[cfg(unix)]
        if matches!(
            cfg.system.disk_limiter_mode,
            crate::server::filesystem::limiter::DiskLimiterMode::FuseQuota
        ) && std::env::var("OCI_CONTAINER").is_ok()
        {
            for _ in 0..5 {
                tracing::error!(
                    "you have enabled FUSEquota disk limiting while running in a container. this setup is NOT recommended and WILL cause issues when the container recreates."
                );
            }

            tracing::info!("waiting 10 seconds to allow you to read the above message...");
            if std::env::var("ALLOW_FUSEQUOTA_CONTAINER_USAGE").is_err() {
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
            tracing::warn!("you are treading on thin ice. proceed at your own risk.");
        }

        if cfg.remote.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid remote configuration, cannot connect to panel without a remote"
            ));
        }

        if !cfg.remote.starts_with("http://") && !cfg.remote.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "invalid remote configuration, cannot connect to panel without http:// or https:// protocol"
            ));
        }

        const MIN_DIRECTORY_SEGMENTS: usize = 1;
        let directories = &[
            (&cfg.system.root_directory, "root_directory"),
            (&cfg.system.log_directory, "log_directory"),
            (&cfg.system.vmount_directory, "vmount_directory"),
            (&cfg.system.data_directory, "data_directory"),
            (&cfg.system.archive_directory, "archive_directory"),
            (&cfg.system.backup_directory, "backup_directory"),
            (&cfg.system.tmp_directory, "tmp_directory"),
        ];

        for (dir, name) in directories {
            let path = Path::new(dir);
            let segments = path
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count();
            if segments < MIN_DIRECTORY_SEGMENTS {
                return Err(anyhow::anyhow!(
                    "the {} '{}' must have at least {} segment(s)",
                    name,
                    dir,
                    MIN_DIRECTORY_SEGMENTS
                ));
            }
        }

        Ok(())
    }

    fn ensure_directories(cfg: &InnerConfig) -> std::io::Result<()> {
        let directories = vec![
            &cfg.system.root_directory,
            &cfg.system.log_directory,
            &cfg.system.vmount_directory,
            &cfg.system.data_directory,
            &cfg.system.archive_directory,
            &cfg.system.backup_directory,
            &cfg.system.tmp_directory,
        ];

        for dir in directories {
            if !Path::new(dir).exists() {
                std::fs::create_dir_all(dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
                }
            }
        }

        #[cfg(unix)]
        if cfg.system.passwd.enabled && !Path::new(&cfg.system.passwd.directory).exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir_all(&cfg.system.passwd.directory)?;
            std::fs::set_permissions(
                &cfg.system.passwd.directory,
                std::fs::Permissions::from_mode(0o755),
            )?;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn ensure_user(cfg: &mut InnerConfig) -> Result<(), anyhow::Error> {
        let release =
            std::fs::read_to_string("/etc/os-release").unwrap_or_else(|_| "unknown".to_string());

        if release.contains("distroless") || std::env::var("OCI_CONTAINER").is_ok() {
            cfg.system.username =
                std::env::var("WINGS_USERNAME").map_or_else(|_| system_username(), |u| u.into());
            cfg.system.user.uid = std::env::var("WINGS_UID")
                .unwrap_or_else(|_| "988".to_string())
                .parse()?;
            cfg.system.user.gid = std::env::var("WINGS_GID")
                .unwrap_or_else(|_| "988".to_string())
                .parse()?;

            return Ok(());
        }

        let users = sysinfo::Users::new_with_refreshed_list();

        if cfg.system.user.rootless.enabled
            && let Ok(current_pid) = sysinfo::get_current_pid()
        {
            let mut sys = sysinfo::System::new_all();
            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[current_pid]),
                false,
                sysinfo::ProcessRefreshKind::nothing().with_memory(),
            );

            if let Some(process) = sys.process(current_pid) {
                if let Some(user) = process.user_id() {
                    if let Some(user) = users.get_user_by_id(user) {
                        cfg.system.username = user.name().to_compact_string();
                    }

                    cfg.system.user.uid = **user;
                }
                if let Some(group) = process.group_id() {
                    cfg.system.user.gid = *group;
                }

                if cfg.system.user.uid == 0 || cfg.system.user.gid == 0 {
                    return Err(anyhow::anyhow!(
                        "refusing to use user with UID or GID of 0 (root), please check your wings config and change system.username to a non-root user or disable rootless mode"
                    ));
                }

                cfg.docker.userns_mode = format!(
                    "keep-id:uid={},gid={}",
                    cfg.system.user.rootless.container_uid, cfg.system.user.rootless.container_gid
                );

                return Ok(());
            }
        }

        let mut found_user = false;
        for user in users.list() {
            if user.name() == cfg.system.username {
                cfg.system.user.uid = **user.id();
                cfg.system.user.gid = *user.group_id();

                if cfg.system.user.uid == 0 || cfg.system.user.gid == 0 {
                    return Err(anyhow::anyhow!(
                        "refusing to use user with UID or GID of 0 (root), please check your wings config and change system.username to a non-root user"
                    ));
                }

                found_user = true;
                break;
            }
        }

        if found_user {
            return Ok(());
        }

        let output = if release.contains("alpine") {
            std::process::Command::new("addgroup")
                .arg("-S")
                .arg(cfg.system.username.as_str())
                .output()
                .context("failed to create group")?;

            std::process::Command::new("adduser")
                .arg("-S")
                .arg("-D")
                .arg("-H")
                .arg("-G")
                .arg(cfg.system.username.as_str())
                .arg("-s")
                .arg("/sbin/nologin")
                .arg(cfg.system.username.as_str())
                .output()
                .context(format!("failed to create user {}", cfg.system.username))?
        } else {
            std::process::Command::new("useradd")
                .arg("--system")
                .arg("--no-create-home")
                .arg("--shell")
                .arg("/usr/sbin/nologin")
                .arg(cfg.system.username.as_str())
                .output()
                .context(format!("failed to create user {}", cfg.system.username))?
        };

        if !output.status.success() {
            return Err(
                anyhow::anyhow!("failed to create user {}", cfg.system.username).context(format!(
                    "failed to create user {}: {}",
                    cfg.system.username,
                    String::from_utf8_lossy(&output.stderr)
                )),
            );
        }

        let users = sysinfo::Users::new_with_refreshed_list();

        let Some(user) = users
            .list()
            .iter()
            .find(|u| u.name() == cfg.system.username)
        else {
            return Err(anyhow::anyhow!(
                "failed to find user {} after creating it",
                cfg.system.username
            ));
        };

        cfg.system.user.uid = **user.id();
        cfg.system.user.gid = *user.group_id();

        if cfg.system.user.uid == 0 || cfg.system.user.gid == 0 {
            return Err(anyhow::anyhow!(
                "refusing to use user with UID or GID of 0 (root), please check your wings config and change system.username to a non-root user"
            ));
        }

        Ok(())
    }

    #[cfg(unix)]
    fn ensure_passwd(cfg: &InnerConfig) -> Result<(), anyhow::Error> {
        use std::os::unix::fs::PermissionsExt;

        if cfg.system.passwd.enabled {
            std::fs::write(
                Path::new(&cfg.system.passwd.directory).join("group"),
                format!(
                    "root:x:0:\ncontainer:x:{}:\nnogroup:x:65534:",
                    cfg.system.user.gid
                ),
            )
            .context(format!(
                "failed to write group file {}",
                Path::new(&cfg.system.passwd.directory)
                    .join("group")
                    .display()
            ))?;
            std::fs::set_permissions(
                Path::new(&cfg.system.passwd.directory).join("group"),
                std::fs::Permissions::from_mode(0o644),
            )
            .context(format!(
                "failed to set permissions for group file {}",
                Path::new(&cfg.system.passwd.directory)
                    .join("group")
                    .display()
            ))?;

            std::fs::write(
                Path::new(&cfg.system.passwd.directory).join("passwd"),
                format!(
                    "root:x:0:0::/root:/bin/sh\ncontainer:x:{}:{}::/home/container:/bin/sh\nnobody:x:65534:65534::/var/empty:/bin/sh\n",
                    cfg.system.user.uid, cfg.system.user.gid
                ),
            )
            .context(format!(
                "failed to write passwd file {}",
                Path::new(&cfg.system.passwd.directory).join("passwd").display()
            ))?;
            std::fs::set_permissions(
                Path::new(&cfg.system.passwd.directory).join("passwd"),
                std::fs::Permissions::from_mode(0o644),
            )
            .context(format!(
                "failed to set permissions for passwd file {}",
                Path::new(&cfg.system.passwd.directory)
                    .join("passwd")
                    .display()
            ))?;
        }

        Ok(())
    }

    pub fn vmount_path(&self, server_uuid: uuid::Uuid) -> PathBuf {
        Path::new(&self.load().system.vmount_directory).join(server_uuid.to_compact_string())
    }

    pub fn data_path(&self, server_uuid: uuid::Uuid) -> PathBuf {
        Path::new(&self.load().system.data_directory).join(server_uuid.to_compact_string())
    }

    pub fn daemon_prelude(&self) -> compact_str::CompactString {
        nu_ansi_term::Color::Yellow
            .bold()
            .paint(format!("[{} Daemon]:", self.load().app_name))
            .to_compact_string()
    }

    pub async fn ensure_docker_network(
        &self,
        client: &bollard::Docker,
    ) -> Result<(), anyhow::Error> {
        let network_name = self.load().docker.network.name.clone();
        let network = client.inspect_network(&network_name, None).await;

        if network.is_err() {
            async fn create_network(
                client: &bollard::Docker,
                cfg: &InnerConfig,
            ) -> Result<(), bollard::errors::Error> {
                client
                    .create_network(bollard::plugin::NetworkCreateRequest {
                        name: cfg.docker.network.name.to_string(),
                        driver: Some(cfg.docker.network.driver.to_string()),
                        enable_ipv6: Some(true),
                        internal: Some(cfg.docker.network.is_internal),
                        ipam: Some(bollard::models::Ipam {
                            config: Some(vec![
                                bollard::models::IpamConfig {
                                    subnet: Some(cfg.docker.network.interfaces.v4.subnet.clone()),
                                    gateway: Some(cfg.docker.network.interfaces.v4.gateway.clone()),
                                    ..Default::default()
                                },
                                bollard::models::IpamConfig {
                                    subnet: Some(cfg.docker.network.interfaces.v6.subnet.clone()),
                                    gateway: Some(cfg.docker.network.interfaces.v6.gateway.clone()),
                                    ..Default::default()
                                },
                            ]),
                            ..Default::default()
                        }),
                        options: Some(HashMap::from([
                            ("encryption".to_string(), "false".to_string()),
                            (
                                "com.docker.network.bridge.default_bridge".to_string(),
                                "false".to_string(),
                            ),
                            (
                                "com.docker.network.bridge.enable_icc".to_string(),
                                cfg.docker.network.enable_icc.to_string(),
                            ),
                            (
                                "com.docker.network.bridge.enable_ip_masquerade".to_string(),
                                "true".to_string(),
                            ),
                            (
                                "com.docker.network.bridge.host_binding_ipv4".to_string(),
                                "0.0.0.0".to_string(),
                            ),
                            (
                                "com.docker.network.bridge.name".to_string(),
                                cfg.docker.network.name.to_string(),
                            ),
                            (
                                "com.docker.network.driver.mtu".to_string(),
                                cfg.docker.network.network_mtu.to_string(),
                            ),
                        ])),
                        ..Default::default()
                    })
                    .await?;

                Ok(())
            }

            let initial_result = create_network(client, &self.load()).await;
            match initial_result {
                Ok(_) => {
                    tracing::info!("created docker network {}", self.load().docker.network.name);
                }
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code,
                    message,
                }) if status_code == 403 && message.contains("Pool overlaps") => {
                    tracing::warn!(
                        "the docker network overlaps with another network. automatically incrementing interface, pool subnet and gateway by 1 and trying again..."
                    );

                    let mut attempts = 0;
                    loop {
                        fn increment_ip_or_cidr(ip: &str) -> String {
                            let (ip, network_mask) = ip.split_once('/').unwrap_or((ip, ""));

                            if let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() {
                                let octets = ip.octets();
                                let incremented = std::net::Ipv4Addr::new(
                                    octets[0],
                                    octets[1].wrapping_add(1),
                                    octets[2],
                                    octets[3],
                                );
                                if network_mask.is_empty() {
                                    incremented.to_string()
                                } else {
                                    format!("{incremented}/{network_mask}")
                                }
                            } else if let Ok(ip) = ip.parse::<std::net::Ipv6Addr>() {
                                let segments = ip.segments();
                                let incremented = std::net::Ipv6Addr::new(
                                    segments[0],
                                    segments[1],
                                    segments[2].wrapping_add(1),
                                    segments[3],
                                    segments[4],
                                    segments[5],
                                    segments[6],
                                    segments[7],
                                );
                                if network_mask.is_empty() {
                                    incremented.to_string()
                                } else {
                                    format!("{incremented}/{network_mask}")
                                }
                            } else {
                                ip.into()
                            }
                        }

                        unsafe {
                            let m = self.mutate_in_place();
                            m.docker.network.interface =
                                increment_ip_or_cidr(&m.docker.network.interface);
                            m.docker.network.interfaces.v4.subnet =
                                increment_ip_or_cidr(&m.docker.network.interfaces.v4.subnet);
                            m.docker.network.interfaces.v4.gateway =
                                increment_ip_or_cidr(&m.docker.network.interfaces.v4.gateway);
                            m.docker.network.interfaces.v6.subnet =
                                increment_ip_or_cidr(&m.docker.network.interfaces.v6.subnet);
                            m.docker.network.interfaces.v6.gateway =
                                increment_ip_or_cidr(&m.docker.network.interfaces.v6.gateway);
                        }

                        if let Err(err) = create_network(client, &self.load()).await {
                            tracing::warn!("failed to create docker network, trying again...");
                            tracing::error!("failed to create docker network: {:?}", err);
                        } else {
                            tracing::info!(
                                "created docker network {}",
                                self.load().docker.network.name
                            );
                            break;
                        }

                        if attempts >= 80 {
                            return Err(anyhow::anyhow!(
                                "failed to create docker network after 80 attempts, aborting"
                            ));
                        }

                        attempts += 1;
                    }
                }
                Err(err) => return Err(err.into()),
            }

            let driver_is_routed = !matches!(
                self.load().docker.network.driver.as_str(),
                "host" | "overlay" | "weavemesh"
            );
            if driver_is_routed {
                unsafe {
                    let m = self.mutate_in_place();
                    m.docker.network.interface = m.docker.network.interfaces.v4.gateway.clone();
                }
            }
        }

        unsafe {
            let m = self.mutate_in_place();
            match m.docker.network.driver.as_str() {
                "host" => {
                    m.docker.network.interface = "127.0.0.1".to_string();
                }
                "overlay" | "weavemesh" => {
                    m.docker.network.interface = String::new();
                    m.docker.network.ispn = true;
                }
                _ => {
                    m.docker.network.ispn = false;
                }
            }
        }

        self.save()?;

        Ok(())
    }
}
