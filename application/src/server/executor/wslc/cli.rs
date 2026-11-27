use serde::Deserialize;
use std::{collections::HashMap, process::Stdio, sync::Arc};
use tokio::io::AsyncWriteExt;

pub const CONTAINER_NOT_RUNNING: &str = "WSLC_E_CONTAINER_NOT_RUNNING";
pub const CONTAINER_NOT_FOUND: &str = "WSLC_E_CONTAINER_NOT_FOUND";

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct InspectState {
    pub status: String,
    pub exit_code: i32,
    pub started_at: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct InspectHostConfig {
    pub nano_cpus: i64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Inspect {
    pub state: InspectState,
    pub host_config: InspectHostConfig,
    pub labels: HashMap<String, String>,
}

impl Inspect {
    pub fn started_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.state.started_at)
            .ok()
            .map(|started_at| started_at.with_timezone(&chrono::Utc))
            .filter(|started_at| started_at.timestamp() > 0)
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ListEntry {
    #[serde(rename = "ID")]
    pub id: String,
    pub names: String,
    pub state: String,
    pub ports: String,
}

impl ListEntry {
    /// Host side of every published port, parsed from `ip:port->port/proto` entries.
    pub fn published_ports(&self) -> impl Iterator<Item = (Option<std::net::IpAddr>, u16)> {
        self.ports.split(',').filter_map(|port| {
            let (host, _) = port.trim().split_once("->")?;
            let (ip, port) = host.rsplit_once(':')?;

            Some((ip.trim_matches(['[', ']']).parse().ok(), port.parse().ok()?))
        })
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct StatsEntry {
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    mem_usage: String,
    #[serde(rename = "NetIO")]
    net_io: String,
    #[serde(rename = "BlockIO")]
    block_io: String,
}

#[derive(Clone, Copy, Default)]
pub struct StatSample {
    pub cpu_absolute: f64,
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

pub type StatSamples = Arc<HashMap<String, StatSample>>;

/// Parses the sizes of the stats table, `KiB`-style units being binary and `kB`-style decimal.
fn parse_size(size: &str) -> Option<u64> {
    let size = size.trim();
    let unit_start = size.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (value, unit) = size.split_at(unit_start);

    let multiplier: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };

    Some((value.parse::<f64>().ok()? * multiplier).round() as u64)
}

fn parse_size_pair(pair: &str) -> (u64, u64) {
    let (first, second) = pair.split_once('/').unwrap_or((pair, ""));

    (
        parse_size(first).unwrap_or(0),
        parse_size(second).unwrap_or(0),
    )
}

fn parse_stats(output: &str) -> HashMap<String, StatSample> {
    let mut samples = HashMap::new();

    for entry in parse_lines::<StatsEntry>(output) {
        let (memory_bytes, memory_limit_bytes) = parse_size_pair(&entry.mem_usage);
        let (network_rx_bytes, network_tx_bytes) = parse_size_pair(&entry.net_io);
        let (disk_read_bytes, disk_write_bytes) = parse_size_pair(&entry.block_io);

        samples.insert(
            entry.name,
            StatSample {
                cpu_absolute: entry
                    .cpu_perc
                    .trim_end_matches('%')
                    .parse()
                    .unwrap_or_default(),
                memory_bytes,
                memory_limit_bytes,
                network_rx_bytes,
                network_tx_bytes,
                disk_read_bytes,
                disk_write_bytes,
            },
        );
    }

    samples
}

fn parse_lines<T: serde::de::DeserializeOwned>(output: &str) -> impl Iterator<Item = T> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str(line.trim()).ok())
}

#[derive(Clone)]
pub struct Cli;

impl Cli {
    pub fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("wslc");

        // CREATE_NO_WINDOW, a service has no console for the client to inherit
        command.creation_flags(0x0800_0000);

        command
    }

    async fn output(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<std::process::Output, anyhow::Error> {
        let mut command = self.command();
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn()?;

        if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("failed to open stdin of wslc"))?;
            stdin.write_all(input).await?;
            drop(stdin);
        }

        Ok(child.wait_with_output().await?)
    }

    pub async fn run_with_input(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        let output = self.output(args, input).await?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "wslc {} exited with {}: {}",
                args.first().copied().unwrap_or_default(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub async fn run(&self, args: &[&str]) -> Result<String, anyhow::Error> {
        self.run_with_input(args, None).await
    }

    /// `None` when no such container exists.
    pub async fn inspect(&self, container: &str) -> Result<Option<Inspect>, anyhow::Error> {
        let output = self
            .run(&[
                "inspect",
                "--type",
                "container",
                "--format",
                "json",
                container,
            ])
            .await?;

        Ok(serde_json::from_str::<Vec<Inspect>>(output.trim())?
            .into_iter()
            .next())
    }

    pub async fn image_exists(&self, image: &str) -> bool {
        self.run(&["inspect", "--type", "image", "--format", "json", image])
            .await
            .is_ok_and(|output| {
                serde_json::from_str::<Vec<serde_json::Value>>(output.trim())
                    .is_ok_and(|images| !images.is_empty())
            })
    }

    pub async fn list(&self, all: bool) -> Result<Vec<ListEntry>, anyhow::Error> {
        let mut args = vec!["list", "--no-trunc", "--format", "json"];
        if all {
            args.push("--all");
        }

        Ok(parse_lines(&self.run(&args).await?).collect())
    }

    pub async fn stats(&self) -> Result<HashMap<String, StatSample>, anyhow::Error> {
        Ok(parse_stats(
            &self.run(&["stats", "--format", "json"]).await?,
        ))
    }

    /// Removing a container that is already gone is not an error.
    pub async fn remove(&self, container: &str) -> Result<(), anyhow::Error> {
        match self.run(&["remove", "--force", container]).await {
            Ok(_) => Ok(()),
            Err(err) if err.to_string().contains(CONTAINER_NOT_FOUND) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Inspect::started_at
    #[test]
    fn started_at_parses_fractional_rfc3339_into_utc() {
        let inspect: Inspect =
            serde_json::from_str(r#"{"State":{"StartedAt":"2026-11-26T15:20:44.7839219Z"}}"#)
                .unwrap();

        let expected = chrono::NaiveDate::from_ymd_opt(2026, 11, 26)
            .unwrap()
            .and_hms_nano_opt(15, 20, 44, 783_921_900)
            .unwrap()
            .and_utc();
        assert_eq!(inspect.started_at(), Some(expected));
    }

    #[test]
    fn started_at_is_none_for_never_started_or_garbage_timestamps() {
        for started_at in ["0001-01-01T00:00:00Z", "", "not a date"] {
            let inspect: Inspect =
                serde_json::from_str(&format!(r#"{{"State":{{"StartedAt":"{started_at}"}}}}"#))
                    .unwrap();
            assert_eq!(inspect.started_at(), None, "{started_at:?}");
        }
    }

    // ListEntry
    #[test]
    fn list_entry_reads_uppercase_id_key() {
        let entry: ListEntry =
            serde_json::from_str(r#"{"ID":"001ce4ff","Names":"srv","State":"running"}"#).unwrap();

        assert_eq!(entry.id, "001ce4ff");
        assert_eq!(entry.names, "srv");
        assert_eq!(entry.ports, "");
    }

    #[test]
    fn published_ports_yields_host_side_and_skips_unpublished_entries() {
        let entry: ListEntry = serde_json::from_str(
            r#"{"Ports":"127.0.0.1:25570->25565/tcp, [::]:25571->25565/udp, 25565/tcp"}"#,
        )
        .unwrap();

        assert_eq!(
            entry.published_ports().collect::<Vec<_>>(),
            vec![
                (Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 25570),
                (Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), 25571),
            ]
        );
    }

    #[test]
    fn published_ports_is_empty_for_empty_ports_string() {
        let entry: ListEntry = serde_json::from_str(r#"{"Ports":""}"#).unwrap();

        assert_eq!(entry.published_ports().count(), 0);
    }

    // parse_size
    #[test]
    fn binary_and_decimal_units_use_their_own_base() {
        assert_eq!(parse_size("0B"), Some(0));
        assert_eq!(parse_size("876B"), Some(876));
        assert_eq!(parse_size("1kB"), Some(1_000));
        assert_eq!(parse_size("1KiB"), Some(1_024));
        assert_eq!(parse_size("2MB"), Some(2_000_000));
        assert_eq!(parse_size("2MiB"), Some(2 * 1_024 * 1_024));
        assert_eq!(parse_size("1GB"), Some(1_000_000_000));
        assert_eq!(parse_size("1GiB"), Some(1_073_741_824));
        assert_eq!(parse_size("1TB"), Some(1_000_000_000_000));
        assert_eq!(parse_size("1TiB"), Some(1_099_511_627_776));
    }

    #[test]
    fn fractional_sizes_round_to_nearest_byte_and_tolerate_whitespace() {
        assert_eq!(parse_size("514.4MiB"), Some(539_387_494));
        assert_eq!(parse_size(" 2.3GiB "), Some(2_469_606_195));
    }

    #[test]
    fn unknown_units_and_malformed_numbers_are_rejected() {
        assert_eq!(parse_size("12XB"), None);
        assert_eq!(parse_size("abcMiB"), None);
        assert_eq!(parse_size("1.2.3kB"), None);
        assert_eq!(parse_size(""), None);
    }

    // parse_size_pair
    #[test]
    fn unparsable_side_of_pair_becomes_zero() {
        assert_eq!(parse_size_pair("876B / 135kB"), (876, 135_000));
        assert_eq!(parse_size_pair("876B / --"), (876, 0));
        assert_eq!(parse_size_pair("garbage"), (0, 0));
    }

    // parse_stats
    #[test]
    fn stats_lines_are_keyed_by_name_and_invalid_lines_skipped() {
        let output = concat!(
            "WARNING: something odd\n",
            "\n",
            r#"{"BlockIO":"0B / 135kB","CPUPerc":"159.60%","ID":"001ce4ff","MemPerc":"21.84%","MemUsage":"514.4MiB / 2.3GiB","Name":"a276646a-4d7b-4504-a7a9-f6856657467a","NetIO":"876B / 0B","PIDs":23}"#,
            "\n",
        );

        let stats = parse_stats(output);

        assert_eq!(stats.len(), 1);
        let sample = stats["a276646a-4d7b-4504-a7a9-f6856657467a"];
        assert_eq!(sample.cpu_absolute, 159.6);
        assert_eq!(sample.memory_bytes, 539_387_494);
        assert_eq!(sample.memory_limit_bytes, 2_469_606_195);
        assert_eq!(sample.network_rx_bytes, 876);
        assert_eq!(sample.network_tx_bytes, 0);
        assert_eq!(sample.disk_read_bytes, 0);
        assert_eq!(sample.disk_write_bytes, 135_000);
    }
}
