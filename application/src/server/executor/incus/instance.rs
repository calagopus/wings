use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) type Devices = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Instance {
    pub name: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub stateful: bool,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub devices: Devices,
    #[serde(default)]
    pub expanded_devices: Devices,
}
impl Instance {
    pub(super) fn effective_devices(&self) -> &Devices {
        if self.expanded_devices.is_empty() {
            &self.devices
        } else {
            &self.expanded_devices
        }
    }

    pub(super) fn is_helper_for(&self, server: uuid::Uuid) -> bool {
        self.name == format!("wgi-{server}")
            || self
                .name
                .strip_prefix(&format!("wgx-{server}-"))
                .is_some_and(|suffix| {
                    suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    }

    pub(super) fn update_body(&self) -> Value {
        json!({
            "architecture": self.architecture,
            "description": self.description,
            "ephemeral": self.ephemeral,
            "profiles": self.profiles,
            "stateful": self.stateful,
            "config": self.config,
            "devices": self.devices,
        })
    }
}
#[derive(Clone, Debug, Deserialize)]
pub(super) struct InstanceState {
    pub status: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub cpu: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub memory: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub network: BTreeMap<String, NetworkState>,
    #[serde(default)]
    pub started_at: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct NetworkState {
    #[serde(default)]
    pub addresses: Vec<NetworkAddress>,
    #[serde(default)]
    pub counters: NetworkCounters,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct NetworkAddress {
    pub address: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(super) struct NetworkCounters {
    #[serde(default)]
    pub bytes_received: u64,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub packets_received: u64,
    #[serde(default)]
    pub packets_sent: u64,
}
