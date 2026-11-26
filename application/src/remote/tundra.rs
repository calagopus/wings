use serde::Deserialize;
use tundra_common::state::Snapshot;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TunnelState {
    Enabled(Snapshot),
    Disabled { disabled: Disabled },
}

#[derive(Deserialize)]
#[serde(try_from = "bool")]
pub struct Disabled;

impl TryFrom<bool> for Disabled {
    type Error = &'static str;

    fn try_from(value: bool) -> Result<Self, Self::Error> {
        if value {
            Ok(Self)
        } else {
            Err("disabled must be true")
        }
    }
}
