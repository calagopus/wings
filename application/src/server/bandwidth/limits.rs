use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const MINIMUM_RATE: u64 = 8;
pub const MAXIMUM_RATE: u64 = 100_000_000_000;

#[derive(Clone, Copy, Default, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
pub struct BandwidthLimits {
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
}

impl BandwidthLimits {
    pub fn is_limited(self) -> bool {
        self.upload != 0 || self.download != 0
    }
}
