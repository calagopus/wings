use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod reader;
pub mod writer;

#[derive(Debug, Clone, Copy, ToSchema, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum CompressionType {
    #[default]
    None,
    Gz,
    Xz,
    Lzip,
    Bz2,
    Lz4,
    Zstd,
}

impl CompressionType {
    #[inline]
    pub fn variants() -> &'static [Self] {
        &[
            Self::None,
            Self::Gz,
            Self::Xz,
            Self::Lzip,
            Self::Bz2,
            Self::Lz4,
            Self::Zstd,
        ]
    }

    pub fn from_mime(mime: &str) -> Self {
        match mime {
            "application/gzip" => CompressionType::Gz,
            "application/x-xz" => CompressionType::Xz,
            "application/x-lzip" => CompressionType::Lzip,
            "application/x-bzip2" => CompressionType::Bz2,
            "application/x-lz4" => CompressionType::Lz4,
            "application/zstd" => CompressionType::Zstd,
            _ => CompressionType::None,
        }
    }

    pub fn from_file_name(file_name: &str) -> Self {
        if file_name.ends_with(".gz") {
            CompressionType::Gz
        } else if file_name.ends_with(".xz") {
            CompressionType::Xz
        } else if file_name.ends_with(".lz") {
            CompressionType::Lzip
        } else if file_name.ends_with(".bz2") {
            CompressionType::Bz2
        } else if file_name.ends_with(".lz4") {
            CompressionType::Lz4
        } else if file_name.ends_with(".zst") {
            CompressionType::Zstd
        } else {
            CompressionType::None
        }
    }
}

#[derive(Debug, Clone, Copy, ToSchema, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum CompressionLevel {
    #[default]
    BestSpeed,
    GoodSpeed,
    GoodCompression,
    BestCompression,
}

impl CompressionLevel {
    #[inline]
    pub const fn to_deflate_level(self) -> u32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 4,
            CompressionLevel::GoodCompression => 6,
            CompressionLevel::BestCompression => 9,
        }
    }

    #[inline]
    pub const fn to_xz_level(self) -> u32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 4,
            CompressionLevel::GoodCompression => 6,
            CompressionLevel::BestCompression => 9,
        }
    }

    #[inline]
    pub const fn to_bz2_level(self) -> u32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 4,
            CompressionLevel::GoodCompression => 6,
            CompressionLevel::BestCompression => 9,
        }
    }

    #[inline]
    pub const fn to_zstd_level(self) -> i32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 8,
            CompressionLevel::GoodCompression => 13,
            CompressionLevel::BestCompression => 19,
        }
    }

    #[inline]
    pub const fn to_lzma2_level(self) -> u32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 4,
            CompressionLevel::GoodCompression => 6,
            CompressionLevel::BestCompression => 9,
        }
    }

    #[inline]
    pub const fn to_lzip_level(self) -> u32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 4,
            CompressionLevel::GoodCompression => 6,
            CompressionLevel::BestCompression => 9,
        }
    }

    #[inline]
    pub const fn to_lz4_level(self) -> i32 {
        match self {
            CompressionLevel::BestSpeed => 1,
            CompressionLevel::GoodSpeed => 5,
            CompressionLevel::GoodCompression => 8,
            CompressionLevel::BestCompression => 12,
        }
    }
}
