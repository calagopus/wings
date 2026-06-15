//! Standalone Proxmox Backup Server client, independent of the backup adapter so
//! it can be unit-tested on its own.
//!
//! It provides the connection primitives (config, token auth, TLS fingerprint
//! pinning, deterministic group naming), the synchronous management REST surface
//! (datastore status, listing, exact-snapshot deletion), and the streaming
//! writer/reader protocols (DataBlob + dynamic-index) used to create, restore,
//! and download backups.

pub mod auth;
pub mod chunker;
pub mod config;
pub mod datablob;
pub mod error;
pub mod h2;
pub mod manifest;
pub mod naming;
pub mod reader;
pub mod rest;
pub mod tls;
pub mod writer;
