//! Social graph and relay connections using nostrdb
//!
//! This crate provides:
//! - Outbound relay connections (connecting to other relays)
//! - Social graph crawler

pub mod crawler;
mod outbound;

pub use crawler::{CrawlerState, CrawlerStats, KIND_CONTACTS};
pub use outbound::{
    NdbQuerySender, RelayConfig, RelayManager, RelayThreadHandle, SocialGraphStats,
    spawn_relay_thread, DEFAULT_RELAYS,
};
