//! Nostr relay implementation using nostrdb
//!
//! This crate provides both:
//! - Outbound relay connections (connecting to other relays)
//! - Inbound relay server (accepting connections as a relay)
//! - Social graph crawler

pub mod crawler;
mod outbound;
mod server;

pub use crawler::{CrawlerState, CrawlerStats, KIND_CONTACTS};
pub use outbound::{
    NdbQuerySender, RelayConfig, RelayManager, RelayThreadHandle, SocialGraphStats,
    spawn_relay_thread, DEFAULT_RELAYS,
};
pub use server::{RelayState, ws_handler};
