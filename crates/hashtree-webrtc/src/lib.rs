//! WebRTC P2P transport for HashTree
//!
//! This crate provides WebRTC-based peer-to-peer data exchange for hashtree,
//! using Nostr relays for peer discovery and signaling.
//!
//! # Overview
//!
//! - **Peer Discovery**: Uses Nostr relay network for signaling
//! - **Data Exchange**: WebRTC data channels for binary data transfer
//! - **Protocol**: Request/response with hash-based addressing
//!
//! # Example
//!
//! ```rust,no_run
//! use hashtree_core::MemoryStore;
//! use hashtree_webrtc::{WebRTCStore, WebRTCStoreConfig};
//! use nostr_sdk::prelude::*;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let local_store = Arc::new(MemoryStore::new());
//!     let config = WebRTCStoreConfig::default();
//!
//!     let mut store = WebRTCStore::new(local_store, config);
//!
//!     // Generate or load Nostr keys
//!     let keys = Keys::generate();
//!
//!     // Start P2P network
//!     store.start(keys).await?;
//!
//!     // Now store.get() will try local first, then fetch from peers
//!
//!     Ok(())
//! }
//! ```

pub mod peer;
pub mod store;
pub mod types;

pub use peer::{Peer, PeerError};
pub use store::{WebRTCStore, WebRTCStoreError};
pub use types::{
    DataMessage, IceCandidate, PeerId, PeerState, SignalingMessage, WebRTCStats,
    WebRTCStoreConfig, DATA_CHANNEL_LABEL, NOSTR_KIND_HASHTREE,
};
