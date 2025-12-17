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
pub mod protocol;
pub mod store;
pub mod types;

pub use peer::{ForwardRequestCallback, Peer, PeerError};
pub use protocol::{
    bytes_to_hash, create_fragment_response, create_request, create_response, encode_request,
    encode_response, hash_to_bytes, hash_to_key, is_fragmented, parse_message, DataMessage,
    DataRequest, DataResponse, FRAGMENT_SIZE, MSG_TYPE_REQUEST, MSG_TYPE_RESPONSE,
};
pub use store::{WebRTCStore, WebRTCStoreError};
pub use types::{
    classifier_channel, should_forward, ClassifierRx, ClassifierTx, ClassifyRequest,
    ForwardRequest, ForwardRx, ForwardTx, IceCandidate, PeerId, PeerHTLConfig, PeerPool,
    PeerState, PoolConfig, PoolSettings, SignalingMessage, WebRTCStats, WebRTCStoreConfig,
    DATA_CHANNEL_LABEL, MAX_HTL, NOSTR_KIND_HASHTREE,
};
