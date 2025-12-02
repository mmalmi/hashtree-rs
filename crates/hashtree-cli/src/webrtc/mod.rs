//! WebRTC peer-to-peer connectivity for hashtree data exchange
//!
//! Uses Nostr relays for signaling with the same protocol as iris-client:
//! - Event kind: 30078 (KIND_APP_DATA)
//! - Tag: ["l", "webrtc"]
//! - Message types: hello, offer, answer, candidate

mod peer;
mod signaling;
mod types;

#[cfg(test)]
mod tests;

pub use peer::{ContentStore, DataMessage, Peer};
pub use signaling::{ConnectionState, PeerEntry, WebRTCManager, WebRTCState};
pub use types::{PeerDirection, PeerId, SignalingMessage, WebRTCConfig};
