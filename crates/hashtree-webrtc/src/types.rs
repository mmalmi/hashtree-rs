//! WebRTC transport types for P2P data exchange
//!
//! Defines message types for WebRTC signaling via Nostr relays
//! and the data channel protocol for hash-based data requests.

use hashtree_core::Hash;
use serde::{Deserialize, Serialize};

/// Unique identifier for a peer in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId {
    /// Nostr public key (hex encoded)
    pub pubkey: String,
    /// Unique session identifier
    pub uuid: String,
}

impl PeerId {
    pub fn new(pubkey: String, uuid: String) -> Self {
        Self { pubkey, uuid }
    }

    pub fn to_peer_string(&self) -> String {
        format!("{}:{}", self.pubkey, self.uuid)
    }

    pub fn from_peer_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            Some(Self {
                pubkey: parts[0].to_string(),
                uuid: parts[1].to_string(),
            })
        } else {
            None
        }
    }
}

/// Signaling message types sent via Nostr relays
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    /// Initial hello message to discover peers
    #[serde(rename = "hello")]
    Hello {
        #[serde(rename = "peerId")]
        peer_id: String,
        roots: Vec<String>,
    },

    /// WebRTC offer (SDP)
    #[serde(rename = "offer")]
    Offer {
        #[serde(rename = "peerId")]
        peer_id: String,
        #[serde(rename = "targetPeerId")]
        target_peer_id: String,
        sdp: String,
    },

    /// WebRTC answer (SDP)
    #[serde(rename = "answer")]
    Answer {
        #[serde(rename = "peerId")]
        peer_id: String,
        #[serde(rename = "targetPeerId")]
        target_peer_id: String,
        sdp: String,
    },

    /// Single ICE candidate
    #[serde(rename = "candidate")]
    Candidate {
        #[serde(rename = "peerId")]
        peer_id: String,
        #[serde(rename = "targetPeerId")]
        target_peer_id: String,
        candidate: String,
        #[serde(rename = "sdpMLineIndex")]
        sdp_m_line_index: Option<u16>,
        #[serde(rename = "sdpMid")]
        sdp_mid: Option<String>,
    },

    /// Batched ICE candidates
    #[serde(rename = "candidates")]
    Candidates {
        #[serde(rename = "peerId")]
        peer_id: String,
        #[serde(rename = "targetPeerId")]
        target_peer_id: String,
        candidates: Vec<IceCandidate>,
    },
}

/// ICE candidate for WebRTC connection establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_m_line_index: Option<u16>,
    #[serde(rename = "sdpMid")]
    pub sdp_mid: Option<String>,
}

/// Data channel message types for hash-based data exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DataMessage {
    /// Request data by hash
    #[serde(rename = "req")]
    Request { id: u32, hash: String },

    /// Response with data (binary payload follows)
    #[serde(rename = "res")]
    Response {
        id: u32,
        hash: String,
        found: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
    },

    /// Push data for a hash the peer previously requested but we didn't have
    /// This happens when we get it later from another peer
    #[serde(rename = "push")]
    Push { hash: String },

    /// Announce available hashes
    #[serde(rename = "have")]
    Have { hashes: Vec<String> },

    /// Request list of wanted hashes
    #[serde(rename = "want")]
    Want { hashes: Vec<String> },

    /// Notify about root hash update
    #[serde(rename = "root")]
    RootUpdate {
        hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
    },
}

use tokio::sync::{mpsc, oneshot};

/// Peer pool classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerPool {
    /// Users in social graph (followed or followers)
    Follows,
    /// Everyone else
    Other,
}

/// Settings for a peer pool
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Maximum connections in this pool
    pub max_connections: usize,
    /// Number of connections to consider "satisfied"
    pub satisfied_connections: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            satisfied_connections: 5,
        }
    }
}

/// Pool settings for both pools
#[derive(Debug, Clone)]
pub struct PoolSettings {
    pub follows: PoolConfig,
    pub other: PoolConfig,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            follows: PoolConfig {
                max_connections: 20,
                satisfied_connections: 10,
            },
            other: PoolConfig {
                max_connections: 10,
                satisfied_connections: 5,
            },
        }
    }
}

/// Request to classify a peer by pubkey
pub struct ClassifyRequest {
    /// Pubkey to classify (hex)
    pub pubkey: String,
    /// Channel to send result back
    pub response: oneshot::Sender<PeerPool>,
}

/// Sender for peer classification requests
pub type ClassifierTx = mpsc::Sender<ClassifyRequest>;

/// Receiver for peer classification requests (implement this to provide classification)
pub type ClassifierRx = mpsc::Receiver<ClassifyRequest>;

/// Create a classifier channel pair
pub fn classifier_channel(buffer: usize) -> (ClassifierTx, ClassifierRx) {
    mpsc::channel(buffer)
}

/// Configuration for WebRTC store
#[derive(Clone)]
pub struct WebRTCStoreConfig {
    /// Nostr relays for signaling
    pub relays: Vec<String>,
    /// Root hashes to advertise
    pub roots: Vec<Hash>,
    /// Timeout for data requests (ms)
    pub request_timeout_ms: u64,
    /// Interval for sending hello messages (ms)
    pub hello_interval_ms: u64,
    /// Enable verbose logging
    pub debug: bool,
    /// Pool settings for follows and other peers
    pub pools: PoolSettings,
    /// Channel for peer classification (optional)
    /// If None, all peers go to "Other" pool
    pub classifier_tx: Option<ClassifierTx>,
}

impl Default for WebRTCStoreConfig {
    fn default() -> Self {
        Self {
            relays: vec![
                "wss://temp.iris.to".to_string(),
                "wss://relay.damus.io".to_string(),
            ],
            roots: Vec::new(),
            request_timeout_ms: 10000,
            hello_interval_ms: 30000,
            debug: false,
            pools: PoolSettings::default(),
            classifier_tx: None,
        }
    }
}

/// Connection state for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state
    New,
    /// Connecting via signaling
    Connecting,
    /// WebRTC connection established
    Connected,
    /// Data channel open and ready
    Ready,
    /// Connection failed or closed
    Disconnected,
}

/// Statistics for WebRTC store
#[derive(Debug, Clone, Default)]
pub struct WebRTCStats {
    pub connected_peers: usize,
    pub pending_requests: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_made: u64,
    pub requests_fulfilled: u64,
}

/// Nostr event kind for hashtree signaling
pub const NOSTR_KIND_HASHTREE: u16 = 29333;

/// Data channel label
pub const DATA_CHANNEL_LABEL: &str = "hashtree";
