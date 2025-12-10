//! WebRTC signaling types compatible with iris-client and hashtree-ts

use serde::{Deserialize, Serialize};

/// Event kind for WebRTC signaling (same as iris-client's KIND_APP_DATA)
pub const WEBRTC_KIND: u64 = 30078;

/// Tag for WebRTC signaling messages
pub const WEBRTC_TAG: &str = "webrtc";

/// Generate a UUID for peer identification
pub fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "{}{}",
        (0..15).map(|_| char::from_digit(rng.gen_range(0..36), 36).unwrap()).collect::<String>(),
        (0..15).map(|_| char::from_digit(rng.gen_range(0..36), 36).unwrap()).collect::<String>()
    )
}

/// Peer identifier combining pubkey and session UUID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId {
    pub pubkey: String,
    pub uuid: String,
}

impl PeerId {
    pub fn new(pubkey: String, uuid: Option<String>) -> Self {
        Self {
            pubkey,
            uuid: uuid.unwrap_or_else(generate_uuid),
        }
    }

    pub fn from_string(s: &str) -> Option<Self> {
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

    pub fn short(&self) -> String {
        format!("{}:{}", &self.pubkey[..8.min(self.pubkey.len())], &self.uuid[..6.min(self.uuid.len())])
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.pubkey, self.uuid)
    }
}

/// Hello message for peer discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "peerId")]
    pub peer_id: String,
}

/// WebRTC offer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub offer: serde_json::Value,
    pub recipient: String,
    #[serde(rename = "peerId")]
    pub peer_id: String,
}

/// WebRTC answer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub answer: serde_json::Value,
    pub recipient: String,
    #[serde(rename = "peerId")]
    pub peer_id: String,
}

/// ICE candidate message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub candidate: serde_json::Value,
    pub recipient: String,
    #[serde(rename = "peerId")]
    pub peer_id: String,
}

/// Batched ICE candidates message (hashtree-ts extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatesMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub candidates: Vec<serde_json::Value>,
    pub recipient: String,
    #[serde(rename = "peerId")]
    pub peer_id: String,
}

/// All signaling message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    #[serde(rename = "hello")]
    Hello { #[serde(rename = "peerId")] peer_id: String },
    #[serde(rename = "offer")]
    Offer {
        offer: serde_json::Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    #[serde(rename = "answer")]
    Answer {
        answer: serde_json::Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    #[serde(rename = "candidate")]
    Candidate {
        candidate: serde_json::Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    #[serde(rename = "candidates")]
    Candidates {
        candidates: Vec<serde_json::Value>,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
}

impl SignalingMessage {
    pub fn msg_type(&self) -> &str {
        match self {
            SignalingMessage::Hello { .. } => "hello",
            SignalingMessage::Offer { .. } => "offer",
            SignalingMessage::Answer { .. } => "answer",
            SignalingMessage::Candidate { .. } => "candidate",
            SignalingMessage::Candidates { .. } => "candidates",
        }
    }

    pub fn recipient(&self) -> Option<&str> {
        match self {
            SignalingMessage::Hello { .. } => None,
            SignalingMessage::Offer { recipient, .. } => Some(recipient),
            SignalingMessage::Answer { recipient, .. } => Some(recipient),
            SignalingMessage::Candidate { recipient, .. } => Some(recipient),
            SignalingMessage::Candidates { recipient, .. } => Some(recipient),
        }
    }

    pub fn peer_id(&self) -> &str {
        match self {
            SignalingMessage::Hello { peer_id } => peer_id,
            SignalingMessage::Offer { peer_id, .. } => peer_id,
            SignalingMessage::Answer { peer_id, .. } => peer_id,
            SignalingMessage::Candidate { peer_id, .. } => peer_id,
            SignalingMessage::Candidates { peer_id, .. } => peer_id,
        }
    }

    pub fn hello(peer_id: &str) -> Self {
        SignalingMessage::Hello {
            peer_id: peer_id.to_string(),
        }
    }

    pub fn offer(offer: serde_json::Value, recipient: &str, peer_id: &str) -> Self {
        SignalingMessage::Offer {
            offer,
            recipient: recipient.to_string(),
            peer_id: peer_id.to_string(),
        }
    }

    pub fn answer(answer: serde_json::Value, recipient: &str, peer_id: &str) -> Self {
        SignalingMessage::Answer {
            answer,
            recipient: recipient.to_string(),
            peer_id: peer_id.to_string(),
        }
    }

    pub fn candidate(candidate: serde_json::Value, recipient: &str, peer_id: &str) -> Self {
        SignalingMessage::Candidate {
            candidate,
            recipient: recipient.to_string(),
            peer_id: peer_id.to_string(),
        }
    }
}

/// Configuration for WebRTC manager
#[derive(Clone)]
pub struct WebRTCConfig {
    /// Nostr relays for signaling
    pub relays: Vec<String>,
    /// Maximum outbound connections (legacy, use pools instead)
    pub max_outbound: usize,
    /// Maximum inbound connections (legacy, use pools instead)
    pub max_inbound: usize,
    /// Hello message interval in milliseconds
    pub hello_interval_ms: u64,
    /// Message timeout in milliseconds
    pub message_timeout_ms: u64,
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// Enable debug logging
    pub debug: bool,
    /// Pool settings for follows and other peers
    pub pools: PoolSettings,
}

impl Default for WebRTCConfig {
    fn default() -> Self {
        Self {
            relays: vec![
                "wss://relay.damus.io".to_string(),
                "wss://relay.primal.net".to_string(),
                "wss://nos.lol".to_string(),
                "wss://temp.iris.to".to_string(),
                "wss://relay.snort.social".to_string(),
            ],
            max_outbound: 6,
            max_inbound: 6,
            hello_interval_ms: 10000,
            message_timeout_ms: 15000,
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun.cloudflare.com:3478".to_string(),
            ],
            debug: false,
            pools: PoolSettings::default(),
        }
    }
}

/// Peer connection status
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub peer_id: String,
    pub pubkey: String,
    pub state: String,
    pub direction: PeerDirection,
    pub connected_at: Option<std::time::Instant>,
    pub pool: PeerPool,
}

/// Direction of peer connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

/// Pool type for peer classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerPool {
    /// Users in social graph (followed or followers)
    Follows,
    /// Everyone else
    Other,
}

/// Configuration for a peer pool
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Maximum connections in this pool
    pub max_connections: usize,
    /// Number of connections to consider "satisfied" (stop sending hellos)
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

impl std::fmt::Display for PeerDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerDirection::Inbound => write!(f, "inbound"),
            PeerDirection::Outbound => write!(f, "outbound"),
        }
    }
}

/// Hashtree data channel protocol messages
/// Shared between WebRTC data channels and WebSocket transport
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DataMessage {
    #[serde(rename = "req")]
    Request { id: u32, hash: String },

    #[serde(rename = "res")]
    Response { id: u32, hash: String, found: bool },

    #[serde(rename = "push")]
    Push { hash: String },

    #[serde(rename = "have")]
    Have { hashes: Vec<String> },

    #[serde(rename = "want")]
    Want { hashes: Vec<String> },

    #[serde(rename = "root")]
    Root { hash: String },
}
