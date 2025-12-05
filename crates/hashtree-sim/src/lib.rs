//! Simulation tools for hashtree P2P protocols
//!
//! Provides store implementations for testing different routing strategies.
//!
//! ## Architecture
//!
//! - `SimStore` - local-only storage (implements hashtree::Store)
//! - `FloodingStore` - complete P2P node with signaling + multi-hop forwarding (like WebRTCStore)
//! - `SequentialStore` - sends to one peer at a time, forwards if not found locally
//! - `MockRelay` - Nostr-like relay for signaling
//! - `PeerChannel` trait - abstraction for peer communication

mod behavior;
mod channel;
mod flooding;
mod message;
mod peer_agent;
mod relay;
mod sequential;
mod simulation;
mod store;

pub use behavior::{Behavior, Cooperative, Malicious, Probabilistic};
pub use channel::{ChannelError, LatencyChannel, MockChannel, PeerChannel};
pub use flooding::{
    handle_request as flooding_handle_request, FloodingConfig, FloodingStore, RoutingStrategy,
    SignalingContent,
};
pub use message::{
    encode_push, encode_request, encode_response, parse, Hash, ParseError,
    ParsedMessage, RequestId, MSG_PUSH, MSG_REQUEST, MSG_RESPONSE,
};
pub use peer_agent::{OurRequest, PeerAgent, TheirRequest};
pub use relay::{
    ClientMessage, Event, Filter, MockRelay, RelayClient, RelayError, RelayMessage,
    KIND_ANSWER, KIND_CANDIDATE, KIND_OFFER, KIND_PRESENCE,
};
pub use sequential::{handle_request as sequential_handle_request, SequentialStore};
pub use simulation::{
    BenchmarkResults, RequestResult, SimConfig, SimEvent, SimStats, Simulation, TopologyStats,
};
pub use store::{NetworkStore, SimStore};

/// Node identifier
pub type NodeId = u64;

// Re-export hashtree types for convenience
pub use hashtree::{Cid, HashTree, HashTreeConfig, MemoryStore, Store};
