//! Simulation tools for hashtree P2P protocols
//!
//! Provides store implementations for testing different routing strategies.
//!
//! ## Architecture
//!
//! The preferred approach is to use `webrtc_sim` which uses the exact same
//! code as production WebRTCStore with mock transports.
//!
//! - `webrtc_sim::Simulation` - uses GenericStore with mock transports (RECOMMENDED)
//! - `SimStore` - local-only storage (implements hashtree_core::Store)
//! - `FloodingStore` - legacy P2P node (DEPRECATED - use webrtc_sim instead)
//! - `MockRelay` - Nostr-like relay for signaling
//! - `PeerChannel` trait - abstraction for peer communication

mod behavior;
mod channel;
mod flooding;
mod message;
mod peer_agent;
mod peer_selector;
mod relay;
mod sequential;
mod simulation;
mod store;
pub mod webrtc_sim;
pub mod ws_relay;

pub use behavior::{Behavior, Cooperative, Malicious, Probabilistic};
pub use channel::{ChannelError, LatencyChannel, MockChannel, PeerChannel};
pub use flooding::{
    clear_channel_registry, handle_request as flooding_handle_request, FloodingConfig,
    FloodingStore, PoolConfig, PoolSettings, RoutingStrategy,
};
// Re-export types from hashtree-webrtc for simulation users
pub use hashtree_webrtc::SignalingMessage;
pub use message::{
    decrement_htl, encode_request, encode_response, parse, should_forward,
    DataRequest, DataResponse, Hash, ParseError, ParsedMessage, PeerHTLConfig,
    DECREMENT_AT_MAX_PROB, DECREMENT_AT_MIN_PROB, MAX_HTL, MSG_TYPE_REQUEST, MSG_TYPE_RESPONSE,
};
pub use peer_agent::{OurRequest, PeerAgent, TheirRequest};
pub use peer_selector::{PeerSelector, PeerStats, SelectionStrategy, SelectorSummary};
pub use relay::{
    ClientMessage, Event, Filter, MockRelay, RelayClient, RelayError, RelayMessage,
    KIND_ANSWER, KIND_CANDIDATE, KIND_OFFER, KIND_PRESENCE,
};
pub use sequential::{handle_request as sequential_handle_request, SequentialStore};
pub use simulation::{
    BenchmarkResults, RequestResult, SimConfig, SimEvent, SimStats, Simulation, TopologyStats,
};
pub use store::{NetworkStore, SimStore};
pub use ws_relay::WsRelay;

/// Node identifier
pub type NodeId = u64;

// Re-export hashtree types for convenience
pub use hashtree_core::{Cid, HashTree, HashTreeConfig, MemoryStore, Store};
