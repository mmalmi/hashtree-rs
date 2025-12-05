//! Simulation tools for hashtree P2P protocols
//!
//! Provides store implementations for testing different routing strategies.
//!
//! ## NetworkStore implementations
//!
//! - `FloodingStore` - sends to all peers, returns first response (high bandwidth, low latency)
//! - `SequentialStore` - sends to one peer at a time with not_found (low bandwidth, higher latency)
//!
//! ## Architecture
//!
//! - `SimStore` - local-only storage (implements hashtree::Store)
//! - `NetworkStore` trait - extends Store with network fetch capability
//! - `PeerChannel` trait - abstraction for peer communication
//! - `PeerAgent` - per-peer request/response tracking

mod store;
mod peer_agent;
mod message;
mod behavior;
mod channel;
mod flooding;
mod sequential;
mod relay;
mod node;
mod simulation;
mod agent;

pub use store::{SimStore, NetworkStore};
pub use peer_agent::{PeerAgent, OurRequest, TheirRequest};
pub use message::{
    Hash, RequestId, ParsedMessage, ParseError,
    encode_request, encode_response, encode_not_found, encode_push, parse,
    MSG_REQUEST, MSG_RESPONSE, MSG_NOT_FOUND, MSG_PUSH,
};
pub use behavior::{Behavior, Cooperative, Malicious, Probabilistic};
pub use channel::{PeerChannel, ChannelError, MockChannel, LatencyChannel};
pub use flooding::{FloodingStore, handle_request as flooding_handle_request};
pub use sequential::{SequentialStore, handle_request as sequential_handle_request};
pub use relay::{
    MockRelay, RelayClient, RelayError, Event, Filter, RelayMessage, ClientMessage,
    KIND_PRESENCE, KIND_OFFER, KIND_ANSWER, KIND_CANDIDATE,
};
pub use node::{SimNode, NodeConfig, SimPeer, SignalingContent, RoutingStrategy};
pub use simulation::{Simulation, SimConfig, SimEvent, SimStats, TopologyStats, BenchmarkResults, RequestResult};
pub use agent::{Agent, AgentConfig};

/// Node identifier
pub type NodeId = u64;

// Re-export hashtree types for convenience
pub use hashtree::{HashTree, HashTreeConfig, MemoryStore, Store, Cid};
