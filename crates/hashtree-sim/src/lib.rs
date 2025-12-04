//! Network simulation for hashtree P2P protocols
//!
//! Discrete event simulation for testing request forwarding strategies,
//! network topologies, and node behaviors at scale.
//!
//! ## Architecture
//!
//! Each simulated node is an actor with:
//! - Local HashTree-backed storage (SimStore implements hashtree::Store)
//! - Per-peer connections via PeerAgent (like hashtree-ts Peer)
//! - Behavior strategy (cooperative, selfish, malicious, etc.)
//!
//! The network uses a discrete event queue for message passing with
//! configurable latency distributions.
//!
//! ## Per-Peer Agent Model
//!
//! Similar to hashtree-ts, each peer connection is an independent agent:
//! - `PeerAgent::our_requests` - requests we sent TO this peer
//! - `PeerAgent::their_requests` - requests this peer sent TO US
//! - Each agent handles its own request/response tracking and timeouts

mod node;
mod network;
mod behavior;
mod config;
mod metrics;
mod message;
mod store;
mod adapter;
mod peer_agent;

pub use node::{SimNode, NodeId, ActiveQuery, ForwardedQuery};
pub use network::Network;
pub use behavior::{Behavior, Cooperative, Malicious, Probabilistic};
pub use config::{SimConfig, LatencyDistribution};
pub use metrics::SimMetrics;
pub use message::{Message, Request, Response};
pub use store::{SimStore, NetworkStore, NetworkRequest};
pub use adapter::{NetworkAdapter, MockNetwork, FetchRequest, FetchResult};
pub use peer_agent::{PeerAgent, OurRequest, TheirRequest};

// Re-export hashtree types for convenience
pub use hashtree::{Hash, HashTree, HashTreeConfig, MemoryStore, Store, Cid};
