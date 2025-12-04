//! Peer agent for simulated P2P connections
//!
//! Each PeerAgent represents a connection to a single peer, similar to
//! hashtree-ts's Peer class. It tracks:
//! - Requests we sent TO this peer (ourRequests)
//! - Requests this peer sent TO US that we couldn't fulfill (theirRequests)
//!
//! This allows proper per-peer request tracking and response routing.

use crate::message::Hash;
use crate::NodeId;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;

/// Default LRU cache sizes (matching hashtree-ts)
const OUR_REQUESTS_SIZE: usize = 100;
const THEIR_REQUESTS_SIZE: usize = 200;

/// A request we sent TO this peer, waiting for response
#[derive(Debug, Clone)]
pub struct OurRequest {
    /// The hash we requested
    pub hash: Hash,
    /// When we sent the request (simulation tick)
    pub sent_at: u64,
    /// Query ID for correlating with the original requester
    pub query_id: u64,
}

/// A request this peer sent TO US that we couldn't fulfill locally
/// We track it so we can push data back when/if we get it from another peer
#[derive(Debug, Clone)]
pub struct TheirRequest {
    /// Their request ID (for response correlation)
    pub id: u32,
    /// When they requested it (simulation tick)
    pub requested_at: u64,
}

/// Simulated peer connection agent
///
/// Models a single peer-to-peer connection, similar to hashtree-ts Peer class.
/// Each node has multiple PeerAgents, one per connected peer.
#[derive(Debug)]
pub struct PeerAgent {
    /// Our node's ID
    pub local_id: NodeId,
    /// The remote peer's ID
    pub remote_id: NodeId,
    /// When this connection was established
    pub connected_at: u64,

    /// Requests we sent TO this peer, keyed by our request ID
    /// Similar to hashtree-ts: ourRequests = new Map<number, OurRequest>()
    our_requests: HashMap<u32, OurRequest>,

    /// Requests this peer sent TO US that we couldn't fulfill locally
    /// Keyed by hash hex string, similar to hashtree-ts:
    /// theirRequests = new LRUCache<string, TheirRequest>(THEIR_REQUESTS_SIZE)
    their_requests: LruCache<Hash, TheirRequest>,

    /// Next request ID for requests we send
    next_request_id: u32,

    /// Request timeout in ticks (default 5000ms like hashtree-ts)
    pub request_timeout: u64,

    /// Stats
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_sent: u64,
    pub requests_received: u64,
    pub data_sent: u64,
    pub data_received: u64,
}

impl PeerAgent {
    /// Create a new peer agent
    pub fn new(local_id: NodeId, remote_id: NodeId, connected_at: u64) -> Self {
        Self {
            local_id,
            remote_id,
            connected_at,
            our_requests: HashMap::with_capacity(OUR_REQUESTS_SIZE),
            their_requests: LruCache::new(NonZeroUsize::new(THEIR_REQUESTS_SIZE).unwrap()),
            next_request_id: 1,
            request_timeout: 5000,
            bytes_sent: 0,
            bytes_received: 0,
            requests_sent: 0,
            requests_received: 0,
            data_sent: 0,
            data_received: 0,
        }
    }

    /// Create a request to send to this peer
    /// Returns (request_id, request_size_bytes)
    pub fn create_request(&mut self, hash: Hash, query_id: u64, tick: u64) -> (u32, u64) {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.requests_sent += 1;

        self.our_requests.insert(
            request_id,
            OurRequest {
                hash,
                sent_at: tick,
                query_id,
            },
        );

        // Message size: type (1) + id (4) + hash (32) = ~37 bytes, round to 40
        let msg_size = 40u64;
        self.bytes_sent += msg_size;

        (request_id, msg_size)
    }

    /// Record that we received a request from this peer
    /// Returns message size
    pub fn receive_request(&mut self, request_id: u32, hash: Hash, tick: u64) -> u64 {
        self.requests_received += 1;

        // Track this request so we can push data later if we get it
        self.their_requests.put(
            hash,
            TheirRequest {
                id: request_id,
                requested_at: tick,
            },
        );

        // Message size
        let msg_size = 40u64;
        self.bytes_received += msg_size;
        msg_size
    }

    /// Handle a response from this peer
    /// Returns Some((query_id, latency)) if this was a pending request
    pub fn handle_response(
        &mut self,
        request_id: u32,
        found: bool,
        data_size: Option<usize>,
        tick: u64,
    ) -> Option<(u64, u64, Hash)> {
        let our_req = self.our_requests.remove(&request_id)?;
        let latency = tick.saturating_sub(our_req.sent_at);

        // Response message size: type (1) + id (4) + hash (32) + found (1) = ~38
        // Plus data if found
        let msg_size = 40 + data_size.unwrap_or(0) as u64;
        self.bytes_received += msg_size;

        if found {
            self.data_received += data_size.unwrap_or(0) as u64;
        }

        Some((our_req.query_id, latency, our_req.hash))
    }

    /// Send a response to this peer for their request
    /// Returns (their_request_id, message_size) if they had requested this hash
    pub fn send_response(&mut self, hash: &Hash, found: bool, data_size: Option<usize>) -> Option<(u32, u64)> {
        // Check if they requested this hash
        let their_req = self.their_requests.pop(hash)?;

        // Response message size
        let msg_size = 40 + data_size.unwrap_or(0) as u64;
        self.bytes_sent += msg_size;

        if found {
            self.data_sent += data_size.unwrap_or(0) as u64;
        }

        Some((their_req.id, msg_size))
    }

    /// Check if this peer has a pending request for this hash
    pub fn has_their_request(&self, hash: &Hash) -> bool {
        self.their_requests.peek(hash).is_some()
    }

    /// Get our pending request by ID
    pub fn get_our_request(&self, request_id: u32) -> Option<&OurRequest> {
        self.our_requests.get(&request_id)
    }

    /// Check for timed out requests
    /// Returns list of (request_id, query_id, hash) for timed out requests
    pub fn check_timeouts(&mut self, tick: u64) -> Vec<(u32, u64, Hash)> {
        let mut timed_out = Vec::new();

        self.our_requests.retain(|&request_id, req| {
            if tick.saturating_sub(req.sent_at) > self.request_timeout {
                timed_out.push((request_id, req.query_id, req.hash));
                false
            } else {
                true
            }
        });

        timed_out
    }

    /// Get count of pending requests we sent to this peer
    pub fn our_request_count(&self) -> usize {
        self.our_requests.len()
    }

    /// Get count of pending requests from this peer
    pub fn their_request_count(&self) -> usize {
        self.their_requests.len()
    }

    /// Clear all pending requests (on disconnect)
    pub fn clear(&mut self) {
        self.our_requests.clear();
        self.their_requests.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_agent_request_response() {
        let mut agent = PeerAgent::new(1, 2, 0);

        // Create a request
        let hash = [42u8; 32];
        let (request_id, _size) = agent.create_request(hash, 100, 0);
        assert_eq!(request_id, 1);
        assert_eq!(agent.our_request_count(), 1);

        // Handle response
        let result = agent.handle_response(request_id, true, Some(1024), 50);
        assert!(result.is_some());

        let (query_id, latency, resp_hash) = result.unwrap();
        assert_eq!(query_id, 100);
        assert_eq!(latency, 50);
        assert_eq!(resp_hash, hash);
        assert_eq!(agent.our_request_count(), 0);
    }

    #[test]
    fn test_peer_agent_their_request() {
        let mut agent = PeerAgent::new(1, 2, 0);

        let hash = [42u8; 32];

        // They request something
        agent.receive_request(1, hash, 0);
        assert!(agent.has_their_request(&hash));
        assert_eq!(agent.their_request_count(), 1);

        // We respond
        let result = agent.send_response(&hash, true, Some(512));
        assert!(result.is_some());
        assert!(!agent.has_their_request(&hash));
    }

    #[test]
    fn test_peer_agent_timeout() {
        let mut agent = PeerAgent::new(1, 2, 0);
        agent.request_timeout = 100;

        let hash = [42u8; 32];
        let (request_id, _) = agent.create_request(hash, 100, 0);

        // Not timed out yet
        let timed_out = agent.check_timeouts(50);
        assert!(timed_out.is_empty());
        assert_eq!(agent.our_request_count(), 1);

        // Now timed out
        let timed_out = agent.check_timeouts(150);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, request_id);
        assert_eq!(agent.our_request_count(), 0);
    }
}
