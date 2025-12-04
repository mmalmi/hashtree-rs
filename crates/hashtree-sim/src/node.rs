//! Simulated network node
//!
//! Each SimNode is an actor with:
//! - Local HashTree-backed storage via SimStore
//! - Per-peer connections via PeerAgent (like hashtree-ts Peer)
//! - Configurable behavior strategy

use crate::behavior::Behavior;
use crate::message::Hash;
use crate::peer_agent::PeerAgent;
use crate::store::SimStore;
use hashtree::{HashTree, HashTreeConfig};
use lru::LruCache;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

pub type NodeId = u64;

/// State for a query this node originated
#[derive(Debug)]
pub struct ActiveQuery {
    pub hash: Hash,
    /// Peers we sent the query to (awaiting response)
    pub pending_peers: HashSet<NodeId>,
    /// Peers that responded "not found"
    pub not_found_peers: HashSet<NodeId>,
    /// When we started this query
    pub started_at: u64,
    /// Have we received a successful response?
    pub resolved: bool,
}

/// State for a forwarded query (request from another peer that we're handling)
#[derive(Debug, Clone)]
pub struct ForwardedQuery {
    /// Who sent us this request
    pub from_peer: NodeId,
    /// Their request ID
    pub their_request_id: u32,
    /// Peers we forwarded to
    pub forwarded_to: HashSet<NodeId>,
    /// When we received it
    pub received_at: u64,
}

/// Simulated node in the network
///
/// Each node acts as an agent with per-peer connections,
/// similar to how hashtree-ts manages Peer objects.
pub struct SimNode {
    pub id: NodeId,

    /// Local content store (implements hashtree::Store trait)
    store: Arc<SimStore>,

    /// Connected peers with per-peer state (like hashtree-ts Peer connections)
    peers: HashMap<NodeId, PeerAgent>,

    /// Active queries we originated (keyed by query_id)
    active_queries: HashMap<u64, ActiveQuery>,

    /// Forwarded queries - requests from peers we're trying to fulfill
    /// Keyed by hash, since multiple peers might request same hash
    forwarded_queries: LruCache<Hash, Vec<ForwardedQuery>>,

    /// Node behavior strategy
    behavior: Behavior,

    /// Next query ID (for queries we originate)
    next_query_id: u64,

    /// Stats
    pub requests_made: u64,
    pub requests_received: u64,
    pub data_served: u64,
}

impl SimNode {
    pub fn new(id: NodeId, cache_size: usize) -> Self {
        Self {
            id,
            store: Arc::new(SimStore::new(id)),
            peers: HashMap::new(),
            active_queries: HashMap::new(),
            forwarded_queries: LruCache::new(NonZeroUsize::new(cache_size).unwrap()),
            behavior: Behavior::default(),
            next_query_id: 1,
            requests_made: 0,
            requests_received: 0,
            data_served: 0,
        }
    }

    pub fn with_behavior(mut self, behavior: Behavior) -> Self {
        self.behavior = behavior;
        self
    }

    /// Get the node's local store (for HashTree integration)
    pub fn local_store(&self) -> Arc<SimStore> {
        self.store.clone()
    }

    /// Create a HashTree using this node's local store
    pub fn hashtree(&self) -> HashTree<SimStore> {
        HashTree::new(HashTreeConfig::new(self.store.clone()).public())
    }

    /// Create a HashTree with custom configuration
    pub fn hashtree_with_config(&self, chunk_size: usize) -> HashTree<SimStore> {
        HashTree::new(
            HashTreeConfig::new(self.store.clone())
                .public()
                .with_chunk_size(chunk_size),
        )
    }

    /// Add content to local store
    pub fn store(&mut self, hash: Hash, data: Vec<u8>) {
        self.store.put_local(hash, data);
    }

    /// Check if we have content locally
    pub fn has(&self, hash: &Hash) -> bool {
        self.store.has_local(hash)
    }

    /// Get content from local store
    pub fn get(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.store.get_local(hash)
    }

    /// Connect to a peer
    pub fn connect(&mut self, peer_id: NodeId, tick: u64) {
        if !self.peers.contains_key(&peer_id) {
            self.peers
                .insert(peer_id, PeerAgent::new(self.id, peer_id, tick));
        }
    }

    /// Disconnect from a peer
    pub fn disconnect(&mut self, peer_id: NodeId) {
        if let Some(mut peer) = self.peers.remove(&peer_id) {
            peer.clear();
        }
    }

    /// Get connected peer IDs
    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.peers.keys().copied().collect()
    }

    /// Get peer agent by ID
    pub fn peer(&self, peer_id: NodeId) -> Option<&PeerAgent> {
        self.peers.get(&peer_id)
    }

    /// Get mutable peer agent by ID
    pub fn peer_mut(&mut self, peer_id: NodeId) -> Option<&mut PeerAgent> {
        self.peers.get_mut(&peer_id)
    }

    /// Initiate a new query for content
    /// Returns (query_id, list of (peer_id, request_id, msg_size))
    pub fn initiate_query(
        &mut self,
        hash: Hash,
        tick: u64,
    ) -> (u64, Vec<(NodeId, u32, u64)>) {
        let query_id = self.next_query_id;
        self.next_query_id += 1;
        self.requests_made += 1;

        let mut requests = Vec::new();
        let mut pending_peers = HashSet::new();

        // Send request to all connected peers
        for (&peer_id, peer) in self.peers.iter_mut() {
            let (request_id, msg_size) = peer.create_request(hash, query_id, tick);
            requests.push((peer_id, request_id, msg_size));
            pending_peers.insert(peer_id);
        }

        self.active_queries.insert(
            query_id,
            ActiveQuery {
                hash,
                pending_peers,
                not_found_peers: HashSet::new(),
                started_at: tick,
                resolved: false,
            },
        );

        (query_id, requests)
    }

    /// Handle incoming request from a peer
    /// Returns:
    /// - Some((data, msg_size)) if we have it locally
    /// - None if we need to forward to other peers
    pub fn handle_request<R: rand::Rng>(
        &mut self,
        from_peer: NodeId,
        request_id: u32,
        hash: Hash,
        tick: u64,
        rng: &mut R,
    ) -> Option<(Vec<u8>, u64)> {
        self.requests_received += 1;

        // Record that we received a request from this peer
        if let Some(peer) = self.peers.get_mut(&from_peer) {
            peer.receive_request(request_id, hash, tick);
        }

        // Check local store
        if let Some(data) = self.store.get_local(&hash) {
            self.data_served += 1;

            // Check behavior - should we lie?
            let response_data = if self.behavior.should_lie(rng) {
                let mut fake = vec![0u8; data.len()];
                rng.fill_bytes(&mut fake);
                fake
            } else {
                data
            };

            // Send response back via peer agent
            if let Some(peer) = self.peers.get_mut(&from_peer) {
                let (_, msg_size) = peer.send_response(&hash, true, Some(response_data.len()))?;
                return Some((response_data, msg_size));
            }
        }

        // Not found locally - track for forwarding
        let fq = ForwardedQuery {
            from_peer,
            their_request_id: request_id,
            forwarded_to: HashSet::new(),
            received_at: tick,
        };

        if let Some(existing) = self.forwarded_queries.get_mut(&hash) {
            existing.push(fq);
        } else {
            self.forwarded_queries.put(hash, vec![fq]);
        }

        None
    }

    /// Forward a request to other peers (excluding the one who sent it)
    /// Returns list of (peer_id, request_id, msg_size)
    pub fn forward_request(
        &mut self,
        hash: Hash,
        exclude_peer: NodeId,
        query_id: u64,
        tick: u64,
    ) -> Vec<(NodeId, u32, u64)> {
        let mut requests = Vec::new();

        // Update forwarded_to set
        if let Some(fqs) = self.forwarded_queries.get_mut(&hash) {
            for fq in fqs.iter_mut() {
                if fq.from_peer == exclude_peer {
                    for (&peer_id, peer) in self.peers.iter_mut() {
                        if peer_id != exclude_peer {
                            let (request_id, msg_size) = peer.create_request(hash, query_id, tick);
                            requests.push((peer_id, request_id, msg_size));
                            fq.forwarded_to.insert(peer_id);
                        }
                    }
                }
            }
        }

        requests
    }

    /// Handle response from a peer
    /// Returns Some((query_id, latency, found, data_opt)) if this resolves a query
    pub fn handle_response(
        &mut self,
        from_peer: NodeId,
        request_id: u32,
        found: bool,
        data: Option<Vec<u8>>,
        tick: u64,
    ) -> Option<(u64, u64, bool, Option<Vec<u8>>)> {
        let peer = self.peers.get_mut(&from_peer)?;
        let data_size = data.as_ref().map(|d| d.len());
        let (query_id, latency, hash) = peer.handle_response(request_id, found, data_size, tick)?;

        // Update our active query
        if let Some(query) = self.active_queries.get_mut(&query_id) {
            query.pending_peers.remove(&from_peer);

            if found {
                query.resolved = true;

                // Cache locally if behavior allows
                if let Some(ref d) = data {
                    if self.behavior.should_cache(&hash, d) {
                        self.store.put_local(hash, d.clone());
                    }
                }

                return Some((query_id, latency, true, data));
            } else {
                query.not_found_peers.insert(from_peer);

                // Check if all peers have responded "not found"
                if query.pending_peers.is_empty() {
                    return Some((query_id, latency, false, None));
                }
            }
        }

        None
    }

    /// Get pending peers for a forwarded hash (peers that haven't responded yet)
    pub fn get_forwarded_pending(&self, hash: &Hash) -> Vec<NodeId> {
        if let Some(fqs) = self.forwarded_queries.peek(hash) {
            fqs.iter()
                .flat_map(|fq| fq.forwarded_to.iter().copied())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get peers waiting for data (for push after we receive it)
    pub fn get_waiting_peers(&mut self, hash: &Hash) -> Vec<(NodeId, u32)> {
        if let Some(fqs) = self.forwarded_queries.pop(hash) {
            fqs.into_iter()
                .map(|fq| (fq.from_peer, fq.their_request_id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Check for timed out requests across all peers
    pub fn check_timeouts(&mut self, tick: u64) -> Vec<(NodeId, u32, u64, Hash)> {
        let mut timed_out = Vec::new();

        for (&peer_id, peer) in self.peers.iter_mut() {
            for (request_id, query_id, hash) in peer.check_timeouts(tick) {
                timed_out.push((peer_id, request_id, query_id, hash));
            }
        }

        timed_out
    }

    /// Get an active query
    pub fn get_query(&self, query_id: u64) -> Option<&ActiveQuery> {
        self.active_queries.get(&query_id)
    }

    /// Remove a completed query
    pub fn remove_query(&mut self, query_id: u64) -> Option<ActiveQuery> {
        self.active_queries.remove(&query_id)
    }

    /// Get number of items in local store
    pub fn store_size(&self) -> usize {
        self.store.size()
    }

    /// Get total bytes sent across all peers
    pub fn total_bytes_sent(&self) -> u64 {
        self.peers.values().map(|p| p.bytes_sent).sum()
    }

    /// Get total bytes received across all peers
    pub fn total_bytes_received(&self) -> u64 {
        self.peers.values().map(|p| p.bytes_received).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashtree::sha256;

    #[test]
    fn test_node_store_operations() {
        let mut node = SimNode::new(1, 100);

        let data = b"test content";
        let hash = sha256(data);

        node.store(hash, data.to_vec());
        assert!(node.has(&hash));
        assert_eq!(node.get(&hash), Some(data.to_vec()));
        assert_eq!(node.store_size(), 1);
    }

    #[test]
    fn test_node_local_store_access() {
        let node = SimNode::new(42, 100);
        let store = node.local_store();

        let data = b"via store";
        let hash = sha256(data);

        store.put_local(hash, data.to_vec());
        assert!(store.has_local(&hash));
        assert_eq!(store.get_local(&hash), Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_node_hashtree_integration() {
        let node = SimNode::new(1, 100);
        let tree = node.hashtree();

        let data = b"Content stored via HashTree API";
        let cid = tree.put(data).await.unwrap();

        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        assert!(node.has(&cid.hash));
        assert_eq!(node.get(&cid.hash), Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_node_hashtree_chunked() {
        let node = SimNode::new(2, 100);
        let tree = node.hashtree_with_config(64);

        let data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let cid = tree.put(&data).await.unwrap();

        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        assert!(node.store_size() > 1);
    }

    #[test]
    fn test_node_peer_connections() {
        let mut node = SimNode::new(1, 100);

        // Connect to peers
        node.connect(2, 0);
        node.connect(3, 0);
        assert_eq!(node.peer_ids().len(), 2);

        // Check peer exists
        assert!(node.peer(2).is_some());
        assert!(node.peer(3).is_some());
        assert!(node.peer(4).is_none());

        // Disconnect
        node.disconnect(2);
        assert!(node.peer(2).is_none());
        assert_eq!(node.peer_ids().len(), 1);
    }

    #[test]
    fn test_node_initiate_query() {
        let mut node = SimNode::new(1, 100);
        node.connect(2, 0);
        node.connect(3, 0);

        let hash = [42u8; 32];
        let (query_id, requests) = node.initiate_query(hash, 0);

        assert_eq!(query_id, 1);
        assert_eq!(requests.len(), 2); // Sent to both peers

        let query = node.get_query(query_id).unwrap();
        assert_eq!(query.pending_peers.len(), 2);
        assert!(!query.resolved);
    }
}
