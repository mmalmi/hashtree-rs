//! Agent-based peer for simulation
//!
//! Each Agent is an autonomous node that:
//! 1. Receives messages on peer channels
//! 2. Routes requests to handler or responses to pending requests
//! 3. Forwards requests to other peers when data not found locally
//!
//! This matches the hashtree-ts Peer architecture.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::channel::{ChannelError, PeerChannel};
use crate::message::{encode_not_found, encode_request, encode_response, parse, ParsedMessage, RequestId};
use crate::store::SimStore;

/// Pending request we sent to a peer
struct OurRequest {
    response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// Request a peer sent to us that we couldn't fulfill
#[derive(Clone)]
struct TheirRequest {
    id: RequestId,
    from_peer: u64,
}

/// Agent configuration
pub struct AgentConfig {
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum pending requests
    pub max_pending: usize,
    /// Enable multi-hop forwarding
    pub forward_requests: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_pending: 100,
            forward_requests: true,
        }
    }
}

/// An autonomous agent that manages peer connections and data requests
pub struct Agent {
    /// Agent ID
    pub id: u64,
    /// Local storage
    pub store: Arc<SimStore>,
    /// Peer channels (peer_id -> channel)
    peers: RwLock<HashMap<u64, Arc<dyn PeerChannel>>>,
    /// Pending requests we sent (request_id -> response channel)
    our_requests: RwLock<HashMap<RequestId, OurRequest>>,
    /// Requests peers sent us that we couldn't fulfill (hash -> their_request)
    their_requests: RwLock<HashMap<[u8; 32], TheirRequest>>,
    /// Next request ID
    next_request_id: AtomicU32,
    /// Message sender for unified handler
    msg_tx: mpsc::Sender<IncomingMessage>,
    /// Configuration
    config: AgentConfig,
    /// Bytes sent
    bytes_sent: AtomicU64,
    /// Bytes received
    bytes_received: AtomicU64,
    /// Running flag
    running: RwLock<bool>,
}

/// Incoming message with source peer
struct IncomingMessage {
    from_peer: u64,
    data: Vec<u8>,
}

impl Agent {
    /// Create a new agent
    pub fn new(id: u64, config: AgentConfig) -> Arc<Self> {
        let (msg_tx, msg_rx) = mpsc::channel(1000);

        let agent = Arc::new(Self {
            id,
            store: Arc::new(SimStore::new(id)),
            peers: RwLock::new(HashMap::new()),
            our_requests: RwLock::new(HashMap::new()),
            their_requests: RwLock::new(HashMap::new()),
            next_request_id: AtomicU32::new(1),
            msg_tx,
            config,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            running: RwLock::new(true),
        });

        // Start message handler
        let agent_clone = agent.clone();
        tokio::spawn(async move {
            agent_clone.message_loop(msg_rx).await;
        });

        agent
    }

    /// Add a peer connection
    pub async fn add_peer(self: &Arc<Self>, peer_id: u64, channel: Arc<dyn PeerChannel>) {
        self.peers.write().await.insert(peer_id, channel.clone());

        // Spawn receiver for this peer
        let agent = self.clone();
        let msg_tx = self.msg_tx.clone();
        tokio::spawn(async move {
            loop {
                if !*agent.running.read().await {
                    break;
                }

                match channel.recv(Duration::from_secs(60)).await {
                    Ok(data) => {
                        agent.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                        let _ = msg_tx.send(IncomingMessage { from_peer: peer_id, data }).await;
                    }
                    Err(ChannelError::Disconnected) => break,
                    Err(ChannelError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        });
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: u64) {
        self.peers.write().await.remove(&peer_id);
    }

    /// Get connected peer IDs
    pub async fn peer_ids(&self) -> Vec<u64> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Request data by hash (tries local first, then peers)
    pub async fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Try local first
        if let Some(data) = self.store.get_local(hash) {
            return Some(data);
        }

        // Try peers
        self.fetch_from_peers(hash, None).await
    }

    /// Fetch from peers (optionally excluding one)
    async fn fetch_from_peers(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return None;
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request_bytes = encode_request(request_id, hash);

        // Send to all peers (flooding)
        let mut sent_to = Vec::new();
        for (&peer_id, channel) in peers.iter() {
            if Some(peer_id) == exclude {
                continue;
            }

            if channel.send(request_bytes.clone()).await.is_ok() {
                self.bytes_sent.fetch_add(request_bytes.len() as u64, Ordering::Relaxed);
                sent_to.push(peer_id);
            }
        }
        drop(peers);

        if sent_to.is_empty() {
            return None;
        }

        // Setup response channel
        let (tx, rx) = oneshot::channel();
        self.our_requests.write().await.insert(request_id, OurRequest { response_tx: tx });

        // Wait for response with timeout
        match tokio::time::timeout(self.config.request_timeout, rx).await {
            Ok(Ok(data)) => {
                // If we got data, cache it locally
                if let Some(ref d) = data {
                    self.store.put_local(*hash, d.clone());
                }
                data
            }
            _ => {
                // Timeout or error - cleanup
                self.our_requests.write().await.remove(&request_id);
                None
            }
        }
    }

    /// Main message processing loop
    async fn message_loop(self: Arc<Self>, mut rx: mpsc::Receiver<IncomingMessage>) {
        while let Some(msg) = rx.recv().await {
            if !*self.running.read().await {
                break;
            }

            // Spawn message handling so it doesn't block the loop
            // This is critical for multi-hop: B can receive A's request,
            // forward to C, and still process C's response
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.handle_message(msg.from_peer, &msg.data).await;
            });
        }
    }

    /// Handle an incoming message
    async fn handle_message(&self, from_peer: u64, data: &[u8]) {
        match parse(data) {
            Ok(ParsedMessage::Request { id, hash }) => {
                self.handle_request(from_peer, id, hash).await;
            }
            Ok(ParsedMessage::Response { id, hash, data }) => {
                self.handle_response(id, hash, data).await;
            }
            Ok(ParsedMessage::NotFound { id, hash: _ }) => {
                // For flooding, we ignore not_found and wait for other responses
                // For sequential, we'd try next peer
                let _ = id;
            }
            Ok(ParsedMessage::Push { hash, data }) => {
                // Peer is pushing data we previously requested
                self.store.put_local(hash, data);
            }
            Err(_) => {}
        }
    }

    /// Handle incoming request
    async fn handle_request(&self, from_peer: u64, id: RequestId, hash: [u8; 32]) {
        // Check local store
        if let Some(data) = self.store.get_local(&hash) {
            // Send response
            let response = encode_response(id, &hash, &data);
            if let Some(channel) = self.peers.read().await.get(&from_peer) {
                if channel.send(response.clone()).await.is_ok() {
                    self.bytes_sent.fetch_add(response.len() as u64, Ordering::Relaxed);
                }
            }
            return;
        }

        // Not found locally - try forwarding to other peers
        if self.config.forward_requests {
            // Track the request for later push
            self.their_requests.write().await.insert(hash, TheirRequest { id, from_peer });

            // Forward to other peers (excluding the requester)
            if let Some(data) = self.fetch_from_peers(&hash, Some(from_peer)).await {
                // Got it! Send response
                self.their_requests.write().await.remove(&hash);
                let response = encode_response(id, &hash, &data);
                if let Some(channel) = self.peers.read().await.get(&from_peer) {
                    if channel.send(response.clone()).await.is_ok() {
                        self.bytes_sent.fetch_add(response.len() as u64, Ordering::Relaxed);
                    }
                }
                return;
            }
        }

        // Not found anywhere - send not_found
        let response = encode_not_found(id, &hash);
        if let Some(channel) = self.peers.read().await.get(&from_peer) {
            if channel.send(response.clone()).await.is_ok() {
                self.bytes_sent.fetch_add(response.len() as u64, Ordering::Relaxed);
            }
        }
    }

    /// Handle incoming response
    async fn handle_response(&self, id: RequestId, hash: [u8; 32], data: Vec<u8>) {
        // Verify hash
        if hashtree::sha256(&data) != hash {
            return;
        }

        // Route to pending request
        if let Some(req) = self.our_requests.write().await.remove(&id) {
            let _ = req.response_tx.send(Some(data));
        }
    }

    /// Stop the agent
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::MockChannel;

    #[tokio::test]
    async fn test_agent_local_hit() {
        let agent = Agent::new(1, AgentConfig::default());

        let data = b"test data".to_vec();
        let hash = hashtree::sha256(&data);
        agent.store.put_local(hash, data.clone());

        let result = agent.get(&hash).await;
        assert_eq!(result, Some(data));
    }

    #[tokio::test]
    async fn test_agent_network_fetch() {
        let agent1 = Agent::new(1, AgentConfig::default());
        let agent2 = Agent::new(2, AgentConfig::default());

        // Agent 2 has the data
        let data = b"network data".to_vec();
        let hash = hashtree::sha256(&data);
        agent2.store.put_local(hash, data.clone());

        // Connect them
        let (chan1, chan2) = MockChannel::pair(1, 2);
        agent1.add_peer(2, Arc::new(chan1)).await;
        agent2.add_peer(1, Arc::new(chan2)).await;

        // Give time for receivers to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Agent 1 fetches
        let result = agent1.get(&hash).await;
        assert_eq!(result, Some(data.clone()));

        // Should be cached locally
        assert!(agent1.store.has_local(&hash));
    }

    #[tokio::test]
    async fn test_agent_multi_hop() {
        // A -- B -- C
        // A requests, C has data
        let agent_a = Agent::new(1, AgentConfig::default());
        let agent_b = Agent::new(2, AgentConfig::default());
        let agent_c = Agent::new(3, AgentConfig::default());

        // C has the data
        let data = b"multi-hop data".to_vec();
        let hash = hashtree::sha256(&data);
        agent_c.store.put_local(hash, data.clone());

        // Connect A-B
        let (chan_ab, chan_ba) = MockChannel::pair(1, 2);
        agent_a.add_peer(2, Arc::new(chan_ab)).await;
        agent_b.add_peer(1, Arc::new(chan_ba)).await;

        // Connect B-C
        let (chan_bc, chan_cb) = MockChannel::pair(2, 3);
        agent_b.add_peer(3, Arc::new(chan_bc)).await;
        agent_c.add_peer(2, Arc::new(chan_cb)).await;

        // Give time for receivers to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A fetches - should go A -> B -> C -> B -> A
        let result = agent_a.get(&hash).await;
        assert_eq!(result, Some(data.clone()));

        // A and B should have cached it
        assert!(agent_a.store.has_local(&hash));
        assert!(agent_b.store.has_local(&hash));
    }
}
