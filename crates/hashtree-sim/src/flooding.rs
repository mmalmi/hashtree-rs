//! Flooding P2P Store with signaling
//!
//! A complete P2P node that:
//! 1. Connects to relay and announces presence
//! 2. Discovers peers and establishes connections via signaling
//! 3. Floods requests to all peers, returns first response
//! 4. Forwards requests it can't fulfill (multi-hop)
//!
//! This is the simulation equivalent of WebRTCStore.

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

use crate::channel::{ChannelError, MockChannel, PeerChannel};
use crate::message::{encode_request, encode_response, parse, ParsedMessage, RequestId};
use crate::relay::{
    Event, Filter, MockRelay, RelayClient, RelayMessage, KIND_ANSWER, KIND_OFFER, KIND_PRESENCE,
};
use crate::store::{NetworkStore, SimStore};

/// Signaling content types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum SignalingContent {
    Presence { node_id: String },
    Offer { sdp: String },
    Answer { sdp: String },
}

/// Pending request we sent to peers
struct OurRequest {
    response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// Request a peer sent to us that we're forwarding
#[derive(Clone)]
struct TheirRequest {
    _id: RequestId,
    _from_peer: u64,
}

/// Pending outbound connection (we sent offer, waiting for answer)
struct PendingConnection {
    our_channel: Arc<MockChannel>,
}

/// Routing strategy for data requests
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Flood requests to all peers simultaneously, first response wins
    /// + Multi-hop forwarding: peers forward to their peers
    /// + Lower latency, higher bandwidth usage
    Flooding,
    /// Try peers one at a time, wait for response before trying next
    /// + Single-hop only: peers only check local storage (no forwarding)
    /// + Lower bandwidth, but only reaches direct neighbors
    /// Note: Multi-hop sequential would require NOT_FOUND responses to avoid
    /// cascading timeouts at each hop.
    Sequential,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::Flooding
    }
}

/// Configuration for FloodingStore
#[derive(Clone)]
pub struct FloodingConfig {
    /// Per-peer timeout for sequential strategy (try next peer if no response)
    pub request_timeout: Duration,
    /// Enable multi-hop forwarding
    pub forward_requests: bool,
    /// Max peers to connect to
    pub max_peers: usize,
    /// Connection timeout (ms)
    pub connect_timeout_ms: u64,
    /// Simulated network latency per hop (ms)
    /// Set to 0 for instant delivery (unit tests), ~50ms for realistic WebRTC
    pub network_latency_ms: u64,
    /// Routing strategy for data requests
    pub routing_strategy: RoutingStrategy,
}

impl Default for FloodingConfig {
    fn default() -> Self {
        Self {
            // Per-peer timeout: 1s allows multi-hop forwarding with 50ms latency
            // Sequential tries each peer for 1s before moving to next
            // Flooding uses this as overall timeout (parallel requests)
            request_timeout: Duration::from_secs(1),
            forward_requests: true,
            max_peers: 5,
            connect_timeout_ms: 5000,
            network_latency_ms: 0, // Instant for tests, set to ~50 for realistic simulation
            routing_strategy: RoutingStrategy::Flooding,
        }
    }
}

/// Incoming data message with source peer
struct IncomingMessage {
    from_peer: u64,
    data: Vec<u8>,
}

/// Flooding store - complete P2P node with signaling
///
/// Like WebRTCStore, this is a complete P2P node that handles:
/// - Signaling (relay connection, presence, offers/answers)
/// - Peer management (connection establishment, channel handling)
/// - Data transfer (flooding requests, multi-hop forwarding)
pub struct FloodingStore {
    /// Node ID (string for signaling)
    id: String,
    /// Node ID (numeric for data transfer)
    node_id: u64,
    /// Local storage
    local: Arc<SimStore>,
    /// Connected peer channels (peer_id -> channel)
    peers: RwLock<HashMap<u64, Arc<dyn PeerChannel>>>,
    /// Pending requests we sent (request_id -> response channel)
    our_requests: RwLock<HashMap<RequestId, OurRequest>>,
    /// Requests peers sent us that we're forwarding (hash -> their_request)
    their_requests: RwLock<HashMap<[u8; 32], TheirRequest>>,
    /// Pending outbound connections (we sent offer)
    pending_outbound: RwLock<HashMap<String, PendingConnection>>,
    /// Next request ID
    next_request_id: AtomicU32,
    /// Message sender for unified handler
    msg_tx: mpsc::Sender<IncomingMessage>,
    /// Configuration
    config: FloodingConfig,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
}

// Global channel registry for signaling
// Maps channel_id -> channel half waiting to be claimed
lazy_static::lazy_static! {
    static ref CHANNEL_REGISTRY: RwLock<HashMap<String, Arc<MockChannel>>> = RwLock::new(HashMap::new());
}

impl FloodingStore {
    /// Create a new flooding store
    pub fn new(id: impl Into<String>, config: FloodingConfig) -> Arc<Self> {
        let id = id.into();
        let node_id = id.parse().unwrap_or(0);
        let local = Arc::new(SimStore::new(node_id));
        let (msg_tx, msg_rx) = mpsc::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        let store = Arc::new(Self {
            id,
            node_id,
            local,
            peers: RwLock::new(HashMap::new()),
            our_requests: RwLock::new(HashMap::new()),
            their_requests: RwLock::new(HashMap::new()),
            pending_outbound: RwLock::new(HashMap::new()),
            next_request_id: AtomicU32::new(1),
            msg_tx,
            config,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            shutdown_tx,
        });

        // Start message handler loop
        let store_clone = store.clone();
        let shutdown_rx = store.shutdown_tx.subscribe();
        tokio::spawn(async move {
            store_clone.message_loop(msg_rx, shutdown_rx).await;
        });

        store
    }

    /// Create with default config
    pub fn with_defaults(id: impl Into<String>) -> Arc<Self> {
        Self::new(id, FloodingConfig::default())
    }

    /// Get string ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get numeric node ID
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Get local store reference
    pub fn local(&self) -> &Arc<SimStore> {
        &self.local
    }

    // ==================== Signaling ====================

    /// Connect to relay and announce presence
    pub async fn start(self: &Arc<Self>, relay: &Arc<MockRelay>) -> RelayClient {
        let mut client = relay.connect(self.id.clone()).await;

        // Announce presence
        let presence = Event::new(
            self.id.clone(),
            KIND_PRESENCE,
            serde_json::to_string(&SignalingContent::Presence {
                node_id: self.id.clone(),
            })
            .unwrap(),
        );
        let _ = client.publish(presence).await;

        // Consume the OK response
        while let Some(msg) = client.recv().await {
            if matches!(msg, RelayMessage::Ok { .. }) {
                break;
            }
        }

        // Subscribe to offers and answers directed at us
        let offer_filter = Filter::new()
            .kinds(vec![KIND_OFFER])
            .p_tags(vec![self.id.clone()]);
        let _ = client.subscribe("offers", vec![offer_filter]).await;

        let answer_filter = Filter::new()
            .kinds(vec![KIND_ANSWER])
            .p_tags(vec![self.id.clone()]);
        let _ = client.subscribe("answers", vec![answer_filter]).await;

        client
    }

    /// Discover peers by querying presence events
    pub async fn discover_peers(&self, client: &RelayClient) -> Result<(), crate::relay::RelayError> {
        let filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        client.subscribe("discovery", vec![filter]).await
    }

    /// Send data to a channel with simulated network latency
    async fn send_with_latency(
        &self,
        channel: &dyn PeerChannel,
        data: Vec<u8>,
    ) -> Result<(), crate::channel::ChannelError> {
        // Simulate network latency (one-way delay)
        if self.config.network_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.config.network_latency_ms)).await;
        }
        channel.send(data).await
    }

    /// Send offer to a peer
    pub async fn send_offer(
        self: &Arc<Self>,
        client: &RelayClient,
        target: &str,
    ) -> Result<(), crate::relay::RelayError> {
        // Check if already connected or pending
        let target_id: u64 = target.parse().unwrap_or(0);
        if self.peers.read().await.contains_key(&target_id) {
            return Ok(());
        }
        if self.pending_outbound.read().await.contains_key(target) {
            return Ok(());
        }
        if self.peers.read().await.len() >= self.config.max_peers {
            return Ok(());
        }

        // Create channel pair
        let (our_chan, their_chan) = MockChannel::pair(self.node_id, target_id);
        let channel_id = format!("{}_{}", self.id, target);

        // Store pending connection
        self.pending_outbound.write().await.insert(
            target.to_string(),
            PendingConnection {
                our_channel: Arc::new(our_chan),
            },
        );

        // Store their channel half in registry for answerer
        CHANNEL_REGISTRY
            .write()
            .await
            .insert(channel_id.clone(), Arc::new(their_chan));

        let offer_content = SignalingContent::Offer { sdp: channel_id };
        let offer = Event::new(
            self.id.clone(),
            KIND_OFFER,
            serde_json::to_string(&offer_content).unwrap(),
        )
        .with_p_tag(target);

        client.publish(offer).await
    }

    /// Handle incoming offer
    async fn handle_offer(
        self: &Arc<Self>,
        client: &RelayClient,
        event: &Event,
    ) -> Result<(), crate::relay::RelayError> {
        let from = &event.pubkey;
        let from_id: u64 = from.parse().unwrap_or(0);

        // Check if already connected
        if self.peers.read().await.contains_key(&from_id) {
            return Ok(());
        }
        if self.peers.read().await.len() >= self.config.max_peers {
            return Ok(());
        }

        // Parse offer content to get channel ID
        let content: SignalingContent = match serde_json::from_str(&event.content) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let channel_id = match content {
            SignalingContent::Offer { sdp } => sdp,
            _ => return Ok(()),
        };

        // Get our channel half from the registry
        let their_channel = CHANNEL_REGISTRY.write().await.remove(&channel_id);
        let channel: Arc<dyn PeerChannel> = match their_channel {
            Some(c) => c,
            None => return Ok(()), // Channel not found, maybe stale offer
        };

        // Add peer and start receiver
        self.add_peer(from_id, channel).await;

        // Send answer
        let answer_content = SignalingContent::Answer { sdp: channel_id };
        let answer = Event::new(
            self.id.clone(),
            KIND_ANSWER,
            serde_json::to_string(&answer_content).unwrap(),
        )
        .with_p_tag(from);

        client.publish(answer).await
    }

    /// Handle incoming answer
    async fn handle_answer(self: &Arc<Self>, event: &Event) {
        let from = &event.pubkey;
        let from_id: u64 = from.parse().unwrap_or(0);

        // Get pending connection
        let pending = self.pending_outbound.write().await.remove(from);
        let pending = match pending {
            Some(p) => p,
            None => return, // No pending connection
        };

        // Check if already connected (race condition)
        if self.peers.read().await.contains_key(&from_id) {
            return;
        }

        // Add peer and start receiver
        let channel: Arc<dyn PeerChannel> = pending.our_channel;
        self.add_peer(from_id, channel).await;
    }

    /// Process relay message - call this in a loop
    pub async fn process_message(
        self: &Arc<Self>,
        client: &RelayClient,
        msg: RelayMessage,
    ) -> Option<String> {
        match msg {
            RelayMessage::Event { sub_id, event } => match sub_id.as_str() {
                "offers" => {
                    let _ = self.handle_offer(client, &event).await;
                }
                "answers" => {
                    self.clone().handle_answer(&event).await;
                }
                "discovery" => {
                    // Found a peer's presence
                    if event.pubkey != self.id {
                        return Some(event.pubkey);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        None
    }

    // ==================== Peer Management ====================

    /// Add a peer channel and start receiving from it
    pub async fn add_peer(self: &Arc<Self>, peer_id: u64, channel: Arc<dyn PeerChannel>) {
        self.peers.write().await.insert(peer_id, channel.clone());

        // Spawn receiver for this peer
        let store = self.clone();
        let msg_tx = self.msg_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    result = channel.recv(Duration::from_secs(60)) => {
                        match result {
                            Ok(data) => {
                                store.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                                let _ = msg_tx.send(IncomingMessage { from_peer: peer_id, data }).await;
                            }
                            Err(ChannelError::Disconnected) => break,
                            Err(ChannelError::Timeout) => continue,
                            Err(_) => break,
                        }
                    }
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

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    // ==================== Data Transfer ====================

    /// Fetch from peers (optionally excluding one)
    async fn fetch_from_peers(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
        match self.config.routing_strategy {
            RoutingStrategy::Flooding => self.fetch_from_peers_flooding(hash, exclude).await,
            RoutingStrategy::Sequential => self.fetch_from_peers_sequential(hash, exclude).await,
        }
    }

    /// Flooding strategy: send to all peers at once, first response wins
    async fn fetch_from_peers_flooding(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
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

            if self.send_with_latency(channel.as_ref(), request_bytes.clone()).await.is_ok() {
                self.bytes_sent
                    .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);
                sent_to.push(peer_id);
            }
        }
        drop(peers);

        if sent_to.is_empty() {
            return None;
        }

        // Setup response channel
        let (tx, rx) = oneshot::channel();
        self.our_requests
            .write()
            .await
            .insert(request_id, OurRequest { response_tx: tx });

        // Wait for response with timeout
        match tokio::time::timeout(self.config.request_timeout, rx).await {
            Ok(Ok(data)) => {
                // If we got data, cache it locally
                if let Some(ref d) = data {
                    self.local.put_local(*hash, d.clone());
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

    /// Sequential strategy: try one peer at a time, wait for response before trying next
    async fn fetch_from_peers_sequential(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
        let peer_list: Vec<(u64, Arc<dyn PeerChannel>)> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .filter(|(&id, _)| Some(id) != exclude)
                .map(|(&id, ch)| (id, ch.clone()))
                .collect()
        };

        if peer_list.is_empty() {
            return None;
        }

        // Try each peer sequentially
        for (_peer_id, channel) in peer_list {
            let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            let request_bytes = encode_request(request_id, hash);

            // Send request
            if self.send_with_latency(channel.as_ref(), request_bytes.clone()).await.is_err() {
                continue; // Try next peer
            }
            self.bytes_sent
                .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);

            // Setup response channel
            let (tx, rx) = oneshot::channel();
            self.our_requests
                .write()
                .await
                .insert(request_id, OurRequest { response_tx: tx });

            // Wait for response - use full timeout since peer may be forwarding sequentially
            // Sequential forwarding: peer tries its peers one at a time, responds when found
            match tokio::time::timeout(self.config.request_timeout, rx).await {
                Ok(Ok(Some(data))) => {
                    // Found it! Cache locally and return
                    self.local.put_local(*hash, data.clone());
                    return Some(data);
                }
                Ok(Ok(None)) => {
                    // Peer responded with not found, try next
                    continue;
                }
                _ => {
                    // Timeout or error - cleanup and try next peer
                    self.our_requests.write().await.remove(&request_id);
                    continue;
                }
            }
        }

        None
    }

    /// Main message processing loop
    async fn message_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<IncomingMessage>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(msg) => {
                            // Spawn message handling so it doesn't block the loop
                            let self_clone = self.clone();
                            tokio::spawn(async move {
                                self_clone.handle_data_message(msg.from_peer, &msg.data).await;
                            });
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// Handle an incoming data message
    async fn handle_data_message(&self, from_peer: u64, data: &[u8]) {
        match parse(data) {
            Ok(ParsedMessage::Request { id, hash }) => {
                self.handle_request(from_peer, id, hash).await;
            }
            Ok(ParsedMessage::Response { id, hash, data }) => {
                self.handle_response(id, hash, data).await;
            }
            Ok(ParsedMessage::Push { hash, data }) => {
                // Peer is pushing data
                self.local.put_local(hash, data);
            }
            Err(_) => {}
        }
    }

    /// Handle incoming request from a peer
    async fn handle_request(&self, from_peer: u64, id: RequestId, hash: [u8; 32]) {
        // Check local store first
        if let Some(data) = self.local.get_local(&hash) {
            let response = encode_response(id, &hash, &data);
            if let Some(channel) = self.peers.read().await.get(&from_peer) {
                if self.send_with_latency(channel.as_ref(), response.clone()).await.is_ok() {
                    self.bytes_sent
                        .fetch_add(response.len() as u64, Ordering::Relaxed);
                }
            }
            return;
        }

        // Not found locally - try forwarding to other peers
        // Both flooding and sequential forward, but with different strategies:
        // - Flooding: send to all peers at once, first response wins
        // - Sequential: try one peer at a time until found
        if self.config.forward_requests {
            // Check if we're already looking for this hash (prevents cycles)
            {
                let their_requests = self.their_requests.read().await;
                if their_requests.contains_key(&hash) {
                    return;
                }
            }

            // Track the request for cycle detection
            self.their_requests.write().await.insert(
                hash,
                TheirRequest {
                    _id: id,
                    _from_peer: from_peer,
                },
            );

            // Forward to other peers (excluding the requester)
            if let Some(data) = self.fetch_from_peers(&hash, Some(from_peer)).await {
                self.their_requests.write().await.remove(&hash);
                let response = encode_response(id, &hash, &data);
                if let Some(channel) = self.peers.read().await.get(&from_peer) {
                    if self.send_with_latency(channel.as_ref(), response.clone()).await.is_ok() {
                        self.bytes_sent
                            .fetch_add(response.len() as u64, Ordering::Relaxed);
                    }
                }
                return;
            }

            self.their_requests.write().await.remove(&hash);
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

    /// Stop the store
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[async_trait]
impl Store for FloodingStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        self.local.put(hash, data).await
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local.get(hash).await? {
            return Ok(Some(data));
        }

        // Fetch from network
        Ok(self.fetch_from_peers(hash, None).await)
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.has(hash).await
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.delete(hash).await
    }
}

#[async_trait]
impl NetworkStore for FloodingStore {
    async fn fetch_from_network(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.fetch_from_peers(hash, None).await)
    }

    fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Simple handler for responding to flooding requests (for nodes without multi-hop)
/// Deprecated: Use FloodingStore directly which handles requests internally
pub async fn handle_request(local: &SimStore, request_bytes: &[u8]) -> Option<Vec<u8>> {
    match parse(request_bytes) {
        Ok(ParsedMessage::Request { id, hash }) => {
            if let Some(data) = local.get_local(&hash) {
                Some(encode_response(id, &hash, &data))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flooding_local_hit() {
        let store = FloodingStore::with_defaults("1");
        let data = b"test data";
        let hash = hashtree::sha256(data);
        store.local().put_local(hash, data.to_vec());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_flooding_network_fetch() {
        let store1 = FloodingStore::with_defaults("1");
        let store2 = FloodingStore::with_defaults("2");

        let data = b"network data";
        let hash = hashtree::sha256(data);
        store2.local().put_local(hash, data.to_vec());

        // Connect them directly (without signaling)
        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(2, Arc::new(chan1)).await;
        store2.add_peer(1, Arc::new(chan2)).await;

        // Fetch from node 1
        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        // Should be cached locally now
        assert!(store1.local().has_local(&hash));
    }

    #[tokio::test]
    async fn test_flooding_multi_hop() {
        // A -- B -- C
        let store_a = FloodingStore::with_defaults("1");
        let store_b = FloodingStore::with_defaults("2");
        let store_c = FloodingStore::with_defaults("3");

        // C has the data
        let data = b"multi-hop data";
        let hash = hashtree::sha256(data);
        store_c.local().put_local(hash, data.to_vec());

        // Connect A-B
        let (chan_ab, chan_ba) = MockChannel::pair(1, 2);
        store_a.add_peer(2, Arc::new(chan_ab)).await;
        store_b.add_peer(1, Arc::new(chan_ba)).await;

        // Connect B-C
        let (chan_bc, chan_cb) = MockChannel::pair(2, 3);
        store_b.add_peer(3, Arc::new(chan_bc)).await;
        store_c.add_peer(2, Arc::new(chan_cb)).await;

        // Give time for receivers to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A fetches - should go A -> B -> C -> B -> A
        let result = store_a.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        // A and B should have cached it
        assert!(store_a.local().has_local(&hash));
        assert!(store_b.local().has_local(&hash));
    }

    #[tokio::test]
    async fn test_flooding_no_peers() {
        let store = FloodingStore::with_defaults("1");
        let hash = [42u8; 32];
        let result = store.get(&hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_signaling_connection() {
        let relay = MockRelay::new();

        let store1 = FloodingStore::with_defaults("1");
        let mut client1 = store1.start(&relay).await;

        let store2 = FloodingStore::with_defaults("2");
        let mut client2 = store2.start(&relay).await;

        // Send offer from 1 to 2
        store1.send_offer(&client1, "2").await.unwrap();

        // Process messages until connected
        while store2.peer_count().await == 0 {
            if let Some(msg) = client2.recv().await {
                store2.process_message(&client2, msg).await;
            }
        }

        while store1.peer_count().await == 0 {
            if let Some(msg) = client1.recv().await {
                store1.process_message(&client1, msg).await;
            }
        }

        assert_eq!(store1.peer_count().await, 1);
        assert_eq!(store2.peer_count().await, 1);
    }

    #[tokio::test]
    async fn test_signaling_data_transfer() {
        let relay = MockRelay::new();

        let store1 = FloodingStore::with_defaults("1");
        let mut client1 = store1.start(&relay).await;

        let store2 = FloodingStore::with_defaults("2");
        let mut client2 = store2.start(&relay).await;

        // Store2 has data
        let data = b"signaling test data";
        let hash = hashtree::sha256(data);
        store2.local().put_local(hash, data.to_vec());

        // Connect via signaling
        store1.send_offer(&client1, "2").await.unwrap();

        while store2.peer_count().await == 0 {
            if let Some(msg) = client2.recv().await {
                store2.process_message(&client2, msg).await;
            }
        }

        while store1.peer_count().await == 0 {
            if let Some(msg) = client1.recv().await {
                store1.process_message(&client1, msg).await;
            }
        }

        // Fetch data
        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
        assert!(store1.local().has_local(&hash));
    }
}
