//! Flooding P2P Store with signaling
//!
//! A complete P2P node that:
//! 1. Connects to relay and announces presence
//! 2. Discovers peers and establishes connections via signaling
//! 3. Floods requests to all peers, returns first response
//! 4. Forwards requests using HTL (Hops-To-Live) like Freenet
//!
//! This is the simulation equivalent of WebRTCStore.

use async_trait::async_trait;
use hashtree_core::{Hash, Store, StoreError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

use crate::channel::{ChannelError, MockChannel, PeerChannel};
use crate::message::{
    decrement_htl, encode_request, encode_response, parse, should_forward,
    ParsedMessage, PeerHTLConfig, MAX_HTL,
};
use crate::peer_selector::{PeerSelector, SelectionStrategy};
use crate::relay::{
    Event, Filter, MockRelay, RelayClient, RelayMessage, KIND_ANSWER, KIND_OFFER, KIND_PRESENCE,
};
use crate::store::{NetworkStore, SimStore};

// Use the same types as real WebRTC
pub use hashtree_webrtc::SignalingMessage;
pub use hashtree_webrtc::{PoolConfig, PoolSettings};

/// Pending request we originated (waiting for response)
struct OurRequest {
    response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// Track forwarded requests to route responses back
/// Key: hash, Value: list of peers waiting for response
struct ForwardedRequest {
    /// All peers who requested this hash (to send response to all)
    from_peers: Vec<u64>,
    /// When this request was first received (for TTL expiration)
    created_at: std::time::Instant,
    #[allow(dead_code)]
    received_htl: u8,
}

/// Max time to keep a forwarded request entry before expiring (prevents unbounded growth)
const FORWARDED_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Pending outbound connection (we sent offer, waiting for answer)
struct PendingConnection {
    our_channel: Arc<MockChannel>,
}

/// Connected peer with its HTL config and link characteristics
struct ConnectedPeer {
    channel: Arc<dyn PeerChannel>,
    htl_config: PeerHTLConfig,
    /// Per-link latency in ms (varies per connection)
    link_latency_ms: u64,
}

/// Routing strategy for data requests
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Flood requests to all peers simultaneously, first response wins
    /// + High bandwidth usage, low latency
    /// + Multi-hop forwarding using HTL
    Flooding,
    /// Freenet-style adaptive routing: try best peer first, fallback on failure
    /// + Low bandwidth, learns peer quality over time
    /// + Multi-hop forwarding using HTL
    /// + Orders peers by: success rate, RTT, backoff state
    Adaptive,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::Adaptive
    }
}

/// Configuration for FloodingStore
#[derive(Clone)]
pub struct FloodingConfig {
    // Note: routing_strategy can be overridden at runtime via set_routing_strategy()
    /// Per-peer timeout (Adaptive: per peer, Flooding: overall)
    pub request_timeout: Duration,
    /// Enable multi-hop forwarding (using HTL)
    pub forward_requests: bool,
    /// Peer pool configuration (uses same defaults as real WebRTC)
    /// Simulation uses "other" pool since there's no social graph
    pub pool: PoolConfig,
    /// Connection timeout (ms)
    pub connect_timeout_ms: u64,
    /// Mean network latency per hop (ms) - used as center of distribution
    /// Set to 0 for instant delivery (unit tests), ~50ms for realistic WebRTC
    pub network_latency_ms: u64,
    /// Latency variation coefficient (0.0-1.0) - how much latency varies per link
    /// 0.0 = all links have same latency, 0.5 = latency varies by ±50%
    pub latency_variation: f64,
    /// Routing strategy for data requests
    pub routing_strategy: RoutingStrategy,
    /// Peer selection strategy (used by Adaptive routing to order peers)
    pub selection_strategy: SelectionStrategy,
    /// Random seed for per-link latency generation (reproducible simulations)
    pub latency_seed: u64,
}

impl FloodingConfig {
    /// Get max peers from pool config
    pub fn max_peers(&self) -> usize {
        self.pool.max_connections
    }
}

impl Default for FloodingConfig {
    fn default() -> Self {
        Self {
            // Per-peer timeout: 1s allows multi-hop forwarding with 50ms latency
            request_timeout: Duration::from_secs(1),
            forward_requests: true,
            // Use same defaults as real WebRTC "other" pool
            pool: PoolConfig::default(),
            connect_timeout_ms: 5000,
            network_latency_ms: 0, // Instant for tests, set to ~50 for realistic simulation
            latency_variation: 0.0, // No variation by default (uniform latency)
            routing_strategy: RoutingStrategy::Adaptive,
            selection_strategy: SelectionStrategy::Weighted,
            latency_seed: 42,
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
/// - Data transfer (flooding requests, HTL-based forwarding)
/// - Adaptive peer selection (preferring reliable, fast peers)
///
/// DEPRECATED: Use `webrtc_sim::Simulation` with GenericStore instead.
/// This uses the exact same code as production WebRTCStore.
#[deprecated(since = "0.2.0", note = "Use webrtc_sim::Simulation with GenericStore instead")]
pub struct FloodingStore {
    /// Node ID (string for signaling)
    id: String,
    /// Node ID (numeric for data transfer)
    node_id: u64,
    /// Local storage
    local: Arc<SimStore>,
    /// Connected peers with their HTL configs
    peers: RwLock<HashMap<u64, ConnectedPeer>>,
    /// Pending requests we originated (hash -> response channel)
    our_requests: RwLock<HashMap<[u8; 32], OurRequest>>,
    /// Forwarded requests (hash -> list of peers waiting for response)
    forwarded_requests: RwLock<HashMap<[u8; 32], ForwardedRequest>>,
    /// Pending outbound connections (we sent offer)
    pending_outbound: RwLock<HashMap<String, PendingConnection>>,
    /// Message sender for unified handler
    msg_tx: mpsc::Sender<IncomingMessage>,
    /// Configuration
    config: FloodingConfig,
    /// Runtime strategy override (if Some, overrides config.routing_strategy)
    strategy_override: RwLock<Option<RoutingStrategy>>,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Adaptive peer selector for intelligent peer selection
    peer_selector: RwLock<PeerSelector>,
}

// Global channel registry for signaling
// Maps channel_id -> channel half waiting to be claimed
lazy_static::lazy_static! {
    static ref CHANNEL_REGISTRY: RwLock<HashMap<String, Arc<MockChannel>>> = RwLock::new(HashMap::new());
}

/// Clear the global channel registry (call between independent simulations)
pub async fn clear_channel_registry() {
    CHANNEL_REGISTRY.write().await.clear();
}

impl FloodingStore {
    /// Create a new flooding store
    pub fn new(id: impl Into<String>, config: FloodingConfig) -> Arc<Self> {
        let id = id.into();
        let node_id = id.parse().unwrap_or(0);
        let local = Arc::new(SimStore::new(node_id));
        let (msg_tx, msg_rx) = mpsc::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        // Initialize peer selector with configured strategy
        let peer_selector = PeerSelector::with_strategy(config.selection_strategy);

        let store = Arc::new(Self {
            id,
            node_id,
            local,
            peers: RwLock::new(HashMap::new()),
            our_requests: RwLock::new(HashMap::new()),
            forwarded_requests: RwLock::new(HashMap::new()),
            pending_outbound: RwLock::new(HashMap::new()),
            msg_tx,
            config,
            strategy_override: RwLock::new(None),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            shutdown_tx,
            peer_selector: RwLock::new(peer_selector),
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

    /// Get current routing strategy (respects runtime override)
    pub async fn routing_strategy(&self) -> RoutingStrategy {
        self.strategy_override
            .read()
            .await
            .unwrap_or(self.config.routing_strategy)
    }

    /// Override routing strategy at runtime (for benchmarking same topology with different strategies)
    pub async fn set_routing_strategy(&self, strategy: RoutingStrategy) {
        *self.strategy_override.write().await = Some(strategy);
    }

    /// Clear routing strategy override (use config default)
    pub async fn clear_routing_strategy_override(&self) {
        *self.strategy_override.write().await = None;
    }

    // ==================== Signaling ====================

    /// Connect to relay and announce presence
    pub async fn start(self: &Arc<Self>, relay: &Arc<MockRelay>) -> RelayClient {
        let mut client = relay.connect(self.id.clone()).await;

        // Subscribe to ALL presence events (for hello-based discovery)
        let presence_filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        let _ = client.subscribe("presence", vec![presence_filter]).await;

        // Subscribe to offers and answers directed at us
        let offer_filter = Filter::new()
            .kinds(vec![KIND_OFFER])
            .p_tags(vec![self.id.clone()]);
        let _ = client.subscribe("offers", vec![offer_filter]).await;

        let answer_filter = Filter::new()
            .kinds(vec![KIND_ANSWER])
            .p_tags(vec![self.id.clone()]);
        let _ = client.subscribe("answers", vec![answer_filter]).await;

        // Announce hello - do this AFTER subscribing so we see our own
        // and after others have subscribed so they see ours
        let hello = Event::new(
            self.id.clone(),
            KIND_PRESENCE,
            serde_json::to_string(&SignalingMessage::Hello {
                peer_id: self.id.clone(),
                roots: vec![], // No roots to advertise in simulation
            })
            .unwrap(),
        );
        let _ = client.publish(hello).await;

        // Consume the OK response
        while let Some(msg) = client.recv().await {
            if matches!(msg, RelayMessage::Ok { .. }) {
                break;
            }
        }

        client
    }

    /// Discover peers by querying presence events
    pub async fn discover_peers(&self, client: &RelayClient) -> Result<(), crate::relay::RelayError> {
        let filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        client.subscribe("discovery", vec![filter]).await
    }

    /// Generate per-link latency based on config and peer IDs
    /// Deterministic: same node pair always gets same latency (for reproducible comparisons)
    fn generate_link_latency(&self, peer_id: u64) -> u64 {
        let base = self.config.network_latency_ms;
        if base == 0 || self.config.latency_variation <= 0.0 {
            return base;
        }

        // Deterministic hash based on both node IDs (order-independent for symmetric latency)
        // XOR is commutative, so A↔B and B↔A get same latency
        let link_hash = self.node_id ^ peer_id;
        // Mix with seed for different runs to produce different (but reproducible) latencies
        let mixed = link_hash.wrapping_mul(0x517cc1b727220a95).wrapping_add(self.config.latency_seed);

        // Convert to variation factor in range [1-variation, 1+variation]
        let variation = self.config.latency_variation;
        let normalized = (mixed as f64) / (u64::MAX as f64); // 0.0 to 1.0
        let factor = 1.0 + variation * (2.0 * normalized - 1.0); // [1-var, 1+var]

        // Ensure latency is at least 1ms and at most 5x base
        let latency = (base as f64 * factor).round() as u64;
        latency.max(1).min(base * 5)
    }

    /// Send data to a channel with per-link latency
    async fn send_with_link_latency(
        &self,
        channel: &dyn PeerChannel,
        data: Vec<u8>,
        link_latency_ms: u64,
    ) -> Result<(), crate::channel::ChannelError> {
        // Simulate network latency (one-way delay) using per-link value
        if link_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(link_latency_ms)).await;
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
        // Use same pool logic as real WebRTC
        if !self.config.pool.can_accept(self.peers.read().await.len()) {
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

        let offer_msg = SignalingMessage::Offer {
            peer_id: self.id.clone(),
            target_peer_id: target.to_string(),
            sdp: channel_id, // Mock uses channel ID instead of real SDP
        };
        let offer = Event::new(
            self.id.clone(),
            KIND_OFFER,
            serde_json::to_string(&offer_msg).unwrap(),
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
        // Use same pool logic as real WebRTC (can_accept for incoming)
        if !self.config.pool.can_accept(self.peers.read().await.len()) {
            return Ok(());
        }

        // Parse offer to get channel ID (mock puts channel ID in sdp field)
        let msg: SignalingMessage = match serde_json::from_str(&event.content) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let channel_id = match msg {
            SignalingMessage::Offer { sdp, .. } => sdp,
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
        let answer_msg = SignalingMessage::Answer {
            peer_id: self.id.clone(),
            target_peer_id: from.clone(),
            sdp: channel_id, // Echo back the channel ID
        };
        let answer = Event::new(
            self.id.clone(),
            KIND_ANSWER,
            serde_json::to_string(&answer_msg).unwrap(),
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
                "presence" => {
                    // Handle hello-based discovery (like real WebRTC)
                    self.handle_hello(client, &event).await;
                }
                "discovery" => {
                    // Legacy: just return peer id for external handling
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

    /// Handle incoming hello message - perfect negotiation pattern
    ///
    /// This uses WebRTC "perfect negotiation" pattern:
    /// 1. Check if we can accept more peers (below max)
    /// 2. If we NEED more peers (below satisfied), send an offer
    /// 3. Both peers may send offers - collisions resolved by polite/impolite pattern
    ///
    /// The polite peer (lower ID) backs off on collision and accepts incoming offer.
    /// This ensures connections form even when one peer is satisfied but can accept.
    async fn handle_hello(self: &Arc<Self>, client: &RelayClient, event: &Event) {
        let from = &event.pubkey;

        // Ignore our own hello
        if from == &self.id {
            return;
        }

        let from_id: u64 = from.parse().unwrap_or(0);

        // Already connected?
        if self.peers.read().await.contains_key(&from_id) {
            return;
        }

        // Already pending?
        if self.pending_outbound.read().await.contains_key(from) {
            return;
        }

        let peer_count = self.peers.read().await.len();

        // Check pool limits - can we accept at all?
        if !self.config.pool.can_accept(peer_count) {
            return;
        }

        // Perfect negotiation: send offer if we NEED more peers
        // Both sides may send offers - collisions handled in handle_offer
        if self.config.pool.needs_peers(peer_count) {
            let _ = self.send_offer(client, from).await;
        }
    }

    // ==================== Peer Management ====================

    /// Add a peer channel and start receiving from it
    pub async fn add_peer(self: &Arc<Self>, peer_id: u64, channel: Arc<dyn PeerChannel>) {
        // Generate random HTL config for this peer (Freenet-style)
        let htl_config = PeerHTLConfig::random();

        // Generate per-link latency (deterministic based on node pair for reproducibility)
        let link_latency_ms = self.generate_link_latency(peer_id);

        self.peers.write().await.insert(peer_id, ConnectedPeer {
            channel: channel.clone(),
            htl_config,
            link_latency_ms,
        });

        // Register with peer selector for adaptive selection
        self.peer_selector.write().await.add_peer(peer_id);

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
        self.peer_selector.write().await.remove_peer(peer_id);
    }

    /// Get peer selector summary stats
    pub async fn peer_selection_summary(&self) -> crate::peer_selector::SelectorSummary {
        self.peer_selector.read().await.summary()
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
        match self.routing_strategy().await {
            RoutingStrategy::Flooding => self.fetch_from_peers_flooding(hash, exclude).await,
            RoutingStrategy::Adaptive => self.fetch_from_peers_adaptive(hash, exclude).await,
        }
    }

    /// Flooding strategy: send to all peers at once, first response wins
    async fn fetch_from_peers_flooding(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return None;
        }

        // Send to all peers (flooding) with MAX_HTL (we're originating this request)
        let mut sent_to = Vec::new();
        for (&peer_id, peer) in peers.iter() {
            if Some(peer_id) == exclude {
                continue;
            }

            // Decrement HTL when sending (Freenet-style)
            let outgoing_htl = decrement_htl(MAX_HTL, &peer.htl_config);
            let request_bytes = encode_request(hash, outgoing_htl);

            // Use per-link latency for this peer
            if self.send_with_link_latency(peer.channel.as_ref(), request_bytes.clone(), peer.link_latency_ms).await.is_ok() {
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
            .insert(*hash, OurRequest { response_tx: tx });

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
                self.our_requests.write().await.remove(hash);
                None
            }
        }
    }

    /// Adaptive routing: try best peer first, learn from results, fallback on failure
    /// Like Freenet's routing but without location-based selection (we use quality only)
    async fn fetch_from_peers_adaptive(&self, hash: &[u8; 32], exclude: Option<u64>) -> Option<Vec<u8>> {
        // Get peer ordering from selector (best peers first) along with their RTOs
        let ordered_peers: Vec<(u64, Duration)> = {
            let mut selector = self.peer_selector.write().await;
            selector.select_peers()
                .into_iter()
                .filter(|&id| Some(id) != exclude)
                .map(|id| {
                    // Use learned RTO per peer, fallback to config timeout
                    let rto = selector.get_stats(id)
                        .map(|s| Duration::from_millis(s.rto_ms))
                        .unwrap_or(self.config.request_timeout);
                    (id, rto)
                })
                .collect()
        };

        if ordered_peers.is_empty() {
            return None;
        }

        // Try each peer in order (best peers first, like Freenet's closerPeer())
        for (peer_id, peer_rto) in ordered_peers {
            let (channel, htl_config, link_latency_ms) = {
                let peers = self.peers.read().await;
                match peers.get(&peer_id) {
                    Some(peer) => (peer.channel.clone(), peer.htl_config.clone(), peer.link_latency_ms),
                    None => continue, // Peer disconnected
                }
            };

            // Decrement HTL when sending (Freenet-style)
            let outgoing_htl = decrement_htl(MAX_HTL, &htl_config);
            let request_bytes = encode_request(hash, outgoing_htl);
            let request_size = request_bytes.len() as u64;

            // Track request in selector
            self.peer_selector.write().await.record_request(peer_id, request_size);
            let request_start = std::time::Instant::now();

            // Send request with per-link latency
            if self.send_with_link_latency(channel.as_ref(), request_bytes.clone(), link_latency_ms).await.is_err() {
                self.peer_selector.write().await.record_failure(peer_id);
                continue; // Try next peer
            }
            self.bytes_sent.fetch_add(request_size, Ordering::Relaxed);

            // Setup response channel
            let (tx, rx) = oneshot::channel();
            self.our_requests
                .write()
                .await
                .insert(*hash, OurRequest { response_tx: tx });

            // Wait for response using learned RTO (adaptive timeout per peer)
            match tokio::time::timeout(peer_rto, rx).await {
                Ok(Ok(Some(data))) => {
                    // Success! Record metrics for learning
                    let rtt_ms = request_start.elapsed().as_millis() as u64;
                    self.peer_selector.write().await.record_success(peer_id, rtt_ms, data.len() as u64);
                    // Cache locally and return
                    self.local.put_local(*hash, data.clone());
                    return Some(data);
                }
                Ok(Ok(None)) => {
                    // Peer responded with not found - not a failure, just doesn't have it
                    continue;
                }
                _ => {
                    // Timeout or error - record and try next peer
                    self.peer_selector.write().await.record_timeout(peer_id);
                    self.our_requests.write().await.remove(hash);
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
            Ok(ParsedMessage::Request(req)) => {
                if let Some(hash) = req.hash() {
                    self.handle_request(from_peer, hash, req.htl_value()).await;
                }
            }
            Ok(ParsedMessage::Response(res)) => {
                if let Some(hash) = res.hash() {
                    self.handle_response(from_peer, hash, res.d).await;
                }
            }
            Err(_) => {}
        }
    }

    /// Handle incoming request from a peer
    async fn handle_request(&self, from_peer: u64, hash: [u8; 32], htl: u8) {
        // Check local store first - always respond if we have data
        if let Some(data) = self.local.get_local(&hash) {
            let response = encode_response(&hash, &data);
            if let Some(peer) = self.peers.read().await.get(&from_peer) {
                if self.send_with_link_latency(peer.channel.as_ref(), response.clone(), peer.link_latency_ms).await.is_ok() {
                    self.bytes_sent
                        .fetch_add(response.len() as u64, Ordering::Relaxed);
                }
            }
            return;
        }

        // Not found locally - check if we're already forwarding this request
        // If so, just add this peer to the list of requesters (they'll all get the response)
        {
            let mut forwarded = self.forwarded_requests.write().await;

            // Expire old entries to prevent unbounded growth (simple TTL cleanup)
            let now = std::time::Instant::now();
            forwarded.retain(|_, req| now.duration_since(req.created_at) < FORWARDED_REQUEST_TTL);

            if let Some(req) = forwarded.get_mut(&hash) {
                // Already forwarding - add this peer to the list
                if !req.from_peers.contains(&from_peer) {
                    req.from_peers.push(from_peer);
                }
                return; // Don't forward again, just wait for response
            }
        }

        // Try forwarding to other peers if HTL allows
        if self.config.forward_requests && should_forward(htl) {
            // Track the request so we can route response back to ALL requesters
            self.forwarded_requests.write().await.insert(
                hash,
                ForwardedRequest {
                    from_peers: vec![from_peer],
                    created_at: std::time::Instant::now(),
                    received_htl: htl,
                },
            );

            // Forward to other peers (excluding the requester)
            let peers = self.peers.read().await;
            for (&peer_id, peer) in peers.iter() {
                if peer_id == from_peer {
                    continue;
                }

                // Decrement HTL when forwarding
                let outgoing_htl = decrement_htl(htl, &peer.htl_config);
                if !should_forward(outgoing_htl) {
                    continue; // HTL exhausted for this peer
                }

                let request_bytes = encode_request(&hash, outgoing_htl);
                if self.send_with_link_latency(peer.channel.as_ref(), request_bytes.clone(), peer.link_latency_ms).await.is_ok() {
                    self.bytes_sent
                        .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);
                }
            }
            drop(peers);

            // Note: We don't wait for response here - response will come asynchronously
            // and be routed back via handle_response
        }
    }

    /// Handle incoming response
    async fn handle_response(&self, from_peer: u64, hash: [u8; 32], data: Vec<u8>) {
        // Verify hash
        if hashtree_core::sha256(&data) != hash {
            // Record failure for bad data
            self.peer_selector.write().await.record_failure(from_peer);
            return;
        }

        // Record success for the peer that responded
        // Even in flooding mode, tracking helps identify reliable peers
        // We don't have exact RTT for flooding mode, use 0 as placeholder
        self.peer_selector.write().await.record_success(from_peer, 0, data.len() as u64);

        // Check if this is a response to our own request
        if let Some(req) = self.our_requests.write().await.remove(&hash) {
            let _ = req.response_tx.send(Some(data.clone()));
            // Cache locally
            self.local.put_local(hash, data);
            return;
        }

        // Check if we need to forward response back to requesters
        if let Some(forwarded) = self.forwarded_requests.write().await.remove(&hash) {
            // Cache locally before forwarding
            self.local.put_local(hash, data.clone());

            // Send response back to ALL requesters (not just the first one)
            let response = encode_response(&hash, &data);
            let peers = self.peers.read().await;
            for requester_id in forwarded.from_peers {
                if let Some(peer) = peers.get(&requester_id) {
                    if self.send_with_link_latency(peer.channel.as_ref(), response.clone(), peer.link_latency_ms).await.is_ok() {
                        self.bytes_sent
                            .fetch_add(response.len() as u64, Ordering::Relaxed);
                    }
                }
            }
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
        Ok(ParsedMessage::Request(req)) => {
            if let Some(hash) = req.hash() {
                if let Some(data) = local.get_local(&hash) {
                    Some(encode_response(&hash, &data))
                } else {
                    None
                }
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
        let hash = hashtree_core::sha256(data);
        store.local().put_local(hash, data.to_vec());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_flooding_network_fetch() {
        let store1 = FloodingStore::with_defaults("1");
        let store2 = FloodingStore::with_defaults("2");

        let data = b"network data";
        let hash = hashtree_core::sha256(data);
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
        let hash = hashtree_core::sha256(data);
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

        // A fetches - should go A -> B -> C -> B -> A (using HTL)
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
        let hash = hashtree_core::sha256(data);
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

    #[tokio::test]
    async fn test_adaptive_selection_prefers_reliable_peers() {
        // Test that adaptive routing learns to prefer reliable peers
        // Setup: Node A connected to peers B (reliable) and C (unreliable/no data)
        let config = FloodingConfig {
            routing_strategy: RoutingStrategy::Adaptive,
            request_timeout: Duration::from_millis(200),
            ..Default::default()
        };

        let store_a = FloodingStore::new("1", config.clone());
        let store_b = FloodingStore::new("2", config.clone());
        let store_c = FloodingStore::new("3", config.clone());

        // Connect A to both B and C
        let (chan_ab, chan_ba) = MockChannel::pair(1, 2);
        let (chan_ac, chan_ca) = MockChannel::pair(1, 3);
        store_a.add_peer(2, Arc::new(chan_ab)).await;
        store_a.add_peer(3, Arc::new(chan_ac)).await;
        store_b.add_peer(1, Arc::new(chan_ba)).await;
        store_c.add_peer(1, Arc::new(chan_ca)).await;

        tokio::time::sleep(Duration::from_millis(20)).await;

        // B has multiple pieces of data, C has none
        let mut hashes = Vec::new();
        for i in 0..5 {
            let data = format!("data chunk {}", i);
            let hash = hashtree_core::sha256(data.as_bytes());
            store_b.local().put_local(hash, data.into_bytes());
            hashes.push(hash);
        }

        // Fetch all data - A should learn that B is reliable
        for hash in &hashes {
            let result = store_a.get(hash).await.unwrap();
            assert!(result.is_some(), "Should find data");
        }

        // Check peer selection stats
        let summary = store_a.peer_selection_summary().await;
        assert!(summary.total_requests > 0, "Should have made requests");
        assert!(summary.total_successes > 0, "Should have successes");

        // Get individual peer stats
        let selector = store_a.peer_selector.read().await;
        let peer_b_stats = selector.get_stats(2).unwrap();
        let peer_c_stats = selector.get_stats(3).unwrap();

        // Peer B should have higher success rate than C
        assert!(
            peer_b_stats.success_rate() > peer_c_stats.success_rate(),
            "Peer B (reliable) should have higher success rate than C. B={:.2}, C={:.2}",
            peer_b_stats.success_rate(),
            peer_c_stats.success_rate()
        );

        // Peer B should have better score than C
        assert!(
            peer_b_stats.score() > peer_c_stats.score(),
            "Peer B should have better score. B={:.2}, C={:.2}",
            peer_b_stats.score(),
            peer_c_stats.score()
        );

        println!("Peer B stats: requests={}, successes={}, score={:.2}",
            peer_b_stats.requests_sent, peer_b_stats.successes, peer_b_stats.score());
        println!("Peer C stats: requests={}, successes={}, score={:.2}",
            peer_c_stats.requests_sent, peer_c_stats.successes, peer_c_stats.score());
    }

    #[tokio::test]
    async fn test_adaptive_with_forwarding() {
        // Test that Adaptive routing forwards requests through the network
        // A -- B -- C (C has data, A requests)
        let config = FloodingConfig {
            routing_strategy: RoutingStrategy::Adaptive,
            forward_requests: true,
            request_timeout: Duration::from_secs(2), // Long timeout for multi-hop
            ..Default::default()
        };

        let store_a = FloodingStore::new("1", config.clone());
        let store_b = FloodingStore::new("2", config.clone());
        let store_c = FloodingStore::new("3", config.clone());

        // C has the data
        let data = b"forwarded data";
        let hash = hashtree_core::sha256(data);
        store_c.local().put_local(hash, data.to_vec());

        // A -- B -- C (A not directly connected to C)
        let (chan_ab, chan_ba) = MockChannel::pair(1, 2);
        let (chan_bc, chan_cb) = MockChannel::pair(2, 3);
        store_a.add_peer(2, Arc::new(chan_ab)).await;
        store_b.add_peer(1, Arc::new(chan_ba)).await;
        store_b.add_peer(3, Arc::new(chan_bc)).await;
        store_c.add_peer(2, Arc::new(chan_cb)).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // A fetches - should go A -> B -> C -> B -> A via forwarding
        let result = store_a.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()), "Adaptive routing should find data via forwarding");

        // B should have cached it (was on forwarding path)
        assert!(store_b.local().has_local(&hash), "B should cache forwarded data");
    }
}
