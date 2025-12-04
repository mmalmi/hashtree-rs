//! Network simulation with discrete event queue
//!
//! All networking goes through NetworkAdapter which implements the
//! hashtree::Store trait. The Network orchestrates timing/latency
//! while nodes use HashTree for actual storage operations.
//!
//! ## Routing Strategy
//!
//! Content requests are routed hop-by-hop through the peer network:
//! 1. Check immediate peers first (1 hop)
//! 2. If not found, forward to peers' peers (2 hops)
//! 3. Continue until TTL expires or content found
//!
//! This simulates realistic P2P flooding while tracking bandwidth.

use crate::adapter::{FetchRequest, FetchResult, NetworkAdapter};
use crate::behavior::Behavior;
use crate::config::SimConfig;
use crate::metrics::SimMetrics;
use crate::node::{NodeId, SimNode};
use crate::store::SimStore;
use hashtree::{sha256, Cid, Hash, HashTree, HashTreeConfig};
use rand::prelude::*;
use rand::SeedableRng;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Event in the simulation
#[derive(Debug, Clone)]
struct Event {
    /// When this event occurs (simulation tick in ms)
    time: u64,
    /// Event type
    kind: EventKind,
}

#[derive(Debug, Clone)]
enum EventKind {
    /// Content fetch request (node initiates request)
    FetchRequest { node: NodeId, hash: Hash },
    /// Query arrives at a node (during multi-hop routing)
    QueryArrival {
        to: NodeId,
        from: NodeId,
        hash: Hash,
        origin: NodeId,
        hops: u32,
        ttl: u32,
        query_id: u64,
    },
    /// Response travels back
    ResponseArrival {
        to: NodeId,
        hash: Hash,
        data: Option<Vec<u8>>,
        hops: u32,
        query_id: u64,
    },
    /// Node joins network
    NodeJoin { node: NodeId },
    /// Node leaves network
    NodeLeave { node: NodeId },
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl Eq for Event {}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse for min-heap (earliest first)
        other.time.cmp(&self.time)
    }
}

/// Pending fetch with response channel
struct PendingFetch {
    respond_to: tokio::sync::oneshot::Sender<FetchResult>,
    started_at: u64,
}

/// Tracks a query in progress at a specific node (for routing responses back)
#[derive(Debug, Clone)]
struct QueryRouteInfo {
    /// Original requester of this query
    origin: NodeId,
    /// Which peer sent us this query (for response routing back)
    received_from: NodeId,
    /// When this query arrived at this node
    arrived_at: u64,
}

/// Network simulation
///
/// Uses NetworkAdapter for all HashTree operations. The simulation
/// handles timing, latency, and node behaviors while HashTree handles
/// the actual merkle tree operations.
pub struct Network {
    /// Simulated nodes
    nodes: HashMap<NodeId, SimNode>,
    /// Node stores (for network-wide content lookup)
    stores: HashMap<NodeId, Arc<SimStore>>,
    /// Event queue for discrete simulation
    event_queue: BinaryHeap<Event>,
    /// Configuration
    config: SimConfig,
    /// Random number generator
    rng: StdRng,
    /// Current simulation tick (ms)
    current_tick: u64,
    /// Collected metrics
    metrics: SimMetrics,
    /// Content that exists in the network (for seeding)
    content: HashMap<Hash, Vec<u8>>,
    /// Which nodes have which content
    content_locations: HashMap<Hash, Vec<NodeId>>,
    /// Next node ID
    next_node_id: NodeId,
    /// Next query ID
    next_query_id: u64,
    /// Pending fetch requests awaiting response (from adapters)
    pending_fetches: HashMap<u64, PendingFetch>,
    /// Active queries being routed (query_id -> node_id -> routing info)
    active_queries: HashMap<u64, HashMap<NodeId, QueryRouteInfo>>,
    /// Queries each node has seen (for deduplication)
    seen_queries: HashMap<NodeId, HashSet<u64>>,
    /// Channel receivers for fetch requests from adapters
    fetch_receivers: HashMap<NodeId, mpsc::Receiver<FetchRequest>>,
    /// Channel senders for creating adapters
    fetch_senders: HashMap<NodeId, mpsc::Sender<FetchRequest>>,
    /// Bandwidth tracking: bytes sent per node
    bytes_sent: HashMap<NodeId, u64>,
    /// Bandwidth tracking: bytes received per node
    bytes_received: HashMap<NodeId, u64>,
}

impl Network {
    pub fn new(config: SimConfig) -> Self {
        let rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        Self {
            nodes: HashMap::new(),
            stores: HashMap::new(),
            event_queue: BinaryHeap::new(),
            config,
            rng,
            current_tick: 0,
            metrics: SimMetrics::new(),
            content: HashMap::new(),
            content_locations: HashMap::new(),
            next_node_id: 0,
            next_query_id: 0,
            pending_fetches: HashMap::new(),
            active_queries: HashMap::new(),
            seen_queries: HashMap::new(),
            fetch_receivers: HashMap::new(),
            fetch_senders: HashMap::new(),
            bytes_sent: HashMap::new(),
            bytes_received: HashMap::new(),
        }
    }

    /// Initialize network with nodes and random topology
    pub fn initialize(&mut self) {
        // Create nodes
        for _ in 0..self.config.node_count {
            self.add_node();
        }

        // Create random connections (peer topology)
        let node_ids: Vec<_> = self.nodes.keys().copied().collect();
        for &node_id in &node_ids {
            let peers_needed = self.config.peers_per_node;
            let mut available: Vec<_> = node_ids
                .iter()
                .filter(|&&id| id != node_id)
                .copied()
                .collect();
            available.shuffle(&mut self.rng);

            for peer_id in available.into_iter().take(peers_needed) {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    node.connect(peer_id, 0);
                }
                // Bidirectional connection
                if let Some(peer) = self.nodes.get_mut(&peer_id) {
                    peer.connect(node_id, 0);
                }
            }
        }

        // Generate and seed content
        self.seed_content();
    }

    fn add_node(&mut self) -> NodeId {
        let id = self.next_node_id;
        self.next_node_id += 1;

        // Create store and channels for this node
        let store = Arc::new(SimStore::new(id));
        let (tx, rx) = mpsc::channel(1000);

        self.stores.insert(id, store.clone());
        self.fetch_senders.insert(id, tx);
        self.fetch_receivers.insert(id, rx);
        self.seen_queries.insert(id, HashSet::new());
        self.bytes_sent.insert(id, 0);
        self.bytes_received.insert(id, 0);

        // Create the SimNode
        let mut node = SimNode::new(id, self.config.request_cache_size);

        // Assign behavior based on config fractions
        let r: f64 = self.rng.gen();
        let behavior = if r < self.config.malicious_fraction {
            Behavior::malicious()
        } else if r < self.config.malicious_fraction + self.config.selfish_fraction {
            Behavior::selfish()
        } else if r < self.config.malicious_fraction
            + self.config.selfish_fraction
            + self.config.freeloader_fraction
        {
            Behavior::freeloader()
        } else {
            Behavior::cooperative()
        };

        node = node.with_behavior(behavior);
        self.nodes.insert(id, node);
        id
    }

    /// Get a NetworkAdapter for a node (for HashTree operations)
    pub fn get_adapter(&self, node_id: NodeId) -> Option<NetworkAdapter> {
        let store = self.stores.get(&node_id)?.clone();
        let tx = self.fetch_senders.get(&node_id)?.clone();
        Some(NetworkAdapter::new(node_id, store, tx))
    }

    /// Get a HashTree for a node
    pub fn get_hashtree(&self, node_id: NodeId) -> Option<HashTree<NetworkAdapter>> {
        let adapter = self.get_adapter(node_id)?;
        Some(HashTree::new(
            HashTreeConfig::new(Arc::new(adapter)).public(),
        ))
    }

    fn seed_content(&mut self) {
        let node_ids: Vec<_> = self.nodes.keys().copied().collect();

        for _ in 0..self.config.content_count {
            // Generate random content
            let mut data = vec![0u8; self.config.content_size];
            self.rng.fill_bytes(&mut data);

            // Hash it
            let hash = sha256(&data);

            // Store in a random node
            let node_id = node_ids[self.rng.gen_range(0..node_ids.len())];
            if let Some(store) = self.stores.get(&node_id) {
                store.put_local(hash, data.clone());
            }

            self.content.insert(hash, data);
            self.content_locations.entry(hash).or_default().push(node_id);
        }
    }

    /// Schedule a content fetch request
    pub fn schedule_fetch(&mut self, node_id: NodeId, hash: Hash, delay_ms: u64) {
        self.event_queue.push(Event {
            time: self.current_tick + delay_ms,
            kind: EventKind::FetchRequest { node: node_id, hash },
        });
    }

    /// Schedule random fetch requests across the network
    pub fn schedule_random_requests(&mut self, count: usize) {
        let node_ids: Vec<_> = self.nodes.keys().copied().collect();
        let hashes: Vec<_> = self.content.keys().copied().collect();

        for i in 0..count {
            let node_id = node_ids[self.rng.gen_range(0..node_ids.len())];
            let hash = hashes[self.rng.gen_range(0..hashes.len())];

            // Don't request content the node already has
            if self
                .stores
                .get(&node_id)
                .map(|s| s.has_local(&hash))
                .unwrap_or(false)
            {
                continue;
            }

            // Spread requests over time
            let delay = (i as u64) * 10; // 10ms apart
            self.schedule_fetch(node_id, hash, delay);
        }
    }

    /// Process pending fetch requests from adapters
    fn drain_adapter_requests(&mut self) {
        let node_ids: Vec<_> = self.fetch_receivers.keys().copied().collect();

        // Collect all requests first to avoid borrow issues
        let mut requests_to_process = Vec::new();

        for node_id in node_ids {
            if let Some(rx) = self.fetch_receivers.get_mut(&node_id) {
                while let Ok(request) = rx.try_recv() {
                    requests_to_process.push((node_id, request));
                }
            }
        }

        // Now process them
        for (node_id, request) in requests_to_process {
            let query_id = self.next_query_id;
            self.next_query_id += 1;

            // Store the pending request
            self.pending_fetches.insert(
                query_id,
                PendingFetch {
                    respond_to: request.respond_to,
                    started_at: self.current_tick,
                },
            );

            // Initiate the query
            self.initiate_query(node_id, request.hash, query_id, false);
        }
    }

    /// Initiate a new content query from a node
    /// If `internal` is true, this is a scheduled request (not from adapter) and we track it internally
    fn initiate_query(&mut self, origin: NodeId, hash: Hash, query_id: u64, internal: bool) {
        // Check local store first
        if let Some(store) = self.stores.get(&origin) {
            if let Some(data) = store.get_local(&hash) {
                // Found locally - immediate response
                self.metrics.record_cache_hit();
                if internal {
                    // For internal queries, just record success
                    self.metrics.record_request(true, false);
                    self.metrics.record_latency(0);
                    self.metrics.record_hops(0);
                } else {
                    self.complete_query(query_id, Some(data), 0);
                }
                return;
            }
        }

        self.metrics.record_cache_miss();

        // Track internal queries differently
        if internal {
            // We'll track completion via the response mechanism
            // Mark this as an "internal" pending fetch with a dummy channel
            let (tx, _rx) = tokio::sync::oneshot::channel();
            self.pending_fetches.insert(
                query_id,
                PendingFetch {
                    respond_to: tx,
                    started_at: self.current_tick,
                },
            );
        }

        // Initialize query tracking - include origin node so responses know when they've arrived
        let mut query_map = HashMap::new();
        query_map.insert(
            origin,
            QueryRouteInfo {
                origin,
                received_from: origin, // Points to self for origin
                arrived_at: self.current_tick,
            },
        );
        self.active_queries.insert(query_id, query_map);
        if let Some(seen) = self.seen_queries.get_mut(&origin) {
            seen.insert(query_id);
        }

        // Send query to all peers
        let peers: Vec<NodeId> = self
            .nodes
            .get(&origin)
            .map(|n| n.peer_ids())
            .unwrap_or_default();

        // Message size: hash (32 bytes) + query_id (8) + origin (8) + hops (4) + ttl (4) = 56 bytes
        let msg_size = 56u64;

        for peer_id in peers {
            let latency = self.config.latency.sample(&mut self.rng);
            self.event_queue.push(Event {
                time: self.current_tick + latency,
                kind: EventKind::QueryArrival {
                    to: peer_id,
                    from: origin,
                    hash,
                    origin,
                    hops: 1,
                    ttl: self.config.max_ttl,
                    query_id,
                },
            });

            // Track bandwidth
            *self.bytes_sent.entry(origin).or_default() += msg_size;
            *self.bytes_received.entry(peer_id).or_default() += msg_size;
            self.metrics.record_message();
        }
    }

    /// Handle a query arriving at a node
    fn handle_query_arrival(
        &mut self,
        to: NodeId,
        from: NodeId,
        hash: Hash,
        origin: NodeId,
        hops: u32,
        ttl: u32,
        query_id: u64,
    ) {
        // Check if we've already seen this query (deduplication)
        if let Some(seen) = self.seen_queries.get_mut(&to) {
            if seen.contains(&query_id) {
                return; // Already processed
            }
            seen.insert(query_id);
        }

        // Track this query for response routing
        if let Some(queries) = self.active_queries.get_mut(&query_id) {
            queries.insert(
                to,
                QueryRouteInfo {
                    origin,
                    received_from: from,
                    arrived_at: self.current_tick,
                },
            );
        }

        // Check if we have the content
        if let Some(store) = self.stores.get(&to) {
            if let Some(data) = store.get_local(&hash) {
                // Found! Send response back
                self.send_response(to, from, hash, Some(data), hops, query_id);
                return;
            }
        }

        // Not found locally - should we forward?
        if ttl == 0 {
            // TTL expired, send not found
            self.send_response(to, from, hash, None, hops, query_id);
            return;
        }

        // Forward to our peers (except the one we received from)
        let peers: Vec<NodeId> = self
            .nodes
            .get(&to)
            .map(|n| n.peer_ids().into_iter().filter(|&p| p != from).collect())
            .unwrap_or_default();

        if peers.is_empty() {
            // No peers to forward to
            self.send_response(to, from, hash, None, hops, query_id);
            return;
        }

        let msg_size = 56u64;

        for peer_id in peers {
            let latency = self.config.latency.sample(&mut self.rng);
            self.event_queue.push(Event {
                time: self.current_tick + latency,
                kind: EventKind::QueryArrival {
                    to: peer_id,
                    from: to,
                    hash,
                    origin,
                    hops: hops + 1,
                    ttl: ttl - 1,
                    query_id,
                },
            });

            *self.bytes_sent.entry(to).or_default() += msg_size;
            *self.bytes_received.entry(peer_id).or_default() += msg_size;
            self.metrics.record_message();
        }
    }

    /// Send a response back along the query path
    fn send_response(
        &mut self,
        from: NodeId,
        to: NodeId,
        hash: Hash,
        data: Option<Vec<u8>>,
        hops: u32,
        query_id: u64,
    ) {
        let latency = self.config.latency.sample(&mut self.rng);

        // Message size: hash (32) + data + query_id (8) + hops (4) = 44 + data
        let msg_size = 44 + data.as_ref().map(|d| d.len() as u64).unwrap_or(0);
        *self.bytes_sent.entry(from).or_default() += msg_size;
        *self.bytes_received.entry(to).or_default() += msg_size;

        self.event_queue.push(Event {
            time: self.current_tick + latency,
            kind: EventKind::ResponseArrival {
                to,
                hash,
                data,
                hops,
                query_id,
            },
        });

        self.metrics.record_message();
    }

    /// Handle a response arriving at a node
    fn handle_response_arrival(
        &mut self,
        to: NodeId,
        hash: Hash,
        data: Option<Vec<u8>>,
        hops: u32,
        query_id: u64,
    ) {
        // Check if this node is the origin (has a pending fetch)
        if let Some(queries) = self.active_queries.get(&query_id) {
            if let Some(query_info) = queries.get(&to) {
                if query_info.origin == to {
                    // This is the origin node - complete the query
                    self.complete_query(query_id, data.clone(), hops);

                    // Cache locally if found
                    if let Some(ref d) = data {
                        if let Some(store) = self.stores.get(&to) {
                            store.put_local(hash, d.clone());
                        }
                    }
                    return;
                }

                // Not origin - forward response back
                let forward_to = query_info.received_from;

                // Cache if we have data (opportunistic caching)
                if let Some(ref d) = data {
                    if let Some(store) = self.stores.get(&to) {
                        store.put_local(hash, d.clone());
                    }
                }

                self.send_response(to, forward_to, hash, data, hops, query_id);
            }
        }
    }

    /// Complete a query and notify the waiting adapter
    fn complete_query(&mut self, query_id: u64, data: Option<Vec<u8>>, hops: u32) {
        if let Some(pending) = self.pending_fetches.remove(&query_id) {
            let latency = self.current_tick - pending.started_at;
            self.metrics.record_latency(latency);
            self.metrics.record_hops(hops);

            let result = if let Some(d) = data {
                self.metrics.record_request(true, false);
                FetchResult::Found(d)
            } else {
                self.metrics.record_request(false, false);
                FetchResult::NotFound
            };

            let _ = pending.respond_to.send(result);
        }

        // Clean up query tracking
        self.active_queries.remove(&query_id);
    }

    /// Process one event
    fn process_event(&mut self, event: Event) {
        self.current_tick = event.time;

        match event.kind {
            EventKind::FetchRequest { node, hash } => {
                let query_id = self.next_query_id;
                self.next_query_id += 1;
                self.initiate_query(node, hash, query_id, true); // Internal (scheduled) request
            }
            EventKind::QueryArrival {
                to,
                from,
                hash,
                origin,
                hops,
                ttl,
                query_id,
            } => {
                self.handle_query_arrival(to, from, hash, origin, hops, ttl, query_id);
            }
            EventKind::ResponseArrival {
                to,
                hash,
                data,
                hops,
                query_id,
            } => {
                self.handle_response_arrival(to, hash, data, hops, query_id);
            }
            EventKind::NodeJoin { node: _ } => {
                // TODO: implement churn
            }
            EventKind::NodeLeave { node: _ } => {
                // TODO: implement churn
            }
        }
    }

    /// Run simulation until event queue is empty or max_ticks reached
    pub fn run(&mut self, max_ticks: u64) -> &SimMetrics {
        let end_tick = self.current_tick + max_ticks;

        loop {
            // Process any pending adapter requests
            self.drain_adapter_requests();

            // Process next event
            match self.event_queue.pop() {
                Some(event) if event.time <= end_tick => {
                    self.process_event(event);
                }
                Some(event) => {
                    // Put it back, we're done
                    self.event_queue.push(event);
                    break;
                }
                None => break,
            }
        }

        self.metrics.finalize();
        &self.metrics
    }

    /// Get current metrics
    pub fn metrics(&self) -> &SimMetrics {
        &self.metrics
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get content count
    pub fn content_count(&self) -> usize {
        self.content.len()
    }

    /// Get a content Cid for testing
    pub fn get_content_cid(&self, index: usize) -> Option<Cid> {
        let hashes: Vec<_> = self.content.keys().collect();
        hashes.get(index).map(|&hash| Cid {
            hash: *hash,
            key: None,
            size: self.content.get(hash).map(|d| d.len() as u64).unwrap_or(0),
        })
    }

    /// Get a random node ID
    pub fn random_node(&mut self) -> Option<NodeId> {
        let ids: Vec<_> = self.nodes.keys().copied().collect();
        if ids.is_empty() {
            None
        } else {
            Some(ids[self.rng.gen_range(0..ids.len())])
        }
    }

    /// Get bytes sent by a node
    pub fn bytes_sent(&self, node_id: NodeId) -> u64 {
        self.bytes_sent.get(&node_id).copied().unwrap_or(0)
    }

    /// Get bytes received by a node
    pub fn bytes_received(&self, node_id: NodeId) -> u64 {
        self.bytes_received.get(&node_id).copied().unwrap_or(0)
    }

    /// Get total bandwidth used across network
    pub fn total_bandwidth(&self) -> u64 {
        self.bytes_sent.values().sum()
    }

    /// Find shortest hop distance between two nodes (BFS)
    pub fn hop_distance(&self, from: NodeId, to: NodeId) -> Option<u32> {
        if from == to {
            return Some(0);
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((from, 0u32));
        visited.insert(from);

        while let Some((current, dist)) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&current) {
                for peer in node.peer_ids() {
                    if peer == to {
                        return Some(dist + 1);
                    }
                    if !visited.contains(&peer) {
                        visited.insert(peer);
                        queue.push_back((peer, dist + 1));
                    }
                }
            }
        }

        None // Not reachable
    }

    /// Get nodes that have specific content
    pub fn nodes_with_content(&self, hash: &Hash) -> Vec<NodeId> {
        self.content_locations.get(hash).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_simulation() {
        let config = SimConfig::small();
        let mut network = Network::new(config);
        network.initialize();

        assert_eq!(network.node_count(), 20);
        assert_eq!(network.content_count(), 100);

        // Schedule some requests
        network.schedule_random_requests(50);

        // Run simulation
        let metrics = network.run(10000);

        println!("{}", metrics.report());
        assert!(metrics.total_requests > 0);
    }

    #[test]
    fn test_multi_hop_fetch() {
        // Create a small network where content is NOT on immediate peers
        let mut config = SimConfig::small();
        config.node_count = 10;
        config.peers_per_node = 2; // Low connectivity
        config.content_count = 1;
        config.seed = Some(42);

        let mut network = Network::new(config);
        network.initialize();

        // Find a node that doesn't have the content
        let content_hash = *network.content.keys().next().unwrap();
        let content_nodes = network.nodes_with_content(&content_hash);

        // Find a node at least 2 hops away
        let mut requesting_node = None;
        for node_id in network.nodes.keys() {
            if !content_nodes.contains(node_id) {
                if let Some(dist) = network.hop_distance(*node_id, content_nodes[0]) {
                    if dist >= 2 {
                        requesting_node = Some(*node_id);
                        break;
                    }
                }
            }
        }

        if let Some(node_id) = requesting_node {
            println!(
                "Requesting node {} is {} hops from content",
                node_id,
                network.hop_distance(node_id, content_nodes[0]).unwrap()
            );

            network.schedule_fetch(node_id, content_hash, 0);
            let metrics = network.run(10000);

            println!("{}", metrics.report());
            println!("Hops p50: {}", metrics.hops_p50());

            // Should have found the content with multiple hops
            assert!(metrics.successful_requests > 0);
            assert!(metrics.hops_p50() >= 1); // At least 1 hop
        }
    }

    #[test]
    fn test_bandwidth_tracking() {
        let mut config = SimConfig::small();
        config.content_size = 1024; // 1KB content
        config.seed = Some(123);

        let mut network = Network::new(config);
        network.initialize();

        network.schedule_random_requests(10);
        network.run(10000);

        let total_bw = network.total_bandwidth();
        println!("Total bandwidth: {} bytes", total_bw);
        assert!(total_bw > 0);

        // Check per-node bandwidth
        for node_id in 0..5 {
            println!(
                "Node {}: sent={} recv={}",
                node_id,
                network.bytes_sent(node_id),
                network.bytes_received(node_id)
            );
        }
    }

    #[test]
    fn test_adversarial_network() {
        let config = SimConfig::adversarial();
        let mut network = Network::new(config);
        network.initialize();

        network.schedule_random_requests(100);
        let metrics = network.run(10000);

        println!("{}", metrics.report());
        assert!(metrics.total_requests > 0);
    }

    #[tokio::test]
    async fn test_hashtree_through_network() {
        let config = SimConfig::small();
        let mut network = Network::new(config);
        network.initialize();

        // Get a node that has some content
        let _cid = network.get_content_cid(0).unwrap();

        // Get another node that doesn't have it
        let requesting_node = network.random_node().unwrap();

        // Get HashTree for the requesting node
        let _tree = network.get_hashtree(requesting_node).unwrap();

        // The tree should be able to access content via the adapter
        let adapter = network.get_adapter(requesting_node).unwrap();
        assert!(adapter.has_network());
    }
}
