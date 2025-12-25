//! Network simulation harness
//!
//! Spawns and removes nodes over time (churn), forms topology through signaling,
//! and analyzes results. Can run network benchmarks measuring bandwidth, latency,
//! and success rate.
//!
//! Uses HashTree<FloodingStore> - full stack simulation matching production architecture.
//! - HashTree handles content chunking and merkle tree operations
//! - FloodingStore handles P2P networking (signaling, peer management, multi-hop routing)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use tokio::sync::RwLock;

use crate::flooding::{FloodingConfig, FloodingStore, RoutingStrategy};
use crate::relay::{MockRelay, RelayClient};
use crate::store::NetworkStore;
use hashtree_core::{HashTree, HashTreeConfig};

/// Simulation configuration
#[derive(Clone)]
pub struct SimConfig {
    /// Number of nodes to spawn
    pub node_count: usize,
    /// Total simulation duration
    pub duration: Duration,
    /// Random seed for reproducibility
    pub seed: u64,
    /// Max peers per node
    pub max_peers: usize,
    /// How often nodes check for new peers (ms)
    pub discovery_interval_ms: u64,
    /// Churn rate: probability a node leaves per interval (0.0 - 1.0)
    pub churn_rate: f64,
    /// Whether departed nodes can rejoin
    pub allow_rejoin: bool,
    /// Mean network latency per hop (e.g., 50ms for realistic WebRTC)
    pub network_latency_ms: u64,
    /// Latency variation coefficient (0.0-1.0) - how much latency varies per link
    /// 0.0 = all links have same latency, 0.5 = latency varies by ±50%
    pub latency_variation: f64,
    /// Routing strategy for data requests
    pub routing_strategy: RoutingStrategy,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            node_count: 100,
            duration: Duration::from_secs(60),
            seed: 42,
            max_peers: 5,
            discovery_interval_ms: 500,
            churn_rate: 0.01, // 1% chance per interval
            allow_rejoin: true,
            network_latency_ms: 50, // 50ms simulated network latency per hop
            latency_variation: 0.3, // ±30% variation by default (realistic variance)
            routing_strategy: RoutingStrategy::Flooding,
        }
    }
}

/// Simulation event for logging/analysis
#[derive(Debug, Clone)]
pub enum SimEvent {
    NodeJoined { node_id: String, time_ms: u64 },
    NodeLeft { node_id: String, time_ms: u64 },
    ConnectionFormed { from: String, to: String, time_ms: u64 },
    ConnectionLost { from: String, to: String, time_ms: u64 },
}

/// A running node in the simulation
struct RunningNode {
    /// HashTree for content operations (chunking, merkle trees)
    tree: HashTree<FloodingStore>,
    /// The underlying FloodingStore for P2P operations (signaling, peer management)
    store: Arc<FloodingStore>,
    /// Relay client for signaling
    client: RelayClient,
    #[allow(dead_code)]
    joined_at_ms: u64,
}

/// Topology analysis results
#[derive(Debug, Clone)]
pub struct TopologyStats {
    /// Total nodes
    pub node_count: usize,
    /// Total connections (edges)
    pub connection_count: usize,
    /// Average connections per node
    pub avg_degree: f64,
    /// Min connections
    pub min_degree: usize,
    /// Max connections
    pub max_degree: usize,
    /// Number of isolated nodes (no connections)
    pub isolated_nodes: usize,
    /// Is the network connected (single component)?
    pub is_connected: bool,
    /// Number of connected components
    pub component_count: usize,
    /// Size of largest component
    pub largest_component: usize,
    /// Clustering coefficient (how connected neighbors are)
    pub clustering_coefficient: f64,
    /// Degree distribution
    pub degree_distribution: HashMap<usize, usize>,
}

/// Results from a single request
#[derive(Debug, Clone)]
pub struct RequestResult {
    /// Whether the request succeeded (found data)
    pub success: bool,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Bytes sent for this request
    pub bytes_sent: u64,
    /// Bytes received for this request
    pub bytes_received: u64,
    /// Number of peers queried
    pub peers_queried: usize,
    /// Hops to find data (for sequential)
    pub hops: usize,
}

/// Aggregated benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    /// Strategy name
    pub strategy: String,
    /// Number of requests made
    pub total_requests: usize,
    /// Successful requests
    pub successful_requests: usize,
    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Average bytes sent per request
    pub avg_bytes_sent: f64,
    /// Average bytes received per request
    pub avg_bytes_received: f64,
    /// Average latency (ms) for successful requests
    pub avg_latency_ms: f64,
    /// Min latency (ms)
    pub min_latency_ms: f64,
    /// Max latency (ms)
    pub max_latency_ms: f64,
    /// P50 latency (ms)
    pub p50_latency_ms: f64,
    /// P95 latency (ms)
    pub p95_latency_ms: f64,
    /// P99 latency (ms)
    pub p99_latency_ms: f64,
    /// Average hops to find data
    pub avg_hops: f64,
    /// Individual request results
    pub requests: Vec<RequestResult>,
}

impl BenchmarkResults {
    fn from_requests(strategy: &str, requests: Vec<RequestResult>) -> Self {
        let total = requests.len();
        let successful: Vec<&RequestResult> = requests.iter().filter(|r| r.success).collect();
        let success_count = successful.len();

        let total_sent: u64 = requests.iter().map(|r| r.bytes_sent).sum();
        let total_recv: u64 = requests.iter().map(|r| r.bytes_received).sum();

        let mut latencies: Vec<f64> = successful.iter().map(|r| r.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        } else {
            0.0
        };

        let percentile = |p: f64| -> f64 {
            if latencies.is_empty() {
                return 0.0;
            }
            let idx = ((p / 100.0) * latencies.len() as f64) as usize;
            latencies[idx.min(latencies.len() - 1)]
        };

        let total_hops: usize = successful.iter().map(|r| r.hops).sum();
        let avg_hops = if success_count > 0 {
            total_hops as f64 / success_count as f64
        } else {
            0.0
        };

        Self {
            strategy: strategy.to_string(),
            total_requests: total,
            successful_requests: success_count,
            success_rate: if total > 0 { success_count as f64 / total as f64 } else { 0.0 },
            total_bytes_sent: total_sent,
            total_bytes_received: total_recv,
            avg_bytes_sent: if total > 0 { total_sent as f64 / total as f64 } else { 0.0 },
            avg_bytes_received: if total > 0 { total_recv as f64 / total as f64 } else { 0.0 },
            avg_latency_ms: avg_latency,
            min_latency_ms: latencies.first().copied().unwrap_or(0.0),
            max_latency_ms: latencies.last().copied().unwrap_or(0.0),
            p50_latency_ms: percentile(50.0),
            p95_latency_ms: percentile(95.0),
            p99_latency_ms: percentile(99.0),
            avg_hops,
            requests,
        }
    }

    /// Print benchmark results
    pub fn print(&self) {
        println!("=== {} Benchmark ===", self.strategy);
        println!("Requests: {} total, {} successful ({:.1}%)",
            self.total_requests, self.successful_requests, self.success_rate * 100.0);
        println!("Bandwidth: {:.0} bytes sent, {:.0} bytes recv (avg per request)",
            self.avg_bytes_sent, self.avg_bytes_received);
        println!("Latency: avg={:.2}ms, min={:.2}ms, max={:.2}ms",
            self.avg_latency_ms, self.min_latency_ms, self.max_latency_ms);
        println!("Latency percentiles: p50={:.2}ms, p95={:.2}ms, p99={:.2}ms",
            self.p50_latency_ms, self.p95_latency_ms, self.p99_latency_ms);
        if self.avg_hops > 0.0 {
            println!("Average hops: {:.2}", self.avg_hops);
        }
    }
}

/// Simulation statistics over time
#[derive(Debug, Clone, Default)]
pub struct SimStats {
    /// Total nodes that ever joined
    pub total_joins: usize,
    /// Total node departures
    pub total_leaves: usize,
    /// Total connections formed
    pub total_connections_formed: usize,
    /// Total connections lost (due to churn)
    pub total_connections_lost: usize,
    /// Topology snapshots over time (time_ms -> stats)
    pub topology_snapshots: Vec<(u64, TopologyStats)>,
    /// All events
    pub events: Vec<SimEvent>,
}

/// Network simulation
pub struct Simulation {
    config: SimConfig,
    relay: Arc<MockRelay>,
    nodes: RwLock<HashMap<String, RunningNode>>,
    rng: RwLock<StdRng>,
    stats: RwLock<SimStats>,
    next_node_id: RwLock<usize>,
}

impl Simulation {
    pub fn new(config: SimConfig) -> Self {
        Self {
            rng: RwLock::new(StdRng::seed_from_u64(config.seed)),
            relay: MockRelay::new(),
            nodes: RwLock::new(HashMap::new()),
            stats: RwLock::new(SimStats::default()),
            next_node_id: RwLock::new(0),
            config,
        }
    }

    /// Run the simulation - spawn/remove nodes over time with churn
    /// Uses tick-based simulation for deterministic topology formation
    pub async fn run(&self) {
        let total_ms = self.config.duration.as_millis() as u64;
        let tick_ms = self.config.discovery_interval_ms;
        let total_ticks = total_ms / tick_ms;

        // Generate initial spawn times for all nodes (in ticks)
        let spawn_ticks: Vec<u64> = {
            let mut rng = self.rng.write().await;
            (0..self.config.node_count)
                .map(|_| rng.gen_range(0..total_ticks))
                .collect()
        };

        // Sort spawn times
        let mut spawn_schedule: Vec<(u64, usize)> = spawn_ticks
            .into_iter()
            .enumerate()
            .map(|(i, t)| (t, i))
            .collect();
        spawn_schedule.sort_by_key(|(t, _)| *t);

        let mut next_spawn_idx = 0;
        let snapshot_interval_ticks = 5000 / tick_ms; // Every ~5s worth of ticks

        // Deterministic tick-based loop (no real time dependency)
        for tick in 0..total_ticks {
            let elapsed_ms = tick * tick_ms;

            // Spawn any nodes scheduled for this tick
            while next_spawn_idx < spawn_schedule.len() && spawn_schedule[next_spawn_idx].0 <= tick {
                self.spawn_node(elapsed_ms).await;
                next_spawn_idx += 1;
            }

            // Process messages, apply churn, run discovery (every tick)
            self.process_all_messages().await;
            self.apply_churn(elapsed_ms).await;
            self.discover_and_connect(elapsed_ms).await;

            // Periodic topology snapshot
            if tick > 0 && tick % snapshot_interval_ticks == 0 {
                let stats = self.analyze_topology().await;
                self.stats.write().await.topology_snapshots.push((elapsed_ms, stats));
            }
        }

        // Final processing (deterministic number of iterations)
        for _ in 0..10 {
            self.process_all_messages().await;
        }

        let final_stats = self.analyze_topology().await;
        self.stats.write().await.topology_snapshots.push((total_ms, final_stats));
    }

    async fn spawn_node(&self, time_ms: u64) {
        let node_id = {
            let mut id = self.next_node_id.write().await;
            let current = *id;
            *id += 1;
            current.to_string()
        };

        // Both Flooding and Adaptive use multi-hop forwarding
        let store_config = FloodingConfig {
            max_peers: self.config.max_peers,
            connect_timeout_ms: 5000,
            network_latency_ms: self.config.network_latency_ms,
            latency_variation: self.config.latency_variation,
            latency_seed: self.config.seed, // Use same seed for reproducibility
            routing_strategy: self.config.routing_strategy,
            forward_requests: true, // Both strategies forward
            // Timeout for multi-hop forwarding (longer to allow propagation)
            request_timeout: Duration::from_secs(1),
            ..FloodingConfig::default()
        };

        // Create FloodingStore for P2P networking
        let store = FloodingStore::new(node_id.clone(), store_config);

        // Wrap in HashTree for content operations (chunking, merkle trees)
        let tree_config = HashTreeConfig::new(store.clone());
        let tree = HashTree::new(tree_config);

        let mut client = store.start(&self.relay).await;

        // Drain initial messages (EOSE, etc)
        while let Some(msg) = client.try_recv() {
            let _ = store.process_message(&client, msg).await;
        }

        // Record event
        {
            let mut stats = self.stats.write().await;
            stats.total_joins += 1;
            stats.events.push(SimEvent::NodeJoined {
                node_id: node_id.clone(),
                time_ms,
            });
        }

        self.nodes.write().await.insert(
            node_id,
            RunningNode {
                tree,
                store,
                client,
                joined_at_ms: time_ms,
            },
        );
    }

    async fn apply_churn(&self, time_ms: u64) {
        if self.config.churn_rate <= 0.0 {
            return;
        }

        let node_ids: Vec<String> = self.nodes.read().await.keys().cloned().collect();
        let mut to_remove = Vec::new();

        {
            let mut rng = self.rng.write().await;
            for node_id in &node_ids {
                if rng.gen::<f64>() < self.config.churn_rate {
                    to_remove.push(node_id.clone());
                }
            }
        }

        // Remove nodes that churned
        for node_id in to_remove {
            self.remove_node(&node_id, time_ms).await;

            // Optionally rejoin later
            if self.config.allow_rejoin {
                // Schedule rejoin sometime in the remaining simulation
                // For simplicity, just spawn a new node
                self.spawn_node(time_ms).await;
            }
        }
    }

    async fn remove_node(&self, node_id: &str, time_ms: u64) {
        let removed = self.nodes.write().await.remove(node_id);

        if let Some(running) = removed {
            // Stop the store
            running.store.stop();

            // Record connections lost
            let peer_ids = running.store.peer_ids().await;
            let mut stats = self.stats.write().await;

            for peer_id in peer_ids {
                stats.total_connections_lost += 1;
                stats.events.push(SimEvent::ConnectionLost {
                    from: node_id.to_string(),
                    to: peer_id.to_string(),
                    time_ms,
                });
            }

            stats.total_leaves += 1;
            stats.events.push(SimEvent::NodeLeft {
                node_id: node_id.to_string(),
                time_ms,
            });
        }
    }

    async fn process_all_messages(&self) {
        // Sort node IDs for deterministic processing order
        let mut node_ids: Vec<String> = self.nodes.read().await.keys().cloned().collect();
        node_ids.sort();

        let mut nodes = self.nodes.write().await;
        for node_id in &node_ids {
            if let Some(running) = nodes.get_mut(node_id) {
                while let Some(msg) = running.client.try_recv() {
                    running.store.process_message(&running.client, msg).await;
                }
            }
        }
    }

    async fn discover_and_connect(&self, _time_ms: u64) {
        let mut node_ids: Vec<String> = self.nodes.read().await.keys().cloned().collect();
        node_ids.sort(); // Deterministic order

        for node_id in &node_ids {
            let nodes = self.nodes.read().await;
            let running = match nodes.get(node_id) {
                Some(r) => r,
                None => continue,
            };

            let current_peers = running.store.peer_count().await;
            if current_peers >= self.config.max_peers {
                continue;
            }

            // Pick random node to connect to
            let target = {
                let mut rng = self.rng.write().await;
                let candidates: Vec<&String> = node_ids
                    .iter()
                    .filter(|id| *id != node_id)
                    .collect();

                if candidates.is_empty() {
                    continue;
                }

                candidates[rng.gen_range(0..candidates.len())].clone()
            };

            // Check if already connected (peer_ids returns u64, need to convert)
            let existing_peers = running.store.peer_ids().await;
            let target_id: u64 = target.parse().unwrap_or(0);
            if existing_peers.contains(&target_id) {
                continue;
            }

            let _ = running.store.send_offer(&running.client, &target).await;

            // Record potential connection (actual connection confirmed via answer)
            // We'll count connections in topology analysis
        }
    }

    /// Analyze the current network topology
    pub async fn analyze_topology(&self) -> TopologyStats {
        let nodes = self.nodes.read().await;

        // Build adjacency map (convert u64 peer IDs to strings for topology analysis)
        let mut adjacency: HashMap<String, HashSet<String>> = HashMap::new();
        for (node_id, running) in nodes.iter() {
            let peers = running.store.peer_ids().await;
            let peer_strings: HashSet<String> = peers.into_iter().map(|p| p.to_string()).collect();
            adjacency.insert(node_id.clone(), peer_strings);
        }

        let node_count = adjacency.len();
        if node_count == 0 {
            return TopologyStats {
                node_count: 0,
                connection_count: 0,
                avg_degree: 0.0,
                min_degree: 0,
                max_degree: 0,
                isolated_nodes: 0,
                is_connected: true,
                component_count: 0,
                largest_component: 0,
                clustering_coefficient: 0.0,
                degree_distribution: HashMap::new(),
            };
        }

        // Only count edges to active nodes (filter out dangling references to churned peers)
        let active_nodes: HashSet<String> = adjacency.keys().cloned().collect();
        let active_adjacency: HashMap<String, HashSet<String>> = adjacency
            .iter()
            .map(|(k, v)| {
                let active_peers: HashSet<String> = v.iter()
                    .filter(|p| active_nodes.contains(*p))
                    .cloned()
                    .collect();
                (k.clone(), active_peers)
            })
            .collect();

        // Calculate degrees and distribution
        let degrees: Vec<usize> = active_adjacency.values().map(|peers| peers.len()).collect();
        let mut degree_distribution: HashMap<usize, usize> = HashMap::new();
        for &d in &degrees {
            *degree_distribution.entry(d).or_insert(0) += 1;
        }

        let total_degree: usize = degrees.iter().sum();
        let connection_count = total_degree / 2;
        let avg_degree = total_degree as f64 / node_count as f64;
        let min_degree = *degrees.iter().min().unwrap_or(&0);
        let max_degree = *degrees.iter().max().unwrap_or(&0);
        let isolated_nodes = degrees.iter().filter(|&&d| d == 0).count();

        // Find connected components using BFS
        let mut visited: HashSet<String> = HashSet::new();
        let mut components: Vec<usize> = Vec::new();

        for node_id in active_adjacency.keys() {
            if visited.contains(node_id) {
                continue;
            }

            let mut queue = vec![node_id.clone()];
            let mut component_size = 0;

            while let Some(current) = queue.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());
                component_size += 1;

                if let Some(peers) = active_adjacency.get(&current) {
                    for peer in peers {
                        if !visited.contains(peer) {
                            queue.push(peer.clone());
                        }
                    }
                }
            }

            if component_size > 0 {
                components.push(component_size);
            }
        }

        let component_count = components.len();
        let largest_component = *components.iter().max().unwrap_or(&0);
        let is_connected = component_count <= 1;

        // Calculate clustering coefficient
        let mut total_clustering = 0.0;
        let mut nodes_with_neighbors = 0;

        for (_, peers) in &active_adjacency {
            let k = peers.len();
            if k < 2 {
                continue;
            }

            let mut neighbor_edges = 0;
            let peer_list: Vec<&String> = peers.iter().collect();
            for i in 0..peer_list.len() {
                for j in (i + 1)..peer_list.len() {
                    if let Some(peer_neighbors) = active_adjacency.get(peer_list[i]) {
                        if peer_neighbors.contains(peer_list[j]) {
                            neighbor_edges += 1;
                        }
                    }
                }
            }

            let max_edges = k * (k - 1) / 2;
            if max_edges > 0 {
                total_clustering += neighbor_edges as f64 / max_edges as f64;
                nodes_with_neighbors += 1;
            }
        }

        let clustering_coefficient = if nodes_with_neighbors > 0 {
            total_clustering / nodes_with_neighbors as f64
        } else {
            0.0
        };

        TopologyStats {
            node_count,
            connection_count,
            avg_degree,
            min_degree,
            max_degree,
            isolated_nodes,
            is_connected,
            component_count,
            largest_component,
            clustering_coefficient,
            degree_distribution,
        }
    }

    /// Get simulation statistics
    pub async fn get_stats(&self) -> SimStats {
        self.stats.read().await.clone()
    }

    /// Get number of currently active nodes
    pub async fn active_node_count(&self) -> usize {
        self.nodes.read().await.len()
    }

    /// Set routing strategy for all nodes (for benchmarking same topology with different strategies)
    pub async fn set_routing_strategy(&self, strategy: RoutingStrategy) {
        let nodes = self.nodes.read().await;
        for (_, running) in nodes.iter() {
            running.store.set_routing_strategy(strategy).await;
        }
    }

    /// Print topology summary
    pub fn print_topology_stats(stats: &TopologyStats) {
        println!("=== Topology Analysis ===");
        println!("Nodes: {}", stats.node_count);
        println!("Connections: {}", stats.connection_count);
        println!("Avg degree: {:.2}", stats.avg_degree);
        println!("Min/Max degree: {} / {}", stats.min_degree, stats.max_degree);
        println!("Isolated nodes: {}", stats.isolated_nodes);
        println!("Connected: {}", stats.is_connected);
        println!("Components: {} (largest: {})", stats.component_count, stats.largest_component);
        println!("Clustering coefficient: {:.4}", stats.clustering_coefficient);
        println!("Degree distribution: {:?}", stats.degree_distribution);
    }

    /// Print simulation summary
    pub fn print_sim_stats(stats: &SimStats) {
        println!("=== Simulation Stats ===");
        println!("Total joins: {}", stats.total_joins);
        println!("Total leaves: {}", stats.total_leaves);
        println!("Connections formed: {}", stats.total_connections_formed);
        println!("Connections lost: {}", stats.total_connections_lost);
        println!("Topology snapshots: {}", stats.topology_snapshots.len());
    }

    /// Run network benchmarks using the live simulation topology
    ///
    /// Places data on random nodes and makes requests from other nodes,
    /// measuring bandwidth, latency, and success rate.
    ///
    /// Uses the routing strategy configured in SimConfig.
    pub async fn run_benchmark(
        &self,
        num_requests: usize,
        data_size: usize,
        request_timeout: Duration,
    ) -> BenchmarkResults {
        let strategy_name = match self.config.routing_strategy {
            RoutingStrategy::Flooding => "Flooding",
            RoutingStrategy::Adaptive => "Adaptive",
        };
        self.benchmark_with_strategy(strategy_name, num_requests, data_size, request_timeout).await
    }

    /// Run benchmark with explicit strategy name (for when strategy is overridden at runtime)
    pub async fn run_benchmark_named(
        &self,
        strategy_name: &str,
        num_requests: usize,
        data_size: usize,
        request_timeout: Duration,
    ) -> BenchmarkResults {
        self.benchmark_with_strategy(strategy_name, num_requests, data_size, request_timeout).await
    }

    /// Get the routing strategy name
    pub fn strategy_name(&self) -> &'static str {
        match self.config.routing_strategy {
            RoutingStrategy::Flooding => "Flooding",
            RoutingStrategy::Adaptive => "Adaptive",
        }
    }

    /// Benchmark using HashTree + FloodingStore (full stack)
    ///
    /// Uses HashTree for content operations (put_file/read_file with chunking)
    /// and FloodingStore for P2P networking (routing based on config).
    /// This mirrors production architecture: HashTree<WebRTCStore>.
    async fn benchmark_with_strategy(
        &self,
        strategy_name: &str,
        num_requests: usize,
        data_size: usize,
        timeout: Duration,
    ) -> BenchmarkResults {
        let mut results = Vec::new();

        let mut node_ids: Vec<String> = self.nodes.read().await.keys().cloned().collect();
        node_ids.sort(); // Deterministic order for reproducible benchmarks

        if node_ids.len() < 2 {
            eprintln!("  Not enough nodes for benchmark");
            return BenchmarkResults::from_requests(strategy_name, results);
        }

        for i in 0..num_requests {
            if i > 0 && i % 10 == 0 {
                eprint!(".");
            }

            // Pick random requester and data owner
            let (requester_id, owner_id) = {
                let mut rng = self.rng.write().await;
                let req_idx = rng.gen_range(0..node_ids.len());
                let mut owner_idx = rng.gen_range(0..node_ids.len());
                while owner_idx == req_idx {
                    owner_idx = rng.gen_range(0..node_ids.len());
                }
                (node_ids[req_idx].clone(), node_ids[owner_idx].clone())
            };

            // Generate random data
            let data: Vec<u8> = {
                let mut rng = self.rng.write().await;
                (0..data_size).map(|_| rng.gen()).collect()
            };

            // Store data on owner's HashTree (handles chunking for large files)
            let hash = {
                let nodes = self.nodes.read().await;
                let owner = match nodes.get(&owner_id) {
                    Some(n) => n,
                    None => continue,
                };
                match owner.tree.put_file(&data).await {
                    Ok(result) => result.hash,
                    Err(_) => continue,
                }
            };

            // Get requester's store for bandwidth tracking
            let (requester_store, bytes_sent_before, bytes_recv_before) = {
                let nodes = self.nodes.read().await;
                let requester = match nodes.get(&requester_id) {
                    Some(n) => n,
                    None => continue,
                };
                let store = requester.store.clone();
                (store, requester.store.bytes_sent(), requester.store.bytes_received())
            };

            // Make request using requester's HashTree (multi-hop forwarding via FloodingStore)
            let start = Instant::now();
            let result = {
                let nodes = self.nodes.read().await;
                let requester = match nodes.get(&requester_id) {
                    Some(n) => n,
                    None => continue,
                };
                tokio::time::timeout(timeout, requester.tree.read_file(&hash)).await
            };
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            // Unwrap timeout and HashTree result
            let result = result.ok().and_then(|r| r.ok()).flatten();

            let bytes_sent = requester_store.bytes_sent() - bytes_sent_before;
            let bytes_recv = requester_store.bytes_received() - bytes_recv_before;

            let success = match result {
                Some(ref retrieved) => *retrieved == data,
                None => false,
            };

            // Clean up - delete from owner and requester cache
            {
                let nodes = self.nodes.read().await;
                if let Some(owner) = nodes.get(&owner_id) {
                    owner.store.local().delete_local(&hash);
                }
                if let Some(requester) = nodes.get(&requester_id) {
                    requester.store.local().delete_local(&hash);
                }
            }

            results.push(RequestResult {
                success,
                latency_ms,
                bytes_sent,
                bytes_received: bytes_recv,
                peers_queried: 0,
                hops: 0,
            });
        }

        BenchmarkResults::from_requests(strategy_name, results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_small_simulation() {
        let config = SimConfig {
            node_count: 10,
            duration: Duration::from_secs(2),
            seed: 42,
            max_peers: 3,
            discovery_interval_ms: 100,
            churn_rate: 0.0, // No churn for basic test
            allow_rejoin: false,
            network_latency_ms: 0, // No latency for unit tests
            latency_variation: 0.0,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;

        let stats = sim.analyze_topology().await;
        println!("\nSmall simulation results:");
        Simulation::print_topology_stats(&stats);

        assert_eq!(stats.node_count, 10);
        assert!(stats.connection_count > 0, "Should have some connections");
    }

    #[tokio::test]
    async fn test_simulation_with_churn() {
        let config = SimConfig {
            node_count: 20,
            duration: Duration::from_secs(3),
            seed: 123,
            max_peers: 4,
            discovery_interval_ms: 100,
            churn_rate: 0.05, // 5% churn rate
            allow_rejoin: true,
            network_latency_ms: 0,
            latency_variation: 0.0,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;

        let stats = sim.analyze_topology().await;
        let sim_stats = sim.get_stats().await;

        println!("\nSimulation with churn:");
        Simulation::print_topology_stats(&stats);
        Simulation::print_sim_stats(&sim_stats);

        assert!(sim_stats.total_joins >= 20, "Should have at least initial joins");
        // With churn, might have some leaves
    }

    #[tokio::test]
    async fn test_topology_over_time() {
        let config = SimConfig {
            node_count: 15,
            duration: Duration::from_secs(5),
            seed: 456,
            max_peers: 3,
            discovery_interval_ms: 100,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 0,
            latency_variation: 0.0,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;

        let sim_stats = sim.get_stats().await;
        println!("\nTopology snapshots over time:");
        for (time_ms, topo) in &sim_stats.topology_snapshots {
            println!("  t={}ms: {} nodes, {} connections, avg_degree={:.2}",
                time_ms, topo.node_count, topo.connection_count, topo.avg_degree);
        }

        assert!(!sim_stats.topology_snapshots.is_empty());
    }
}
