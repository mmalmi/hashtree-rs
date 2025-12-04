//! Network simulation harness
//!
//! Spawns and removes nodes over time (churn), forms topology through signaling,
//! and analyzes results.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use tokio::sync::RwLock;

use crate::relay::{MockRelay, RelayClient};
use crate::node::{NodeConfig, SimNode};

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
    node: Arc<SimNode>,
    client: RelayClient,
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
    pub async fn run(&self) {
        let total_ms = self.config.duration.as_millis() as u64;

        // Generate initial spawn times for all nodes
        let spawn_times: Vec<u64> = {
            let mut rng = self.rng.write().await;
            (0..self.config.node_count)
                .map(|_| rng.gen_range(0..total_ms))
                .collect()
        };

        // Sort spawn times
        let mut spawn_schedule: Vec<(u64, usize)> = spawn_times
            .into_iter()
            .enumerate()
            .map(|(i, t)| (t, i))
            .collect();
        spawn_schedule.sort_by_key(|(t, _)| *t);

        let start = std::time::Instant::now();
        let mut next_spawn_idx = 0;
        let discovery_interval = Duration::from_millis(self.config.discovery_interval_ms);
        let mut last_tick = std::time::Instant::now();
        let snapshot_interval = Duration::from_secs(5); // Take topology snapshot every 5s
        let mut last_snapshot = std::time::Instant::now();

        // Main simulation loop
        while start.elapsed() < self.config.duration {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            // Spawn any nodes scheduled for this time
            while next_spawn_idx < spawn_schedule.len() && spawn_schedule[next_spawn_idx].0 <= elapsed_ms {
                let (_, _) = spawn_schedule[next_spawn_idx];
                self.spawn_node(elapsed_ms).await;
                next_spawn_idx += 1;
            }

            // Periodic tick: discovery, churn, message processing
            if last_tick.elapsed() >= discovery_interval {
                self.process_all_messages().await;
                self.apply_churn(elapsed_ms).await;
                self.discover_and_connect(elapsed_ms).await;
                last_tick = std::time::Instant::now();
            }

            // Periodic topology snapshot
            if last_snapshot.elapsed() >= snapshot_interval {
                let stats = self.analyze_topology().await;
                self.stats.write().await.topology_snapshots.push((elapsed_ms, stats));
                last_snapshot = std::time::Instant::now();
            }

            // Small sleep to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Final processing and snapshot
        for _ in 0..10 {
            self.process_all_messages().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let final_stats = self.analyze_topology().await;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.stats.write().await.topology_snapshots.push((elapsed_ms, final_stats));
    }

    async fn spawn_node(&self, time_ms: u64) {
        let node_id = {
            let mut id = self.next_node_id.write().await;
            let current = *id;
            *id += 1;
            current.to_string()
        };

        let node_config = NodeConfig {
            max_peers: self.config.max_peers,
            connect_timeout_ms: 5000,
        };

        let node = SimNode::new(node_id.clone(), node_config);
        let mut client = node.connect_to_relay(&self.relay).await;

        // Setup signaling subscriptions
        let _ = node.setup_signaling(&client).await;

        // Drain initial messages
        while let Some(msg) = client.try_recv() {
            let _ = node.process_message(&client, msg).await;
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
                node,
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
            // Record connections lost
            let peer_ids = running.node.peer_ids().await;
            let mut stats = self.stats.write().await;

            for peer_id in peer_ids {
                stats.total_connections_lost += 1;
                stats.events.push(SimEvent::ConnectionLost {
                    from: node_id.to_string(),
                    to: peer_id,
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
        let mut nodes = self.nodes.write().await;
        for (_, running) in nodes.iter_mut() {
            while let Some(msg) = running.client.try_recv() {
                running.node.process_message(&running.client, msg).await;
            }
        }
    }

    async fn discover_and_connect(&self, _time_ms: u64) {
        let node_ids: Vec<String> = self.nodes.read().await.keys().cloned().collect();

        for node_id in &node_ids {
            let nodes = self.nodes.read().await;
            let running = match nodes.get(node_id) {
                Some(r) => r,
                None => continue,
            };

            let current_peers = running.node.peer_count().await;
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

            // Check if already connected
            let existing_peers = running.node.peer_ids().await;
            if existing_peers.contains(&target) {
                continue;
            }

            let _ = running.node.send_offer(&running.client, &target).await;

            // Record potential connection (actual connection confirmed via answer)
            // We'll count connections in topology analysis
        }
    }

    /// Analyze the current network topology
    pub async fn analyze_topology(&self) -> TopologyStats {
        let nodes = self.nodes.read().await;

        // Build adjacency map
        let mut adjacency: HashMap<String, HashSet<String>> = HashMap::new();
        for (node_id, running) in nodes.iter() {
            let peers = running.node.peer_ids().await;
            adjacency.insert(node_id.clone(), peers.into_iter().collect());
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
