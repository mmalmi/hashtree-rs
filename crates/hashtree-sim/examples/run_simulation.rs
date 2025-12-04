//! Run a network simulation with 100 nodes joining/leaving over 1 minute
//!
//! Usage: cargo run -p hashtree-sim --example run_simulation

use hashtree_sim::{SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== Hashtree Network Simulation ===\n");

    // Parse command line args for seed
    let args: Vec<String> = std::env::args().collect();
    let seed = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);

    let config = SimConfig {
        node_count: 100,
        duration: Duration::from_secs(60),
        seed,
        max_peers: 5,
        discovery_interval_ms: 500,
        churn_rate: 0.02, // 2% chance per tick
        allow_rejoin: true,
    };

    println!("Configuration:");
    println!("  Nodes: {}", config.node_count);
    println!("  Duration: {:?}", config.duration);
    println!("  Seed: {}", config.seed);
    println!("  Max peers: {}", config.max_peers);
    println!("  Discovery interval: {}ms", config.discovery_interval_ms);
    println!("  Churn rate: {:.1}%", config.churn_rate * 100.0);
    println!("  Allow rejoin: {}", config.allow_rejoin);
    println!();

    println!("Running simulation...");
    let start = std::time::Instant::now();

    let max_peers = config.max_peers;
    let sim = Simulation::new(config);
    sim.run().await;

    let elapsed = start.elapsed();
    println!("Simulation completed in {:.2}s\n", elapsed.as_secs_f64());

    // Print final topology
    let topology = sim.analyze_topology().await;
    Simulation::print_topology_stats(&topology);
    println!();

    // Print simulation stats
    let sim_stats = sim.get_stats().await;
    Simulation::print_sim_stats(&sim_stats);
    println!();

    // Print topology evolution
    println!("=== Topology Evolution ===");
    for (time_ms, topo) in &sim_stats.topology_snapshots {
        let time_s = *time_ms as f64 / 1000.0;
        println!(
            "  t={:5.1}s: {:3} nodes, {:3} connections, avg_deg={:.2}, components={}",
            time_s,
            topo.node_count,
            topo.connection_count,
            topo.avg_degree,
            topo.component_count
        );
    }
    println!();

    // Print degree distribution
    println!("=== Degree Distribution ===");
    let mut degrees: Vec<_> = topology.degree_distribution.iter().collect();
    degrees.sort_by_key(|(d, _)| *d);
    for (degree, count) in degrees {
        let bar = "#".repeat(*count);
        println!("  {:2} peers: {:3} nodes {}", degree, count, bar);
    }
    println!();

    // Summary
    println!("=== Summary ===");
    let coverage = if topology.node_count > 0 {
        (topology.largest_component.min(topology.node_count)) as f64 / topology.node_count as f64 * 100.0
    } else {
        0.0
    };
    println!("Network connectivity: {:.1}% of nodes in largest component", coverage);
    println!("Average node has {:.1} peers (max {})", topology.avg_degree, max_peers);
    println!("Clustering coefficient: {:.3}", topology.clustering_coefficient);

    if topology.isolated_nodes > 0 {
        println!("WARNING: {} isolated nodes with no connections", topology.isolated_nodes);
    }
}
