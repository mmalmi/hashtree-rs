//! Quick network simulation (10 nodes, 5 seconds)
//!
//! Usage: cargo run -p hashtree-sim --example quick_sim --release

use hashtree_sim::{SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== Quick Network Simulation ===\n");

    let config = SimConfig {
        node_count: 20,
        duration: Duration::from_secs(5),
        seed: 42,
        max_peers: 4,
        discovery_interval_ms: 200,
        churn_rate: 0.05, // 5% churn per tick
        allow_rejoin: true,
    };

    println!("Config: {} nodes, {:?}, {}% churn",
        config.node_count, config.duration, config.churn_rate * 100.0);
    println!();

    let max_peers = config.max_peers;
    let sim = Simulation::new(config);
    sim.run().await;

    let topology = sim.analyze_topology().await;
    let sim_stats = sim.get_stats().await;

    Simulation::print_topology_stats(&topology);
    println!();
    Simulation::print_sim_stats(&sim_stats);
    println!();

    println!("=== Timeline ===");
    for (time_ms, topo) in &sim_stats.topology_snapshots {
        println!("  t={:.1}s: {} nodes, {} conn, avg_deg={:.1}",
            *time_ms as f64 / 1000.0,
            topo.node_count,
            topo.connection_count,
            topo.avg_degree);
    }
    println!();

    // Verify largest component <= node_count
    assert!(topology.largest_component <= topology.node_count,
        "largest_component ({}) should be <= node_count ({})",
        topology.largest_component, topology.node_count);

    println!("All assertions passed!");
}
