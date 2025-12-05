//! Run a network simulation with benchmarks
//!
//! Tests the full stack: HashTree<FloodingStore> for content operations + P2P networking

use hashtree_sim::{SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    eprintln!("=== Network Simulation ===\n");

    let config = SimConfig {
        node_count: 20,
        duration: Duration::from_secs(5),
        seed: 42,
        max_peers: 4,
        discovery_interval_ms: 100,
        churn_rate: 0.0, // No churn for quick test
        allow_rejoin: false,
        network_latency_ms: 0,
    };

    eprintln!("Configuration:");
    eprintln!("  Nodes: {}", config.node_count);
    eprintln!("  Duration: {:?}", config.duration);
    eprintln!("  Max peers: {}", config.max_peers);

    eprintln!("\nRunning simulation...");
    let start = std::time::Instant::now();
    let sim = Simulation::new(config);
    sim.run().await;
    eprintln!("Simulation completed in {:.2}s\n", start.elapsed().as_secs_f64());

    // Analyze topology
    let topology = sim.analyze_topology().await;
    Simulation::print_topology_stats(&topology);

    // Run benchmarks with different data sizes
    eprintln!("\n=== Running Network Benchmarks ===");

    // Small data (256 bytes)
    eprintln!("\nSmall data (256 bytes):");
    let (results, _) = sim.run_benchmarks(20, 256, Duration::from_secs(2)).await;
    results.print();

    // Medium data (1KB)
    eprintln!("\nMedium data (1KB):");
    let (results, _) = sim.run_benchmarks(20, 1024, Duration::from_secs(2)).await;
    results.print();

    // Large data (64KB - will be chunked)
    eprintln!("\nLarge data (64KB - chunked):");
    let (results, _) = sim.run_benchmarks(10, 64 * 1024, Duration::from_secs(5)).await;
    results.print();

    eprintln!("\nDone!");
}
