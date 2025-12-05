//! Run a network simulation with 100 nodes joining/leaving over 1 minute
//! then benchmark file requests across the formed network.
//!
//! Usage: cargo run -p hashtree-sim --example run_simulation --release [seed]

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
        network_latency_ms: 50, // 50ms per hop
    };

    println!("Configuration:");
    println!("  Nodes: {}", config.node_count);
    println!("  Duration: {:?}", config.duration);
    println!("  Seed: {}", config.seed);
    println!("  Max peers: {}", config.max_peers);
    println!("  Discovery interval: {}ms", config.discovery_interval_ms);
    println!("  Churn rate: {:.1}%", config.churn_rate * 100.0);
    println!("  Allow rejoin: {}", config.allow_rejoin);
    println!("  Network latency: {}ms per hop", config.network_latency_ms);
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

    // Run network benchmarks
    println!("=== Running Network Benchmarks ===");
    println!("Making 100 requests with 1KB data...\n");

    let (flooding, sequential) = sim.run_benchmarks(
        100,                          // number of requests
        1024,                         // data size (1KB)
        Duration::from_secs(5),       // timeout per request
    ).await;

    flooding.print();
    println!();
    sequential.print();
    println!();

    // Comparison summary
    println!("=== Strategy Comparison ===");
    println!("                    Flooding    Sequential");
    println!("Success rate:       {:6.1}%      {:6.1}%",
        flooding.success_rate * 100.0, sequential.success_rate * 100.0);
    println!("Avg latency:        {:6.2}ms     {:6.2}ms",
        flooding.avg_latency_ms, sequential.avg_latency_ms);
    println!("Avg bytes sent:     {:6.0}        {:6.0}",
        flooding.avg_bytes_sent, sequential.avg_bytes_sent);
    println!("Avg bytes recv:     {:6.0}        {:6.0}",
        flooding.avg_bytes_received, sequential.avg_bytes_received);

    if flooding.avg_hops > 0.0 || sequential.avg_hops > 0.0 {
        println!("Avg hops:           {:6.1}        {:6.1}",
            flooding.avg_hops, sequential.avg_hops);
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

    // Bandwidth efficiency
    if flooding.avg_bytes_sent > 0.0 && sequential.avg_bytes_sent > 0.0 {
        let ratio = flooding.avg_bytes_sent / sequential.avg_bytes_sent;
        println!("\nFlooding uses {:.1}x more bandwidth than sequential", ratio);
    }
}
