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
        network_latency_ms: 50, // Realistic WebRTC latency per hop
    };

    eprintln!("Configuration:");
    eprintln!("  Nodes: {}", config.node_count);
    eprintln!("  Duration: {:?}", config.duration);
    eprintln!("  Max peers: {}", config.max_peers);
    eprintln!("  Network latency: {}ms per hop", config.network_latency_ms);

    eprintln!("\nRunning simulation...");
    let start = std::time::Instant::now();
    let sim = Simulation::new(config);
    sim.run().await;
    eprintln!("Simulation completed in {:.2}s\n", start.elapsed().as_secs_f64());

    // Analyze topology
    let topology = sim.analyze_topology().await;
    Simulation::print_topology_stats(&topology);

    // Run benchmarks comparing flooding vs sequential
    eprintln!("\n=== Flooding vs Sequential Comparison ===");
    eprintln!("Testing with 1KB data, 20 requests each...\n");

    let (flooding, sequential) = sim.run_benchmarks(20, 1024, Duration::from_secs(3)).await;

    // Print detailed results
    flooding.print();
    eprintln!();
    sequential.print();

    // Summary comparison
    eprintln!("\n=== Strategy Comparison ===");
    eprintln!("                      Flooding    Sequential");
    eprintln!("Success rate:         {:6.1}%      {:6.1}%",
        flooding.success_rate * 100.0, sequential.success_rate * 100.0);
    eprintln!("Avg latency:          {:6.0}ms      {:6.0}ms",
        flooding.avg_latency_ms, sequential.avg_latency_ms);
    eprintln!("Avg bytes sent:       {:6.0}        {:6.0}",
        flooding.avg_bytes_sent, sequential.avg_bytes_sent);
    eprintln!("Avg bytes recv:       {:6.0}        {:6.0}",
        flooding.avg_bytes_received, sequential.avg_bytes_received);

    // Analysis
    eprintln!("\n=== Analysis ===");
    if flooding.success_rate > sequential.success_rate {
        eprintln!("Flooding has {:.1}% higher success rate (multi-hop routing reaches more nodes)",
            (flooding.success_rate - sequential.success_rate) * 100.0);
    }
    if sequential.avg_bytes_sent < flooding.avg_bytes_sent && sequential.success_rate > 0.0 {
        eprintln!("Sequential uses {:.0}x less bandwidth (queries one peer at a time)",
            flooding.avg_bytes_sent / sequential.avg_bytes_sent.max(1.0));
    }
    if sequential.avg_latency_ms > flooding.avg_latency_ms && sequential.success_rate > 0.0 {
        eprintln!("Sequential has {:.0}ms higher latency (waits for each NOT_FOUND before trying next)",
            sequential.avg_latency_ms - flooding.avg_latency_ms);
    }

    eprintln!("\nDone!");
}
