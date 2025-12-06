//! Run a network simulation with benchmarks
//!
//! Tests the full stack: HashTree<FloodingStore> for content operations + P2P networking
//! Compares flooding vs sequential routing strategies.

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    eprintln!("=== Network Simulation ===\n");

    // Base configuration (same seed for fair comparison)
    // Note: 30s duration gives network time to form connections
    // With 50 nodes, max_peers=5, we get ~85% in largest component
    let base_config = SimConfig {
        node_count: 50,
        duration: Duration::from_secs(30),
        seed: 42,
        max_peers: 10, // Good balance for demonstration
        discovery_interval_ms: 200,
        churn_rate: 0.0,
        allow_rejoin: false,
        network_latency_ms: 50, // Realistic WebRTC latency per hop
        routing_strategy: RoutingStrategy::Flooding, // Will be overridden
    };

    eprintln!("Configuration:");
    eprintln!("  Nodes: {}", base_config.node_count);
    eprintln!("  Duration: {:?}", base_config.duration);
    eprintln!("  Max peers: {}", base_config.max_peers);
    eprintln!("  Network latency: {}ms per hop", base_config.network_latency_ms);

    // Run flooding simulation
    eprintln!("\n=== Running Flooding Simulation ===");
    let flooding_config = SimConfig {
        routing_strategy: RoutingStrategy::Flooding,
        ..base_config
    };
    let flooding_sim = Simulation::new(flooding_config);
    flooding_sim.run().await;
    let flooding_topology = flooding_sim.analyze_topology().await;
    // 30 requests with 5s timeout (enough for multi-hop with 50ms latency)
    let flooding = flooding_sim.run_benchmark(30, 1024, Duration::from_secs(5)).await;

    // Run sequential simulation (same topology seed)
    eprintln!("\n=== Running Sequential Simulation ===");
    let sequential_config = SimConfig {
        routing_strategy: RoutingStrategy::Sequential,
        ..base_config
    };
    let sequential_sim = Simulation::new(sequential_config);
    sequential_sim.run().await;
    let sequential = sequential_sim.run_benchmark(30, 1024, Duration::from_secs(5)).await;

    // Print topology (same for both since same seed)
    eprintln!("\n=== Topology (shared) ===");
    Simulation::print_topology_stats(&flooding_topology);

    // Print detailed results
    eprintln!("\n=== Flooding vs Sequential Comparison ===");
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
    eprintln!("Flooding: Multi-hop forwarding, parallel requests to all peers");
    eprintln!("Sequential: Single-hop only, tries peers one at a time (500ms timeout)");
    eprintln!();
    if flooding.success_rate > sequential.success_rate {
        eprintln!("Flooding has {:.1}% higher success rate (can reach multi-hop neighbors)",
            (flooding.success_rate - sequential.success_rate) * 100.0);
    }
    if sequential.avg_bytes_sent < flooding.avg_bytes_sent && sequential.success_rate > 0.0 {
        eprintln!("Sequential uses {:.0}x less bandwidth (single-hop, one peer at a time)",
            flooding.avg_bytes_sent / sequential.avg_bytes_sent.max(1.0));
    }
    if sequential.avg_latency_ms < flooding.avg_latency_ms && sequential.success_rate > 0.0 {
        eprintln!("Sequential is {:.0}ms faster when data is on direct neighbor",
            flooding.avg_latency_ms - sequential.avg_latency_ms);
    } else if sequential.avg_latency_ms > flooding.avg_latency_ms && sequential.success_rate > 0.0 {
        eprintln!("Sequential has {:.0}ms higher latency (waits for timeout before trying next)",
            sequential.avg_latency_ms - flooding.avg_latency_ms);
    }

    eprintln!("\nDone!");
}
