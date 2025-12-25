//! Run a network simulation with benchmarks
//!
//! Tests the full stack: HashTree<FloodingStore> for content operations + P2P networking
//! Compares Flooding vs Adaptive routing strategies (both use multi-hop forwarding).
//!
//! Usage: cargo run --example run_simulation -- [OPTIONS]
//!   --nodes N       Number of nodes (default: 20)
//!   --duration S    Simulation duration in seconds (default: 5)
//!   --requests N    Number of benchmark requests (default: 10)
//!   --latency MS    Network latency per hop in ms (default: 10)

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

fn parse_arg(args: &[String], flag: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let node_count = parse_arg(&args, "--nodes", 20) as usize;
    let duration_secs = parse_arg(&args, "--duration", 5);
    let num_requests = parse_arg(&args, "--requests", 10) as usize;
    let latency_ms = parse_arg(&args, "--latency", 10);

    eprintln!("=== Network Simulation ===\n");

    // Base configuration (same seed for fair comparison)
    let base_config = SimConfig {
        node_count,
        duration: Duration::from_secs(duration_secs),
        seed: 42,
        max_peers: 8, // Higher for better connectivity (1 component)
        discovery_interval_ms: 100,
        churn_rate: 0.0,
        allow_rejoin: false,
        network_latency_ms: latency_ms,
        latency_variation: 0.3, // ±30% variation per link
        routing_strategy: RoutingStrategy::Flooding, // Will be overridden
    };

    eprintln!("Configuration:");
    eprintln!("  Nodes: {}", base_config.node_count);
    eprintln!("  Duration: {:?}", base_config.duration);
    eprintln!("  Requests: {}", num_requests);
    eprintln!("  Max peers: {}", base_config.max_peers);
    eprintln!("  Network latency: {}ms ±{:.0}% per link",
        base_config.network_latency_ms,
        base_config.latency_variation * 100.0);

    // Build ONE network and test both strategies on it (same topology = fair comparison)
    eprintln!("\n=== Building Network ===");
    let sim = Simulation::new(base_config);
    sim.run().await;

    let topology = sim.analyze_topology().await;
    eprintln!("Nodes: {}, Connections: {}, Components: {}",
        topology.node_count, topology.connection_count, topology.component_count);

    // Long timeout to ensure failures are due to unreachability, not timing
    let request_timeout = Duration::from_secs(10);

    // Test flooding strategy on this network (parallel requests = realistic load)
    eprintln!("\n=== Running Flooding Benchmark ===");
    sim.set_routing_strategy(RoutingStrategy::Flooding).await;
    let flooding = sim.run_benchmark_parallel("Flooding", num_requests, 1024, request_timeout).await;

    // Test adaptive strategy on SAME network
    eprintln!("\n=== Running Adaptive Benchmark ===");
    sim.set_routing_strategy(RoutingStrategy::Adaptive).await;
    let adaptive = sim.run_benchmark_parallel("Adaptive", num_requests, 1024, request_timeout).await;

    // Print detailed results
    eprintln!("\n=== Flooding vs Adaptive Comparison ===");
    flooding.print();
    eprintln!();
    adaptive.print();

    // Summary comparison
    eprintln!("\n=== Strategy Comparison ===");
    eprintln!("                      Flooding    Adaptive");
    eprintln!("Success rate:         {:6.1}%      {:6.1}%",
        flooding.success_rate * 100.0, adaptive.success_rate * 100.0);
    eprintln!("Avg latency:          {:6.0}ms      {:6.0}ms",
        flooding.avg_latency_ms, adaptive.avg_latency_ms);
    eprintln!("Avg bytes sent:       {:6.0}        {:6.0}",
        flooding.avg_bytes_sent, adaptive.avg_bytes_sent);
    eprintln!("Avg bytes recv:       {:6.0}        {:6.0}",
        flooding.avg_bytes_received, adaptive.avg_bytes_received);

    // Analysis
    eprintln!("\n=== Analysis ===");
    eprintln!("Flooding: Query all peers simultaneously, first response wins");
    eprintln!("Adaptive: Try best peer first (learned), fallback on failure (Freenet-style)");
    eprintln!();

    if flooding.success_rate > adaptive.success_rate + 0.05 {
        eprintln!("Flooding has {:.1}% higher success rate (parallel exploration)",
            (flooding.success_rate - adaptive.success_rate) * 100.0);
    } else if adaptive.success_rate > flooding.success_rate + 0.05 {
        eprintln!("Adaptive has {:.1}% higher success rate (smart peer selection)",
            (adaptive.success_rate - flooding.success_rate) * 100.0);
    } else {
        eprintln!("Similar success rates ({:.1}% vs {:.1}%)",
            flooding.success_rate * 100.0, adaptive.success_rate * 100.0);
    }

    if adaptive.avg_bytes_sent < flooding.avg_bytes_sent * 0.8 && adaptive.success_rate > 0.5 {
        eprintln!("Adaptive uses {:.1}x less bandwidth (queries fewer peers)",
            flooding.avg_bytes_sent / adaptive.avg_bytes_sent.max(1.0));
    }

    eprintln!("\nDone!");
}
