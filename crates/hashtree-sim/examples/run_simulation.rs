//! Run a network simulation with benchmarks
//!
//! Tests the full stack: HashTree<FloodingStore> for content operations + P2P networking
//! Compares Flooding vs Adaptive routing strategies (both use multi-hop forwarding).
//!
//! Usage: cargo run --example run_simulation -- [OPTIONS]
//!   --nodes N       Number of nodes (default: 20)
//!   --duration S    Simulation duration in seconds (default: 5)
//!   --requests N    Number of requests per node in burst mode (default: 10)
//!   --latency MS    Network latency per hop in ms (default: 10)
//!   --runs N        Number of runs for variance analysis (default: 1)
//!   --waves N       Number of waves (0=burst mode, >0=wave mode, default: 0)
//!   --per-wave N    Requests per wave (default: 10)
//!   --wave-gap MS   Gap between waves in ms (default: 500)

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

fn parse_arg(args: &[String], flag: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Stats from a single run
struct RunStats {
    flooding_success: f64,
    flooding_latency: f64,
    adaptive_success: f64,
    adaptive_latency: f64,
}

/// Print variance analysis
fn print_variance(runs: &[RunStats]) {
    if runs.is_empty() {
        return;
    }

    let n = runs.len() as f64;

    // Calculate means
    let f_success_mean: f64 = runs.iter().map(|r| r.flooding_success).sum::<f64>() / n;
    let f_latency_mean: f64 = runs.iter().map(|r| r.flooding_latency).sum::<f64>() / n;
    let a_success_mean: f64 = runs.iter().map(|r| r.adaptive_success).sum::<f64>() / n;
    let a_latency_mean: f64 = runs.iter().map(|r| r.adaptive_latency).sum::<f64>() / n;

    // Calculate stddev
    let f_success_std = (runs.iter().map(|r| (r.flooding_success - f_success_mean).powi(2)).sum::<f64>() / n).sqrt();
    let f_latency_std = (runs.iter().map(|r| (r.flooding_latency - f_latency_mean).powi(2)).sum::<f64>() / n).sqrt();
    let a_success_std = (runs.iter().map(|r| (r.adaptive_success - a_success_mean).powi(2)).sum::<f64>() / n).sqrt();
    let a_latency_std = (runs.iter().map(|r| (r.adaptive_latency - a_latency_mean).powi(2)).sum::<f64>() / n).sqrt();

    // Min/max
    let f_success_min = runs.iter().map(|r| r.flooding_success).fold(f64::INFINITY, f64::min);
    let f_success_max = runs.iter().map(|r| r.flooding_success).fold(f64::NEG_INFINITY, f64::max);
    let a_success_min = runs.iter().map(|r| r.adaptive_success).fold(f64::INFINITY, f64::min);
    let a_success_max = runs.iter().map(|r| r.adaptive_success).fold(f64::NEG_INFINITY, f64::max);

    eprintln!("\n=== Variance Analysis ({} runs) ===", runs.len());
    eprintln!("                        Flooding              Adaptive");
    eprintln!("Success rate:    {:5.1}% ± {:4.1}%         {:5.1}% ± {:4.1}%",
        f_success_mean * 100.0, f_success_std * 100.0,
        a_success_mean * 100.0, a_success_std * 100.0);
    eprintln!("  range:         [{:4.0}% - {:4.0}%]        [{:4.0}% - {:4.0}%]",
        f_success_min * 100.0, f_success_max * 100.0,
        a_success_min * 100.0, a_success_max * 100.0);
    eprintln!("Avg latency:     {:5.0}ms ± {:4.0}ms        {:5.0}ms ± {:4.0}ms",
        f_latency_mean, f_latency_std,
        a_latency_mean, a_latency_std);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let node_count = parse_arg(&args, "--nodes", 20) as usize;
    let duration_secs = parse_arg(&args, "--duration", 5);
    let num_requests = parse_arg(&args, "--requests", 10) as usize;
    let latency_ms = parse_arg(&args, "--latency", 10);
    let num_runs = parse_arg(&args, "--runs", 1) as usize;
    let wave_count = parse_arg(&args, "--waves", 0) as usize;
    let use_waves = wave_count > 0;
    let per_wave = parse_arg(&args, "--per-wave", 10) as usize;
    let wave_gap_ms = parse_arg(&args, "--wave-gap", 500);

    eprintln!("=== Network Simulation ===\n");

    eprintln!("Configuration:");
    eprintln!("  Nodes: {}", node_count);
    eprintln!("  Duration: {}s", duration_secs);
    if use_waves {
        eprintln!("  Mode: Waves ({} waves × {} requests, {}ms gaps)", wave_count, per_wave, wave_gap_ms);
    } else {
        eprintln!("  Mode: Burst ({} requests per node)", num_requests);
    }
    eprintln!("  Network latency: {}ms ±30% per link", latency_ms);
    if num_runs > 1 {
        eprintln!("  Runs: {}", num_runs);
    }

    let mut all_runs: Vec<RunStats> = Vec::new();

    for run in 0..num_runs {
        if num_runs > 1 {
            eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("RUN {}/{}", run + 1, num_runs);
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }

        // Different seed per run for variance
        let seed = 42 + run as u64;

        // Use higher max_peers for smaller networks to ensure full connectivity
        let max_peers = if node_count <= 20 { 10 } else if node_count <= 50 { 8 } else { 6 };

        let config = SimConfig {
            node_count,
            duration: Duration::from_secs(duration_secs),
            seed,
            max_peers,
            discovery_interval_ms: 50, // Faster discovery
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: latency_ms,
            latency_variation: 0.3,
            routing_strategy: RoutingStrategy::Flooding,
        };

        // Build network - keep running until we have 1 component
        eprintln!("\n=== Building Network ===");
        let sim = Simulation::new(config.clone());
        sim.run().await;

        let mut topology = sim.analyze_topology().await;
        let mut extra_rounds = 0;
        while topology.component_count > 1 && extra_rounds < 20 {
            // Run more discovery rounds
            for _ in 0..50 {
                sim.run_discovery_round().await;
            }
            topology = sim.analyze_topology().await;
            extra_rounds += 1;
        }

        eprintln!("Nodes: {}, Connections: {}, Components: {}",
            topology.node_count, topology.connection_count, topology.component_count);

        if topology.component_count > 1 {
            eprintln!("  Warning: Network has {} disconnected components", topology.component_count);
        }

        let request_timeout = Duration::from_secs(30);

        let wave_gap = Duration::from_millis(wave_gap_ms);

        // Test flooding
        eprintln!("\n=== Flooding Benchmark ===");
        sim.set_routing_strategy(RoutingStrategy::Flooding).await;
        let flooding = if use_waves {
            sim.run_benchmark_waves("Flooding", wave_count, per_wave, 1024, request_timeout, wave_gap).await
        } else {
            sim.run_benchmark_burst("Flooding", num_requests, 1024, request_timeout).await
        };

        // Test adaptive
        eprintln!("\n=== Adaptive Benchmark ===");
        sim.set_routing_strategy(RoutingStrategy::Adaptive).await;
        let adaptive = if use_waves {
            sim.run_benchmark_waves("Adaptive", wave_count, per_wave, 1024, request_timeout, wave_gap).await
        } else {
            sim.run_benchmark_burst("Adaptive", num_requests, 1024, request_timeout).await
        };

        // Store stats
        all_runs.push(RunStats {
            flooding_success: flooding.success_rate,
            flooding_latency: flooding.avg_latency_ms,
            adaptive_success: adaptive.success_rate,
            adaptive_latency: adaptive.avg_latency_ms,
        });

        // Print summary for this run
        if num_runs == 1 {
            eprintln!("\n=== Results ===");
            eprintln!("                      Flooding    Adaptive");
            eprintln!("Success rate:         {:6.1}%      {:6.1}%",
                flooding.success_rate * 100.0, adaptive.success_rate * 100.0);
            eprintln!("Avg latency:          {:6.0}ms      {:6.0}ms",
                flooding.avg_latency_ms, adaptive.avg_latency_ms);
        }
    }

    // Print variance analysis if multiple runs
    if num_runs > 1 {
        print_variance(&all_runs);
    }

    eprintln!("\nDone!");
}
