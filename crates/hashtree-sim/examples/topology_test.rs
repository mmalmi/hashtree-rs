//! Network topology formation testing
//!
//! Tests how different parameters affect network connectivity:
//! - Number of max peers per node
//! - Discovery interval
//! - Network size scaling
//! - Duration of simulation

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    eprintln!("=== Network Topology Formation Tests ===\n");

    // Test 1: How max_peers affects connectivity
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("TEST 1: Effect of max_peers on connectivity (100 nodes)");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    eprintln!("{:<12} {:>10} {:>12} {:>12} {:>10} {:>12}",
        "max_peers", "nodes", "connections", "components", "largest", "coverage%");
    eprintln!("{:-<12} {:->10} {:->12} {:->12} {:->10} {:->12}", "", "", "", "", "", "");

    for max_peers in [2, 3, 4, 6, 8, 10, 15, 20] {
        let config = SimConfig {
            node_count: 100,
            duration: Duration::from_secs(8),
            seed: 42,
            max_peers,
            discovery_interval_ms: 100,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 10,
            latency_variation: 0.3,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;
        let t = sim.analyze_topology().await;

        let coverage = if t.node_count > 0 {
            t.largest_component as f64 / t.node_count as f64 * 100.0
        } else {
            0.0
        };

        eprintln!("{:<12} {:>10} {:>12} {:>12} {:>10} {:>11.1}%",
            max_peers, t.node_count, t.connection_count, t.component_count,
            t.largest_component, coverage);
    }

    // Test 2: How discovery interval affects connectivity
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("TEST 2: Effect of discovery interval (100 nodes, max_peers=6)");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    eprintln!("{:<15} {:>10} {:>12} {:>12} {:>10} {:>12}",
        "interval_ms", "nodes", "connections", "components", "largest", "coverage%");
    eprintln!("{:-<15} {:->10} {:->12} {:->12} {:->10} {:->12}", "", "", "", "", "", "");

    for interval_ms in [50, 100, 200, 500, 1000] {
        let config = SimConfig {
            node_count: 100,
            duration: Duration::from_secs(10),
            seed: 42,
            max_peers: 6,
            discovery_interval_ms: interval_ms,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 10,
            latency_variation: 0.3,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;
        let t = sim.analyze_topology().await;

        let coverage = if t.node_count > 0 {
            t.largest_component as f64 / t.node_count as f64 * 100.0
        } else {
            0.0
        };

        eprintln!("{:<15} {:>10} {:>12} {:>12} {:>10} {:>11.1}%",
            interval_ms, t.node_count, t.connection_count, t.component_count,
            t.largest_component, coverage);
    }

    // Test 3: Scaling - how does network size affect connectivity?
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("TEST 3: Network scaling (max_peers=6, discovery=100ms)");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    eprintln!("{:<10} {:>10} {:>12} {:>12} {:>10} {:>12} {:>10}",
        "nodes", "duration", "connections", "components", "largest", "coverage%", "avg_deg");
    eprintln!("{:-<10} {:->10} {:->12} {:->12} {:->10} {:->12} {:->10}", "", "", "", "", "", "", "");

    for (node_count, duration_secs) in [(50, 5), (100, 8), (200, 12), (500, 20), (1000, 30)] {
        let config = SimConfig {
            node_count,
            duration: Duration::from_secs(duration_secs),
            seed: 42,
            max_peers: 6,
            discovery_interval_ms: 100,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 10,
            latency_variation: 0.3,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;
        let t = sim.analyze_topology().await;

        let coverage = if t.node_count > 0 {
            t.largest_component as f64 / t.node_count as f64 * 100.0
        } else {
            0.0
        };

        eprintln!("{:<10} {:>9}s {:>12} {:>12} {:>10} {:>11.1}% {:>9.1}",
            node_count, duration_secs, t.connection_count, t.component_count,
            t.largest_component, coverage, t.avg_degree);
    }

    // Test 4: Find optimal max_peers for large networks
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("TEST 4: Optimal max_peers for 500-node network");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    eprintln!("{:<12} {:>12} {:>12} {:>10} {:>12} {:>10}",
        "max_peers", "connections", "components", "largest", "coverage%", "cluster");
    eprintln!("{:-<12} {:->12} {:->12} {:->10} {:->12} {:->10}", "", "", "", "", "", "");

    let mut best_coverage = 0.0;
    let mut best_max_peers = 0;

    for max_peers in [4, 6, 8, 10, 12, 15, 20] {
        let config = SimConfig {
            node_count: 500,
            duration: Duration::from_secs(20),
            seed: 42,
            max_peers,
            discovery_interval_ms: 100,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 10,
            latency_variation: 0.3,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;
        let t = sim.analyze_topology().await;

        let coverage = if t.node_count > 0 {
            t.largest_component as f64 / t.node_count as f64 * 100.0
        } else {
            0.0
        };

        if coverage > best_coverage {
            best_coverage = coverage;
            best_max_peers = max_peers;
        }

        eprintln!("{:<12} {:>12} {:>12} {:>10} {:>11.1}% {:>9.3}",
            max_peers, t.connection_count, t.component_count,
            t.largest_component, coverage, t.clustering_coefficient);
    }

    eprintln!("\n  → Best: max_peers={} achieves {:.1}% coverage", best_max_peers, best_coverage);

    // Test 5: Benchmark data transfer with optimal settings
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("TEST 5: Data transfer benchmark (500 nodes, max_peers={})", best_max_peers);
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let config = SimConfig {
        node_count: 500,
        duration: Duration::from_secs(20),
        seed: 42,
        max_peers: best_max_peers,
        discovery_interval_ms: 100,
        churn_rate: 0.0,
        allow_rejoin: false,
        network_latency_ms: 50,
        latency_variation: 0.3,
        routing_strategy: RoutingStrategy::Flooding,
    };

    let sim = Simulation::new(config);
    sim.run().await;

    let t = sim.analyze_topology().await;
    eprintln!("Network: {} nodes, {} connections, {:.1}% in largest component",
        t.node_count, t.connection_count,
        t.largest_component as f64 / t.node_count as f64 * 100.0);
    eprintln!("Avg degree: {:.1}, Clustering: {:.3}\n", t.avg_degree, t.clustering_coefficient);

    eprintln!("Running 100 benchmark requests (1KB data)...");
    let results = sim.run_benchmark(100, 1024, Duration::from_secs(5)).await;
    eprintln!();
    results.print();

    // Summary
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("SUMMARY: Recommended settings for maximum connectivity");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    eprintln!("  max_peers:          {} (higher = more connections, more bandwidth)", best_max_peers);
    eprintln!("  discovery_interval: 100ms (faster discovery, more relay traffic)");
    eprintln!("  routing_strategy:   Flooding (parallel requests, lower latency)");
    eprintln!("\n  For bandwidth-constrained networks:");
    eprintln!("  max_peers:          4-6 (fewer connections)");
    eprintln!("  discovery_interval: 500ms (less relay traffic)");
    eprintln!("  routing_strategy:   Sequential (less bandwidth per request)");

    eprintln!("\nDone!");
}
