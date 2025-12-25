//! Large scale benchmark: flooding vs adaptive routing

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    for node_count in [50, 100, 200] {
        eprintln!("\n============================================================");
        eprintln!("=== {} Node Network ===", node_count);
        eprintln!("============================================================\n");

        // Base config (same seed for fair comparison)
        let base_config = SimConfig {
            node_count,
            duration: Duration::from_secs(10),
            seed: 42,
            max_peers: 6,
            discovery_interval_ms: 100,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 50,
            latency_variation: 0.3, // ±30% variation per link
            routing_strategy: RoutingStrategy::Flooding, // Will be overridden
        };

        // Run flooding simulation
        eprintln!("Building flooding network...");
        let flooding_config = SimConfig {
            routing_strategy: RoutingStrategy::Flooding,
            ..base_config
        };
        let flooding_sim = Simulation::new(flooding_config);
        flooding_sim.run().await;

        let topology = flooding_sim.analyze_topology().await;
        eprintln!("Topology: {} nodes, {} connections, {} components (largest: {})",
            topology.node_count, topology.connection_count,
            topology.component_count, topology.largest_component);
        eprintln!("Avg degree: {:.1}, clustering: {:.3}",
            topology.avg_degree, topology.clustering_coefficient);

        eprintln!("\nRunning 50 flooding benchmark requests (1KB data)...");
        let flooding = flooding_sim.run_benchmark(50, 1024, Duration::from_secs(5)).await;

        // Run adaptive simulation (Freenet-style)
        eprintln!("Building adaptive network...");
        let adaptive_config = SimConfig {
            routing_strategy: RoutingStrategy::Adaptive,
            ..base_config
        };
        let adaptive_sim = Simulation::new(adaptive_config);
        adaptive_sim.run().await;

        eprintln!("Running 50 adaptive benchmark requests (1KB data)...");
        let adaptive = adaptive_sim.run_benchmark(50, 1024, Duration::from_secs(5)).await;

        eprintln!("\n{:<20} {:>12} {:>12}", "", "Flooding", "Adaptive");
        eprintln!("{:-<20} {:->12} {:->12}", "", "", "");
        eprintln!("{:<20} {:>11.1}% {:>11.1}%", "Success rate",
            flooding.success_rate * 100.0, adaptive.success_rate * 100.0);
        eprintln!("{:<20} {:>11.0}ms {:>11.0}ms", "Avg latency",
            flooding.avg_latency_ms, adaptive.avg_latency_ms);
        eprintln!("{:<20} {:>12.0} {:>12.0}", "Bytes sent",
            flooding.avg_bytes_sent, adaptive.avg_bytes_sent);
        eprintln!("{:<20} {:>12.0} {:>12.0}", "Bytes recv",
            flooding.avg_bytes_received, adaptive.avg_bytes_received);
    }

    eprintln!("\nDone!");
}
