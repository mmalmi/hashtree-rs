//! Test with simulated network latency

use hashtree_sim::{RoutingStrategy, SimConfig, Simulation};
use std::time::Duration;

#[tokio::main]
async fn main() {
    eprintln!("=== Latency Simulation Test ===\n");

    let config = SimConfig {
        node_count: 10,
        duration: Duration::from_secs(3),
        seed: 42,
        max_peers: 4,
        discovery_interval_ms: 100,
        churn_rate: 0.0,
        allow_rejoin: false,
        network_latency_ms: 25, // 25ms per hop
        routing_strategy: RoutingStrategy::Flooding,
    };

    eprintln!("Running simulation with {}ms latency per hop...", config.network_latency_ms);
    let sim = Simulation::new(config);
    sim.run().await;

    let topology = sim.analyze_topology().await;
    eprintln!("\nTopology: {} nodes, {} connections, {} components",
        topology.node_count, topology.connection_count, topology.component_count);

    eprintln!("\n=== Running 10 benchmark requests ===");
    let flooding = sim.run_benchmark(10, 256, Duration::from_secs(2)).await;
    eprintln!("\n");

    flooding.print();

    eprintln!("\nExpected latency with 25ms per hop:");
    eprintln!("  Direct peer: ~50ms (request + response)");
    eprintln!("  2-hop: ~100ms");
    eprintln!("  3-hop: ~150ms");
}
