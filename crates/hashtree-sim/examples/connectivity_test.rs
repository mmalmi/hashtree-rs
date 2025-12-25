use hashtree_sim::{PoolConfig, SimConfig, Simulation, RoutingStrategy};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nodes: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let max_conn: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
    let satisfied: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);

    println!("Testing {nodes} nodes, {runs} runs, max={max_conn}, satisfied={satisfied}");
    
    for run in 1..=runs {
        let config = SimConfig {
            node_count: nodes,
            duration: Duration::from_secs(5),
            seed: 42 + run as u64,
            pool: PoolConfig { max_connections: max_conn, satisfied_connections: satisfied },
            discovery_interval_ms: 50,
            churn_rate: 0.0,
            allow_rejoin: false,
            network_latency_ms: 0,
            latency_variation: 0.0,
            routing_strategy: RoutingStrategy::Flooding,
        };

        let sim = Simulation::new(config);
        sim.run().await;
        
        // Extra discovery rounds if needed
        let mut topo = sim.analyze_topology().await;
        let mut extra = 0;
        while topo.component_count > 1 && extra < 10 {
            sim.run_discovery_round().await;
            topo = sim.analyze_topology().await;
            extra += 1;
        }
        
        println!("Run {run}: {nodes} nodes, {} connections, {} components, {extra} extra rounds",
            topo.connection_count, topo.component_count);
    }
}
