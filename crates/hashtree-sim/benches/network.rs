//! Network simulation benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hashtree_sim::{Network, SimConfig, LatencyDistribution};

fn bench_small_network(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_network");

    group.bench_function("initialize_20_nodes", |b| {
        b.iter(|| {
            let config = SimConfig::small();
            let mut network = Network::new(config);
            network.initialize();
            black_box(network.node_count())
        })
    });

    group.bench_function("run_50_requests", |b| {
        b.iter(|| {
            let config = SimConfig::small();
            let mut network = Network::new(config);
            network.initialize();
            network.schedule_random_requests(50);
            let metrics = network.run(10000);
            black_box(metrics.total_requests)
        })
    });

    group.finish();
}

fn bench_medium_network(c: &mut Criterion) {
    let mut group = c.benchmark_group("medium_network");
    group.sample_size(20); // Fewer samples for slower benchmarks

    group.bench_function("initialize_100_nodes", |b| {
        b.iter(|| {
            let config = SimConfig::medium();
            let mut network = Network::new(config);
            network.initialize();
            black_box(network.node_count())
        })
    });

    group.bench_function("run_200_requests", |b| {
        b.iter(|| {
            let config = SimConfig::medium();
            let mut network = Network::new(config);
            network.initialize();
            network.schedule_random_requests(200);
            let metrics = network.run(20000);
            black_box(metrics.total_requests)
        })
    });

    group.finish();
}

fn bench_adversarial_network(c: &mut Criterion) {
    let mut group = c.benchmark_group("adversarial_network");
    group.sample_size(20);

    group.bench_function("run_100_requests_with_adversaries", |b| {
        b.iter(|| {
            let config = SimConfig::adversarial();
            let mut network = Network::new(config);
            network.initialize();
            network.schedule_random_requests(100);
            let metrics = network.run(10000);
            black_box((metrics.successful_requests, metrics.corrupted_responses))
        })
    });

    group.finish();
}

fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");
    group.sample_size(10);

    for node_count in [50, 100, 200, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("nodes", node_count),
            node_count,
            |b, &count| {
                b.iter(|| {
                    let config = SimConfig {
                        node_count: count,
                        peers_per_node: 5,
                        latency: LatencyDistribution::Fixed { ms: 10 },
                        content_count: count * 10,
                        seed: Some(42),
                        ..Default::default()
                    };
                    let mut network = Network::new(config);
                    network.initialize();
                    network.schedule_random_requests(count);
                    let metrics = network.run(30000);
                    black_box(metrics.success_rate())
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_small_network,
    bench_medium_network,
    bench_adversarial_network,
    bench_scalability,
);

criterion_main!(benches);
