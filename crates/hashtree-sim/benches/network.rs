//! Network store benchmarks
//!
//! Compare FloodingStore vs SequentialStore with different peer counts.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hashtree_sim::{
    FloodingStore, MockChannel, NetworkStore, PeerChannel, SequentialStore, SimStore, Store,
    flooding_handle_request, sequential_handle_request,
};
use std::sync::Arc;
use std::time::Duration;

/// Setup a network of nodes with one node having the data
async fn setup_flooding_network(
    peer_count: usize,
    data: &[u8],
) -> (Arc<FloodingStore>, Vec<tokio::task::JoinHandle<()>>) {
    let hash = hashtree::sha256(data);

    // Requester node
    let local = Arc::new(SimStore::new(0));
    let store = Arc::new(FloodingStore::new(local, Duration::from_secs(5)));

    // Peer nodes - last one has the data
    let mut handles = Vec::new();
    for i in 0..peer_count {
        let peer_local = Arc::new(SimStore::new(i as u64 + 1));
        if i == peer_count - 1 {
            // Last peer has the data
            peer_local.put_local(hash, data.to_vec());
        }

        let (chan_req, chan_peer) = MockChannel::pair(0, i as u64 + 1);
        store.add_peer(Arc::new(chan_req)).await;

        // Spawn handler
        let peer_local_clone = peer_local.clone();
        handles.push(tokio::spawn(async move {
            loop {
                match chan_peer.recv(Duration::from_secs(10)).await {
                    Ok(bytes) => {
                        if let Some(response) = flooding_handle_request(&peer_local_clone, &bytes).await {
                            let _ = chan_peer.send(response).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    (store, handles)
}

async fn setup_sequential_network(
    peer_count: usize,
    data: &[u8],
) -> (Arc<SequentialStore>, Vec<tokio::task::JoinHandle<()>>) {
    let hash = hashtree::sha256(data);

    let local = Arc::new(SimStore::new(0));
    let store = Arc::new(SequentialStore::new(local, Duration::from_secs(5)));

    let mut handles = Vec::new();
    for i in 0..peer_count {
        let peer_local = Arc::new(SimStore::new(i as u64 + 1));
        if i == peer_count - 1 {
            peer_local.put_local(hash, data.to_vec());
        }

        let (chan_req, chan_peer) = MockChannel::pair(0, i as u64 + 1);
        store.add_peer(Arc::new(chan_req)).await;

        let peer_local_clone = peer_local.clone();
        handles.push(tokio::spawn(async move {
            loop {
                match chan_peer.recv(Duration::from_secs(10)).await {
                    Ok(bytes) => {
                        if let Some(response) = sequential_handle_request(&peer_local_clone, &bytes).await {
                            let _ = chan_peer.send(response).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    (store, handles)
}

fn bench_flooding_vs_sequential(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("routing_strategy");

    let data = vec![0u8; 1024]; // 1KB data
    let hash = hashtree::sha256(&data);

    for peer_count in [2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::new("flooding", peer_count),
            &peer_count,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let (store, handles) = setup_flooding_network(count, &data).await;
                    let result = Store::get(&*store, &hash).await.unwrap();
                    for h in handles {
                        h.abort();
                    }
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sequential", peer_count),
            &peer_count,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let (store, handles) = setup_sequential_network(count, &data).await;
                    let result = Store::get(&*store, &hash).await.unwrap();
                    for h in handles {
                        h.abort();
                    }
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_bandwidth(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("bandwidth");

    let data = vec![0u8; 1024];
    let hash = hashtree::sha256(&data);
    let peer_count = 5;

    group.bench_function("flooding_bandwidth", |b| {
        b.to_async(&rt).iter(|| async {
            let (store, handles) = setup_flooding_network(peer_count, &data).await;
            let _ = Store::get(&*store, &hash).await;
            let sent = store.bytes_sent();
            let recv = store.bytes_received();
            for h in handles {
                h.abort();
            }
            black_box((sent, recv))
        });
    });

    group.bench_function("sequential_bandwidth", |b| {
        b.to_async(&rt).iter(|| async {
            let (store, handles) = setup_sequential_network(peer_count, &data).await;
            let _ = Store::get(&*store, &hash).await;
            let sent = store.bytes_sent();
            let recv = store.bytes_received();
            for h in handles {
                h.abort();
            }
            black_box((sent, recv))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_flooding_vs_sequential, bench_bandwidth);
criterion_main!(benches);
