//! TreeBuilder benchmark comparing CBOR vs Binary merkle algorithms
//!
//! Run with: cargo bench -p hashtree

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hashtree::{
    BuilderConfig, MerkleAlgorithm, MemoryStore, Store, TreeBuilder, TreeReader,
    BEP52_CHUNK_SIZE, DEFAULT_CHUNK_SIZE,
};
use std::sync::Arc;

/// Generate random data
fn random_data(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Benchmark TreeBuilder with different configurations
fn bench_tree_builder(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("tree_builder");

    let sizes = [
        (1, "1MB"),
        (10, "10MB"),
        (50, "50MB"),
    ];

    let configs: Vec<(&str, usize, MerkleAlgorithm)> = vec![
        ("256KB_cbor", DEFAULT_CHUNK_SIZE, MerkleAlgorithm::Cbor),
        ("256KB_binary", DEFAULT_CHUNK_SIZE, MerkleAlgorithm::Binary),
        ("16KB_cbor", BEP52_CHUNK_SIZE, MerkleAlgorithm::Cbor),
        ("16KB_binary", BEP52_CHUNK_SIZE, MerkleAlgorithm::Binary),
    ];

    for (size_mb, size_name) in sizes {
        let size = size_mb * 1024 * 1024;
        let data = random_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        for (config_name, chunk_size, algorithm) in &configs {
            group.bench_with_input(
                BenchmarkId::new(*config_name, size_name),
                &data,
                |b, data| {
                    b.iter(|| {
                        rt.block_on(async {
                            let store = Arc::new(MemoryStore::new());
                            let config = BuilderConfig::new(store)
                                .with_chunk_size(*chunk_size)
                                .with_merkle_algorithm(*algorithm);
                            let builder = TreeBuilder::new(config);
                            builder.put_file(black_box(data)).await.unwrap()
                        })
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark TreeReader for CBOR trees
fn bench_tree_reader(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("tree_reader");

    let sizes = [
        (1, "1MB"),
        (10, "10MB"),
    ];

    let chunk_sizes = [
        ("256KB", DEFAULT_CHUNK_SIZE),
        ("16KB", BEP52_CHUNK_SIZE),
    ];

    for (size_mb, size_name) in sizes {
        let size = size_mb * 1024 * 1024;
        let data = random_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        for (chunk_name, chunk_size) in &chunk_sizes {
            // Pre-build the tree
            let (store, hash) = rt.block_on(async {
                let store = Arc::new(MemoryStore::new());
                let config = BuilderConfig::new(store.clone())
                    .with_chunk_size(*chunk_size)
                    .with_merkle_algorithm(MerkleAlgorithm::Cbor);
                let builder = TreeBuilder::new(config);
                let result = builder.put_file(&data).await.unwrap();
                (store, result.hash)
            });

            group.bench_with_input(
                BenchmarkId::new(*chunk_name, size_name),
                &(store.clone(), hash),
                |b, (store, hash)| {
                    b.iter(|| {
                        rt.block_on(async {
                            let reader = TreeReader::new(store.clone());
                            reader.read_file(black_box(hash)).await.unwrap()
                        })
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark write+read roundtrip
fn bench_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("roundtrip");

    let size = 10 * 1024 * 1024; // 10 MB
    let data = random_data(size);
    group.throughput(Throughput::Bytes(size as u64));

    // CBOR algorithm (supports read)
    for (name, chunk_size) in [("256KB", DEFAULT_CHUNK_SIZE), ("16KB", BEP52_CHUNK_SIZE)] {
        group.bench_with_input(
            BenchmarkId::new(format!("{}_cbor", name), "10MB"),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = BuilderConfig::new(store.clone())
                            .with_chunk_size(chunk_size)
                            .with_merkle_algorithm(MerkleAlgorithm::Cbor);
                        let builder = TreeBuilder::new(config);
                        let result = builder.put_file(black_box(data)).await.unwrap();

                        let reader = TreeReader::new(store);
                        reader.read_file(&result.hash).await.unwrap()
                    })
                })
            },
        );
    }

    // Binary algorithm (read via leaf hashes)
    for (name, chunk_size) in [("256KB", DEFAULT_CHUNK_SIZE), ("16KB", BEP52_CHUNK_SIZE)] {
        group.bench_with_input(
            BenchmarkId::new(format!("{}_binary", name), "10MB"),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = BuilderConfig::new(store.clone())
                            .with_chunk_size(chunk_size)
                            .with_merkle_algorithm(MerkleAlgorithm::Binary);
                        let builder = TreeBuilder::new(config);
                        let result = builder.put_file(black_box(data)).await.unwrap();

                        // Read using leaf hashes (binary mode)
                        let mut output = Vec::with_capacity(data.len());
                        for hash in &result.leaf_hashes {
                            if let Some(chunk) = store.get(hash).await.unwrap() {
                                output.extend_from_slice(&chunk);
                            }
                        }
                        output
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_tree_builder,
    bench_tree_reader,
    bench_roundtrip,
);

criterion_main!(benches);
