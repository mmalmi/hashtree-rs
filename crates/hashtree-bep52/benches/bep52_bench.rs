//! Benchmarks comparing BEP52 tree building performance
//!
//! BEP52 uses 16KB blocks vs default hashtree's 256KB,
//! resulting in ~16x more blocks and hashing operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hashtree_bep52::{
    Bep52Config, Bep52TreeBuilder, MemoryStore,
    merkle_root, merkle_build_tree, merkle_hash_pair, BEP52_BLOCK_SIZE,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Generate random data
fn random_data(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Hash a block with SHA256
fn hash_block(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Benchmark raw SHA256 hashing (baseline)
fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [16 * 1024, 256 * 1024, 1024 * 1024] {
        let data = random_data(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &data,
            |b, data| {
                b.iter(|| hash_block(black_box(data)))
            },
        );
    }

    group.finish();
}

/// Benchmark merkle hash pair (combining two hashes)
fn bench_merkle_hash_pair(c: &mut Criterion) {
    let left = [1u8; 32];
    let right = [2u8; 32];

    c.bench_function("merkle_hash_pair", |b| {
        b.iter(|| merkle_hash_pair(black_box(&left), black_box(&right)))
    });
}

/// Benchmark merkle root computation
fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_root");

    for num_leaves in [4, 16, 64, 256, 1024] {
        let leaves: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                hash
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_leaves),
            &leaves,
            |b, leaves| {
                b.iter(|| merkle_root(black_box(leaves), None))
            },
        );
    }

    group.finish();
}

/// Benchmark full tree building
fn bench_merkle_build_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_build_tree");

    for num_leaves in [4, 16, 64, 256] {
        let leaves: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                hash
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_leaves),
            &leaves,
            |b, leaves| {
                b.iter(|| merkle_build_tree(black_box(leaves)))
            },
        );
    }

    group.finish();
}

/// Benchmark BEP52 tree builder with MemoryStore
fn bench_bep52_builder(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("bep52_builder");

    for size_mb in [1, 5, 10] {
        let size = size_mb * 1024 * 1024;
        let data = random_data(size);
        let num_blocks = (size + BEP52_BLOCK_SIZE - 1) / BEP52_BLOCK_SIZE;

        group.throughput(Throughput::Bytes(size as u64));

        // Without store (hash-only mode)
        group.bench_with_input(
            BenchmarkId::new("no_store", format!("{}MB", size_mb)),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let builder: Bep52TreeBuilder<MemoryStore> =
                            Bep52TreeBuilder::new(Bep52Config::default());
                        builder.build_from_data(black_box(data)).await.unwrap()
                    })
                })
            },
        );

        // With MemoryStore
        group.bench_with_input(
            BenchmarkId::new("memory_store", format!("{}MB", size_mb)),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = Bep52Config::new().with_store(store);
                        let builder = Bep52TreeBuilder::new(config);
                        builder.build_from_data(black_box(data)).await.unwrap()
                    })
                })
            },
        );

        println!("  {} MB = {} blocks", size_mb, num_blocks);
    }

    group.finish();
}

/// Benchmark comparing block sizes (shows why BEP52 is slower)
fn bench_block_size_comparison(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("block_size_comparison");

    let size = 10 * 1024 * 1024; // 10 MB
    let data = random_data(size);
    group.throughput(Throughput::Bytes(size as u64));

    // BEP52: 16KB blocks = 640 blocks for 10MB (full tree build)
    group.bench_with_input(
        BenchmarkId::new("16KB_blocks_full_tree", "10MB"),
        &data,
        |b, data| {
            b.iter(|| {
                rt.block_on(async {
                    let builder: Bep52TreeBuilder<MemoryStore> =
                        Bep52TreeBuilder::new(Bep52Config::default());
                    builder.build_from_data(black_box(data)).await.unwrap()
                })
            })
        },
    );

    // Simulated 256KB blocks with full merkle tree
    let block_size_256k = 256 * 1024;
    group.bench_with_input(
        BenchmarkId::new("256KB_blocks_full_tree", "10MB"),
        &data,
        |b, data| {
            b.iter(|| {
                // Hash blocks
                let mut leaves = Vec::new();
                let mut offset = 0;
                while offset < data.len() {
                    let end = (offset + block_size_256k).min(data.len());
                    leaves.push(hash_block(&data[offset..end]));
                    offset = end;
                }
                // Build merkle tree from leaves
                merkle_root(black_box(&leaves), None)
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_merkle_hash_pair,
    bench_merkle_root,
    bench_merkle_build_tree,
    bench_bep52_builder,
    bench_block_size_comparison,
);

criterion_main!(benches);
