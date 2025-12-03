//! TreeBuilder benchmark comparing CBOR vs Binary merkle algorithms
//! and encrypted vs non-encrypted performance.
//!
//! Run with: cargo bench -p hashtree --features encryption

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hashtree::{
    HashTree, HashTreeConfig, MerkleAlgorithm, MemoryStore, Store,
    BEP52_CHUNK_SIZE, DEFAULT_CHUNK_SIZE,
};
// For internal bench-only access to TreeBuilder/TreeReader
use hashtree::builder::{TreeBuilder, BuilderConfig};
use hashtree::reader::TreeReader;
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

/// Benchmark encrypted vs non-encrypted write performance
#[cfg(feature = "encryption")]
fn bench_encrypted_write(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("encrypted_write");

    let sizes = [
        (1, "1MB"),
        (10, "10MB"),
    ];

    for (size_mb, size_name) in sizes {
        let size = size_mb * 1024 * 1024;
        let data = random_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Non-encrypted
        group.bench_with_input(
            BenchmarkId::new("plain", size_name),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = BuilderConfig::new(store);
                        let builder = TreeBuilder::new(config);
                        builder.put_file(black_box(data)).await.unwrap()
                    })
                })
            },
        );

        // Encrypted
        group.bench_with_input(
            BenchmarkId::new("encrypted", size_name),
            &data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = EncryptedTreeConfig {
                            store,
                            chunk_size: DEFAULT_CHUNK_SIZE,
                            max_links: 174,
                        };
                        put_file_encrypted(&config, black_box(data)).await.unwrap()
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark encrypted vs non-encrypted read performance
#[cfg(feature = "encryption")]
fn bench_encrypted_read(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("encrypted_read");

    let sizes = [
        (1, "1MB"),
        (10, "10MB"),
    ];

    for (size_mb, size_name) in sizes {
        let size = size_mb * 1024 * 1024;
        let data = random_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Non-encrypted - pre-build
        let (plain_store, plain_hash) = rt.block_on(async {
            let store = Arc::new(MemoryStore::new());
            let config = BuilderConfig::new(store.clone());
            let builder = TreeBuilder::new(config);
            let result = builder.put_file(&data).await.unwrap();
            (store, result.hash)
        });

        group.bench_with_input(
            BenchmarkId::new("plain", size_name),
            &(plain_store.clone(), plain_hash),
            |b, (store, hash)| {
                b.iter(|| {
                    rt.block_on(async {
                        let reader = TreeReader::new(store.clone());
                        reader.read_file(black_box(hash)).await.unwrap()
                    })
                })
            },
        );

        // Encrypted - pre-build
        let (enc_store, enc_hash, enc_key) = rt.block_on(async {
            let store = Arc::new(MemoryStore::new());
            let config = EncryptedTreeConfig {
                store: store.clone(),
                chunk_size: DEFAULT_CHUNK_SIZE,
                max_links: 174,
            };
            let result = put_file_encrypted(&config, &data).await.unwrap();
            (store, result.hash, result.key)
        });

        group.bench_with_input(
            BenchmarkId::new("encrypted", size_name),
            &(enc_store.clone(), enc_hash, enc_key),
            |b, (store, hash, key)| {
                b.iter(|| {
                    rt.block_on(async {
                        read_file_encrypted(store.as_ref(), black_box(hash), black_box(key))
                            .await
                            .unwrap()
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark encrypted vs non-encrypted directory write performance
#[cfg(feature = "encryption")]
fn bench_encrypted_dir_write(c: &mut Criterion) {
    use hashtree::DirEntry;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("encrypted_dir_write");

    // Test with different numbers of files
    let file_counts = [100, 1000];
    let file_size = 10 * 1024; // 10KB per file

    for file_count in file_counts {
        let total_size = file_count * file_size;
        let files: Vec<(String, Vec<u8>)> = (0..file_count)
            .map(|i| (format!("file_{:05}.txt", i), random_data(file_size)))
            .collect();

        group.throughput(Throughput::Bytes(total_size as u64));

        // Non-encrypted directory
        group.bench_with_input(
            BenchmarkId::new("plain", format!("{}files", file_count)),
            &files,
            |b, files| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = BuilderConfig::new(store.clone());
                        let builder = TreeBuilder::new(config);

                        let mut entries = Vec::new();
                        for (name, data) in files {
                            let result = builder.put_file(data).await.unwrap();
                            entries.push(DirEntry::new(name.clone(), result.hash).with_size(result.size));
                        }
                        builder.put_directory(entries, None).await.unwrap()
                    })
                })
            },
        );

        // Encrypted directory
        group.bench_with_input(
            BenchmarkId::new("encrypted", format!("{}files", file_count)),
            &files,
            |b, files| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(MemoryStore::new());
                        let config = EncryptedTreeConfig {
                            store: store.clone(),
                            chunk_size: DEFAULT_CHUNK_SIZE,
                            max_links: 174,
                        };

                        let mut _hashes = Vec::new();
                        for (_name, data) in files {
                            let result = put_file_encrypted(&config, data).await.unwrap();
                            _hashes.push((result.hash, result.key));
                        }
                        // Note: encrypted directories would need separate implementation
                        // This just benchmarks encrypting all files
                    })
                })
            },
        );
    }

    group.finish();
}

#[cfg(feature = "encryption")]
criterion_group!(
    benches,
    bench_tree_builder,
    bench_tree_reader,
    bench_roundtrip,
    bench_encrypted_write,
    bench_encrypted_read,
    bench_encrypted_dir_write,
);

#[cfg(not(feature = "encryption"))]
criterion_group!(
    benches,
    bench_tree_builder,
    bench_tree_reader,
    bench_roundtrip,
);

criterion_main!(benches);
