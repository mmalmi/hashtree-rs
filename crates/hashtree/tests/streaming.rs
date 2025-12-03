//! Streaming tests - port of hashtree-ts streaming tests

use hashtree::{
    BuilderConfig, HashTree, HashTreeConfig, MemoryStore, StreamBuilder, to_hex,
};
use std::sync::Arc;

#[tokio::test]
async fn test_incremental_root_updates() {
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(100);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    stream.append(&[1, 2, 3]).await.unwrap();
    let root1 = stream.current_root().await.unwrap().unwrap();

    stream.append(&[4, 5, 6]).await.unwrap();
    let root2 = stream.current_root().await.unwrap().unwrap();

    stream.append(&[7, 8, 9]).await.unwrap();
    let root3 = stream.current_root().await.unwrap().unwrap();

    // Each addition should produce different root
    assert_ne!(to_hex(&root1), to_hex(&root2));
    assert_ne!(to_hex(&root2), to_hex(&root3));

    // All intermediate roots should be readable
    let data1 = tree.read_file(&root1).await.unwrap().unwrap();
    assert_eq!(data1, vec![1, 2, 3]);

    let data2 = tree.read_file(&root2).await.unwrap().unwrap();
    assert_eq!(data2, vec![1, 2, 3, 4, 5, 6]);

    let data3 = tree.read_file(&root3).await.unwrap().unwrap();
    assert_eq!(data3, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[tokio::test]
async fn test_partial_stream_checkpoints() {
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(100);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    let mut checkpoints = Vec::new();

    for i in 0..5u8 {
        let chunk: Vec<u8> = (0..20).map(|_| i).collect();
        stream.append(&chunk).await.unwrap();
        let root = stream.current_root().await.unwrap().unwrap();
        checkpoints.push(root);
    }

    // Each checkpoint should be independently readable
    for (i, checkpoint) in checkpoints.iter().enumerate() {
        let data = tree.read_file(checkpoint).await.unwrap().unwrap();
        assert_eq!(data.len(), (i + 1) * 20);
        assert_eq!(data[i * 20], i as u8);
    }
}

#[tokio::test]
async fn test_livestream_simulation() {
    // Simulate video stream chunking
    let chunk_size = 64 * 1024; // 64KB internal chunks
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    let mut published_roots = Vec::new();

    // Simulate 5 seconds of video
    for second in 0..5u8 {
        // Each "second" of video is ~100KB
        let video_data: Vec<u8> = (0..100 * 1024)
            .map(|i| ((second as usize * 100 + i) % 256) as u8)
            .collect();

        stream.append(&video_data).await.unwrap();
        let root = stream.current_root().await.unwrap().unwrap();
        published_roots.push(root);
    }

    // Final root
    let (final_root, size) = stream.finalize().await.unwrap();
    assert_eq!(size, 5 * 100 * 1024);

    // Viewer joining at second 3 should be able to read data
    let partial_data = tree.read_file(&published_roots[2]).await.unwrap().unwrap();
    assert_eq!(partial_data.len(), 3 * 100 * 1024);

    // Full stream should contain all data
    let full_data = tree.read_file(&final_root).await.unwrap().unwrap();
    assert_eq!(full_data.len(), 5 * 100 * 1024);
}

#[tokio::test]
async fn test_rapid_sequential_appends() {
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(1024);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    // Simulate rapid data arrival
    for i in 0..50u8 {
        let chunk: Vec<u8> = (0..100).map(|_| i).collect();
        stream.append(&chunk).await.unwrap();
    }

    let (hash, size) = stream.finalize().await.unwrap();
    assert_eq!(size, 5000);

    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data.len(), 5000);
}

#[tokio::test]
async fn test_single_byte_appends() {
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(10);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    for i in 0..25u8 {
        stream.append(&[i]).await.unwrap();
    }

    let (hash, size) = stream.finalize().await.unwrap();
    assert_eq!(size, 25);

    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data.len(), 25);
    for i in 0..25 {
        assert_eq!(data[i], i as u8);
    }
}

#[tokio::test]
async fn test_chunk_aligned_appends() {
    let chunk_size = 100;
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    // Append exactly chunk-sized data 5 times
    for i in 0..5u8 {
        let chunk: Vec<u8> = (0..chunk_size).map(|_| i).collect();
        stream.append(&chunk).await.unwrap();
    }

    assert_eq!(stream.stats().chunks, 5);
    assert_eq!(stream.stats().buffered, 0);
    assert_eq!(stream.stats().total_size, 500);

    let (hash, _) = stream.finalize().await.unwrap();
    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data.len(), 500);
}

#[tokio::test]
async fn test_very_large_single_append() {
    let chunk_size = 100;
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    // Single large append (10 chunks worth)
    let big_data: Vec<u8> = (0..chunk_size * 10).map(|i| (i % 256) as u8).collect();

    stream.append(&big_data).await.unwrap();

    assert_eq!(stream.stats().chunks, 10);
    assert_eq!(stream.stats().total_size, 1000);

    let (hash, _) = stream.finalize().await.unwrap();
    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data, big_data);
}

#[tokio::test]
async fn test_mixed_small_and_large_appends() {
    let chunk_size = 100;
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    stream.append(&[1, 2, 3]).await.unwrap(); // 3 bytes
    stream.append(&vec![4u8; 250]).await.unwrap(); // 250 bytes (crosses chunks)
    stream.append(&[5]).await.unwrap(); // 1 byte
    stream.append(&vec![6u8; 46]).await.unwrap(); // 46 bytes

    let (hash, size) = stream.finalize().await.unwrap();
    assert_eq!(size, 300);

    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data[0], 1);
    assert_eq!(data[3], 4);
    assert_eq!(data[253], 5);
    assert_eq!(data[254], 6);
}

#[tokio::test]
async fn test_rolling_window_rebuild() {
    let chunk_size = 100;
    let max_chunks = 3; // Keep only last 3 "seconds"

    // Simulate chunks arriving
    let all_chunks: Vec<Vec<u8>> = (0..10u8)
        .map(|i| vec![i; chunk_size])
        .collect();

    // Build "live" stream with only last N chunks
    let live_chunks = &all_chunks[all_chunks.len() - max_chunks..];
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);
    let tree = HashTree::new(HashTreeConfig::new(store).public());

    for chunk in live_chunks {
        stream.append(chunk).await.unwrap();
    }

    let (hash, size) = stream.finalize().await.unwrap();
    assert_eq!(size, (max_chunks * chunk_size) as u64);

    let data = tree.read_file(&hash).await.unwrap().unwrap();
    // Should contain chunks 7, 8, 9
    assert_eq!(data[0], 7);
    assert_eq!(data[100], 8);
    assert_eq!(data[200], 9);
}

#[tokio::test]
async fn test_deduplication() {
    let chunk_size = 100;
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(chunk_size);
    let mut stream = StreamBuilder::new(config);

    let repeated_data: Vec<u8> = vec![42u8; chunk_size];

    // Append same data 5 times
    for _ in 0..5 {
        stream.append(&repeated_data).await.unwrap();
    }

    let (hash, size) = stream.finalize().await.unwrap();
    assert_eq!(size, 500);

    // Store should have fewer items due to dedup
    // (1 chunk blob + potentially some tree nodes)
    let store_size = store.size();
    // With 5 identical chunks, we only store 1 unique chunk
    // plus tree structure (much less than 5 separate chunks)
    assert!(store_size < 5, "Expected deduplication, got {} items", store_size);

    // Verify can still read back
    // Use same store
    let tree = HashTree::new(HashTreeConfig::new(store).public());
    let data = tree.read_file(&hash).await.unwrap().unwrap();
    assert_eq!(data.len(), 500);
}

#[tokio::test]
async fn test_concurrent_readers() {
    let store = Arc::new(MemoryStore::new());
    let config = BuilderConfig::new(store.clone()).with_chunk_size(100);
    let mut stream = StreamBuilder::new(config);

    // Build stream
    for i in 0..10u8 {
        let chunk: Vec<u8> = vec![i; 50];
        stream.append(&chunk).await.unwrap();
    }
    let (hash, _) = stream.finalize().await.unwrap();

    // Multiple readers can read independently
    let tree1 = HashTree::new(HashTreeConfig::new(store.clone()).public());
    let tree2 = HashTree::new(HashTreeConfig::new(store).public());

    let (data1, data2) = tokio::join!(
        tree1.read_file(&hash),
        tree2.read_file(&hash)
    );

    let data1 = data1.unwrap().unwrap();
    let data2 = data2.unwrap().unwrap();

    assert_eq!(data1, data2);
    assert_eq!(data1.len(), 500);
}
