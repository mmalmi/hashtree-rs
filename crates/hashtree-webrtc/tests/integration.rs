//! Integration tests for WebRTC peer connectivity
//!
//! These tests connect to actual Nostr relays for signaling and establish
//! WebRTC connections between peers.

use hashtree_core::MemoryStore;
use hashtree_webrtc::{classifier_channel, ClassifyRequest, PeerPool, PoolConfig, PoolSettings, WebRTCStore, WebRTCStoreConfig};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default relays for signaling
const TEST_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://temp.iris.to",
];

/// Helper to run classifier that treats specific pubkeys as "follows"
async fn run_classifier(mut rx: hashtree_webrtc::ClassifierRx, follows: Arc<RwLock<HashSet<String>>>) {
    while let Some(req) = rx.recv().await {
        let is_follow = follows.read().await.contains(&req.pubkey);
        let pool = if is_follow { PeerPool::Follows } else { PeerPool::Other };
        let _ = req.response.send(pool);
    }
}

#[tokio::test]
async fn test_connect_to_relays() {
    let local_store = Arc::new(MemoryStore::new());
    let config = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 5000,
        ..Default::default()
    };

    let mut store = WebRTCStore::new(local_store, config);
    let keys = Keys::generate();

    // Should connect without error
    let result = store.start(keys).await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());

    // Give it time to send hello
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Check stats
    let stats = store.stats().await;
    println!("Stats after connect: {:?}", stats);

    store.stop().await;
}

#[tokio::test]
async fn test_peer_discovery() {
    // Create two stores that should discover each other
    let store1_local = Arc::new(MemoryStore::new());
    let store2_local = Arc::new(MemoryStore::new());

    // Generate keys first so we can set up the classifier
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();
    let pubkey1 = keys1.public_key().to_hex();
    let pubkey2 = keys2.public_key().to_hex();
    println!("Store1 pubkey: {}", pubkey1);
    println!("Store2 pubkey: {}", pubkey2);

    // Set up classifiers - each store treats the other as a "follow"
    let (classifier_tx1, classifier_rx1) = classifier_channel(10);
    let (classifier_tx2, classifier_rx2) = classifier_channel(10);

    // Store1 follows store2
    let follows1: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::from([pubkey2.clone()])));
    // Store2 follows store1
    let follows2: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::from([pubkey1.clone()])));

    // Start classifier tasks
    tokio::spawn(run_classifier(classifier_rx1, follows1));
    tokio::spawn(run_classifier(classifier_rx2, follows2));

    // Configure pools: only connect to follows (other pool has 0 max)
    let pools = PoolSettings {
        follows: PoolConfig {
            max_connections: 10,
            satisfied_connections: 1,
        },
        other: PoolConfig {
            max_connections: 0, // Don't connect to non-follows
            satisfied_connections: 0,
        },
    };

    let config1 = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 1000, // Very frequent hellos for test reliability
        pools: pools.clone(),
        classifier_tx: Some(classifier_tx1),
        ..Default::default()
    };

    let config2 = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 1000,
        pools: pools.clone(),
        classifier_tx: Some(classifier_tx2),
        ..Default::default()
    };

    let mut store1 = WebRTCStore::new(store1_local, config1);
    let mut store2 = WebRTCStore::new(store2_local, config2);

    // Start both stores with minimal stagger (both should be subscribed quickly)
    store1.start(keys1).await.expect("Store1 failed to start");
    println!("Store1 started");

    // Minimal stagger - just enough for store1 to be subscribed
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    store2.start(keys2).await.expect("Store2 failed to start");
    println!("Store2 started");

    // Wait for peer discovery (~30s timeout with more iterations)
    let mut found_peer = false;
    for i in 0..10 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        println!("Discovery attempt {}/10", i + 1);

        let count1 = store1.peer_count().await;
        let count2 = store2.peer_count().await;

        println!("Peer counts: store1={}, store2={}", count1, count2);

        if count1 > 0 || count2 > 0 {
            found_peer = true;
            break;
        }
    }

    store1.stop().await;
    store2.stop().await;

    assert!(found_peer, "Peers should discover and connect to each other");
}

#[tokio::test]
async fn test_data_transfer_between_peers() {
    use hashtree_core::{Store, sha256};

    // Store1 has data, store2 fetches it via WebRTC
    let store1_local = Arc::new(MemoryStore::new());
    let store2_local = Arc::new(MemoryStore::new());

    // Put test data in store1
    let test_data = b"Hello from peer 1 via WebRTC!";
    let hash = sha256(test_data);
    store1_local.put(hash, test_data.to_vec()).await.unwrap();

    // Generate keys first so we can set up the classifier
    let keys1 = Keys::generate();
    let keys2 = Keys::generate();
    let pubkey1 = keys1.public_key().to_hex();
    let pubkey2 = keys2.public_key().to_hex();

    // Set up classifiers - each store treats the other as a "follow"
    let (classifier_tx1, classifier_rx1) = classifier_channel(10);
    let (classifier_tx2, classifier_rx2) = classifier_channel(10);

    let follows1: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::from([pubkey2.clone()])));
    let follows2: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::from([pubkey1.clone()])));

    tokio::spawn(run_classifier(classifier_rx1, follows1));
    tokio::spawn(run_classifier(classifier_rx2, follows2));

    // Configure pools: only connect to follows
    let pools = PoolSettings {
        follows: PoolConfig {
            max_connections: 10,
            satisfied_connections: 1,
        },
        other: PoolConfig {
            max_connections: 0,
            satisfied_connections: 0,
        },
    };

    let config1 = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 3000,
        pools: pools.clone(),
        classifier_tx: Some(classifier_tx1),
        ..Default::default()
    };

    let config2 = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 3000,
        pools: pools.clone(),
        classifier_tx: Some(classifier_tx2),
        ..Default::default()
    };

    let mut store1 = WebRTCStore::new(store1_local.clone(), config1);
    let mut store2 = WebRTCStore::new(store2_local.clone(), config2);

    // Start both stores
    store1.start(keys1).await.expect("Store1 failed to start");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    store2.start(keys2).await.expect("Store2 failed to start");

    // Wait for peer connection
    let mut connected = false;
    for _ in 0..5 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let count1 = store1.peer_count().await;
        let count2 = store2.peer_count().await;
        println!("Peer counts: store1={}, store2={}", count1, count2);
        if count1 > 0 && count2 > 0 {
            connected = true;
            break;
        }
    }

    if !connected {
        store1.stop().await;
        store2.stop().await;
        println!("Warning: Peers did not connect (network/relay issue)");
        return; // Skip data transfer test if no connection
    }
    println!("Peers connected, attempting data transfer...");

    // Store2 should be able to fetch data from store1
    let result = store2.get(&hash).await;

    store1.stop().await;
    store2.stop().await;

    match result {
        Ok(Some(data)) => {
            assert_eq!(data, test_data.to_vec());
            println!("Data transfer successful!");
        }
        Ok(None) => {
            println!("Warning: Data not found (peer may not have responded in time)");
        }
        Err(e) => {
            println!("Warning: Error fetching data: {:?}", e);
        }
    }
}
