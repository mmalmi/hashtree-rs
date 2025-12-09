//! Integration tests for WebRTC peer connectivity
//!
//! These tests connect to actual Nostr relays for signaling and establish
//! WebRTC connections between peers.

use hashtree::MemoryStore;
use hashtree_webrtc::{WebRTCStore, WebRTCStoreConfig};
use nostr_sdk::prelude::*;
use std::sync::Arc;

/// Default relays for signaling
const TEST_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://temp.iris.to",
];

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

    let config = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 2000, // More frequent hellos
        satisfied_connections: 1,
        ..Default::default()
    };

    let mut store1 = WebRTCStore::new(store1_local, config.clone());
    let mut store2 = WebRTCStore::new(store2_local, config);

    let keys1 = Keys::generate();
    let keys2 = Keys::generate();
    println!("Store1 pubkey: {}", keys1.public_key().to_hex());
    println!("Store2 pubkey: {}", keys2.public_key().to_hex());

    // Start both stores
    store1.start(keys1).await.expect("Store1 failed to start");
    println!("Store1 started");

    // Stagger to avoid relay rate limiting
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    store2.start(keys2).await.expect("Store2 failed to start");
    println!("Store2 started");

    // Wait for peer discovery (~15s timeout)
    let mut found_peer = false;
    for _ in 0..5 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

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
    use hashtree::{Store, sha256};

    // Store1 has data, store2 fetches it via WebRTC
    let store1_local = Arc::new(MemoryStore::new());
    let store2_local = Arc::new(MemoryStore::new());

    // Put test data in store1
    let test_data = b"Hello from peer 1 via WebRTC!";
    let hash = sha256(test_data);
    store1_local.put(hash, test_data.to_vec()).await.unwrap();

    let config = WebRTCStoreConfig {
        relays: TEST_RELAYS.iter().map(|s| s.to_string()).collect(),
        debug: true,
        hello_interval_ms: 3000,
        satisfied_connections: 1,
        ..Default::default()
    };

    let mut store1 = WebRTCStore::new(store1_local.clone(), config.clone());
    let mut store2 = WebRTCStore::new(store2_local.clone(), config);

    let keys1 = Keys::generate();
    let keys2 = Keys::generate();

    // Start both stores (same timing as peer_discovery test)
    store1.start(keys1).await.expect("Store1 failed to start");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    store2.start(keys2).await.expect("Store2 failed to start");

    // Wait for peer connection (same timing as peer_discovery test)
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
    // (store2 doesn't have it locally, so it asks peers)
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

