//! WebSocket endpoint for hashtree data exchange
//!
//! Speaks the same protocol as WebRTC data channels in hashtree-ts:
//! - JSON messages: req, res, push, have, want, root
//! - Binary messages: [4-byte LE request_id][data]
//!
//! This allows hashtree-ts to fall back to WebSocket when WebRTC fails.
//! The server can also forward requests to other connected peers.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, warn};

use crate::storage::HashtreeStore;
use crate::webrtc::types::DataMessage;

/// Delay between sequential peer queries (ms)
const PEER_QUERY_DELAY_MS: u64 = 500;

/// Timeout for a single peer query (ms)
#[allow(dead_code)]
const PEER_QUERY_TIMEOUT_MS: u64 = 2000;

/// A connected peer
struct Peer {
    tx: mpsc::Sender<Message>,
}

/// Max number of hashes to track per peer (LRU eviction after this)
const MAX_REQUESTED_HASHES_PER_PEER: usize = 1000;

/// Registry of all connected peers
pub struct PeerRegistry {
    peers: RwLock<HashMap<u64, Peer>>,
    next_id: RwLock<u64>,
    /// Pending requests waiting for responses from peers
    pending_requests: RwLock<HashMap<(u64, u32), oneshot::Sender<Option<Vec<u8>>>>>,
    /// Track hashes we've already requested from each peer (peer_id -> LRU cache of hashes)
    /// Value is () since we only care about presence
    requested_from_peer: Mutex<HashMap<u64, LruCache<String, ()>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            next_id: RwLock::new(1),
            pending_requests: RwLock::new(HashMap::new()),
            requested_from_peer: Mutex::new(HashMap::new()),
        }
    }

    async fn register(&self, tx: mpsc::Sender<Message>) -> u64 {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let mut peers = self.peers.write().await;
        peers.insert(id, Peer { tx });
        debug!("Peer {} registered, total: {}", id, peers.len());
        id
    }

    async fn unregister(&self, id: u64) {
        let mut peers = self.peers.write().await;
        peers.remove(&id);
        debug!("Peer {} unregistered, total: {}", id, peers.len());
        drop(peers);

        // Clean up request tracking for this peer
        let mut requested = self.requested_from_peer.lock().await;
        requested.remove(&id);
    }

    /// Forward a request to other peers (excluding the requester)
    /// Returns data if any peer has it, None otherwise
    async fn forward_request(&self, exclude_peer: u64, hash: &str) -> Option<Vec<u8>> {
        let peers = self.peers.read().await;
        let other_peers: Vec<(u64, mpsc::Sender<Message>)> = peers
            .iter()
            .filter(|(id, _)| **id != exclude_peer)
            .map(|(id, p)| (*id, p.tx.clone()))
            .collect();
        drop(peers);

        if other_peers.is_empty() {
            return None;
        }

        // Filter out peers we've already requested this hash from
        let mut requested = self.requested_from_peer.lock().await;
        let peers_to_query: Vec<_> = other_peers
            .into_iter()
            .filter(|(peer_id, _)| {
                if let Some(cache) = requested.get(peer_id) {
                    !cache.contains(hash)
                } else {
                    true
                }
            })
            .collect();
        drop(requested);

        if peers_to_query.is_empty() {
            debug!("Already requested {} from all peers, skipping", &hash[..16.min(hash.len())]);
            return None;
        }

        debug!("Forwarding request for {} to {} peers", &hash[..16.min(hash.len())], peers_to_query.len());

        // Query peers sequentially with delay
        for (peer_id, tx) in peers_to_query {
            // Mark this hash as requested from this peer
            {
                let mut requested = self.requested_from_peer.lock().await;
                let cache = requested.entry(peer_id).or_insert_with(|| {
                    LruCache::new(NonZeroUsize::new(MAX_REQUESTED_HASHES_PER_PEER).unwrap())
                });
                cache.put(hash.to_string(), ());
            }

            // Create a unique request ID for this forward
            let forward_id = {
                let next_id = self.next_id.read().await;
                (*next_id as u32).wrapping_add(peer_id as u32)
            };

            // Set up response channel
            let (resp_tx, resp_rx) = oneshot::channel();
            {
                let mut pending = self.pending_requests.write().await;
                pending.insert((peer_id, forward_id), resp_tx);
            }

            // Send request to peer
            let req = DataMessage::Request {
                id: forward_id,
                hash: hash.to_string(),
            };
            if let Ok(json) = serde_json::to_string(&req) {
                let _ = tx.send(Message::Text(json)).await;
            }

            // Wait for response with timeout
            let result = tokio::time::timeout(
                Duration::from_millis(PEER_QUERY_DELAY_MS),
                resp_rx,
            )
            .await;

            // Clean up pending request
            {
                let mut pending = self.pending_requests.write().await;
                pending.remove(&(peer_id, forward_id));
            }

            match result {
                Ok(Ok(Some(data))) => {
                    debug!("Got data from peer {} for {}", peer_id, &hash[..16.min(hash.len())]);
                    return Some(data);
                }
                Ok(Ok(None)) => {
                    debug!("Peer {} doesn't have {}", peer_id, &hash[..16.min(hash.len())]);
                }
                Ok(Err(_)) => {
                    debug!("Peer {} channel closed", peer_id);
                }
                Err(_) => {
                    debug!("Peer {} timeout for {}", peer_id, &hash[..16.min(hash.len())]);
                }
            }
        }

        None
    }

    /// Handle a response from a peer (for forwarded requests)
    async fn handle_peer_response(&self, peer_id: u64, id: u32, data: Option<Vec<u8>>) {
        let mut pending = self.pending_requests.write().await;
        if let Some(tx) = pending.remove(&(peer_id, id)) {
            let _ = tx.send(data);
        }
    }
}

/// State for the data WebSocket handler
#[derive(Clone)]
pub struct DataWsState {
    pub store: Arc<HashtreeStore>,
    pub peers: Arc<PeerRegistry>,
}

impl DataWsState {
    pub fn new(store: Arc<HashtreeStore>) -> Self {
        Self {
            store,
            peers: Arc::new(PeerRegistry::new()),
        }
    }
}

/// WebSocket upgrade handler for /ws/data endpoint
pub async fn data_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<DataWsState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_data_socket(socket, state))
}

/// Handle a single WebSocket connection
async fn handle_data_socket(socket: WebSocket, state: DataWsState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(32);

    // Register this peer
    let peer_id = state.peers.register(tx.clone()).await;

    // Spawn task to forward messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_json_message(&text, peer_id, &state, &tx).await {
                    warn!("Error handling JSON message: {}", e);
                }
            }
            Ok(Message::Binary(data)) => {
                // Binary data is a response to a forwarded request
                // Format: [4-byte LE request_id][data]
                if data.len() >= 4 {
                    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let payload = data[4..].to_vec();
                    state.peers.handle_peer_response(peer_id, id, Some(payload)).await;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {} // Ping/Pong handled by axum
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Clean up
    state.peers.unregister(peer_id).await;
    drop(tx);
    let _ = send_task.await;
}

/// Handle a JSON data message
async fn handle_json_message(
    text: &str,
    peer_id: u64,
    state: &DataWsState,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    let msg: DataMessage = serde_json::from_str(text)?;

    match msg {
        DataMessage::Request { id, hash } => {
            handle_request(id, &hash, peer_id, state, tx).await?;
        }
        DataMessage::Response { id, found, .. } => {
            // Response from a peer - if not found, notify pending request
            if !found {
                state.peers.handle_peer_response(peer_id, id, None).await;
            }
            // If found, binary data will follow
        }
        DataMessage::Want { hashes } => {
            // Client wants multiple hashes - respond with what we have
            for hash in hashes {
                // Check if we have it without sending data
                if let Ok(Some(_)) = state.store.get_file(&hash) {
                    let have_msg = DataMessage::Have {
                        hashes: vec![hash],
                    };
                    let json = serde_json::to_string(&have_msg)?;
                    tx.send(Message::Text(json)).await?;
                }
            }
        }
        DataMessage::Have { hashes } => {
            // Client is telling us what they have - we could track this
            debug!("Peer {} has {} hashes", peer_id, hashes.len());
        }
        DataMessage::Root { hash } => {
            // Client updated their root - we could track this
            debug!("Peer {} root: {}", peer_id, hash);
        }
        DataMessage::Push { .. } => {
            // Push from peer - we could handle this to receive pushed data
            debug!("Received push from peer {}", peer_id);
        }
    }

    Ok(())
}

/// Handle a data request
async fn handle_request(
    id: u32,
    hash: &str,
    peer_id: u64,
    state: &DataWsState,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    // First, try local storage
    let result = state.store.get_file(hash);

    match result {
        Ok(Some(data)) => {
            send_found_response(id, hash, &data, tx).await?;
            return Ok(());
        }
        Ok(None) => {
            // Not in local storage, try forwarding to other peers
            debug!("Hash {} not in local storage, forwarding to peers", &hash[..16.min(hash.len())]);
        }
        Err(e) => {
            warn!("Store error for hash {}: {}", hash, e);
        }
    }

    // Forward to other peers
    if let Some(data) = state.peers.forward_request(peer_id, hash).await {
        // Store locally for future requests (put_blob computes hash internally)
        if let Err(e) = state.store.put_blob(&data) {
            warn!("Failed to cache forwarded data: {}", e);
        }
        send_found_response(id, hash, &data, tx).await?;
        return Ok(());
    }

    // Not found anywhere
    let response = DataMessage::Response {
        id,
        hash: hash.to_string(),
        found: false,
    };
    let json = serde_json::to_string(&response)?;
    tx.send(Message::Text(json)).await?;

    Ok(())
}

async fn send_found_response(
    id: u32,
    hash: &str,
    data: &[u8],
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    // Send response indicating found
    let response = DataMessage::Response {
        id,
        hash: hash.to_string(),
        found: true,
    };
    let json = serde_json::to_string(&response)?;
    tx.send(Message::Text(json)).await?;

    // Send binary data: [4-byte LE id][data]
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.extend_from_slice(&id.to_le_bytes());
    packet.extend_from_slice(data);
    tx.send(Message::Binary(packet)).await?;

    debug!("Sent {} bytes for hash {}", data.len(), &hash[..16.min(hash.len())]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_message_serialize_request() {
        let msg = DataMessage::Request {
            id: 42,
            hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"req\""));
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"hash\":\"abc123\""));
    }

    #[test]
    fn test_data_message_serialize_response() {
        let msg = DataMessage::Response {
            id: 42,
            hash: "abc123".to_string(),
            found: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"res\""));
        assert!(json.contains("\"found\":true"));
    }

    #[test]
    fn test_data_message_deserialize_request() {
        let json = r#"{"type":"req","id":123,"hash":"deadbeef"}"#;
        let msg: DataMessage = serde_json::from_str(json).unwrap();
        match msg {
            DataMessage::Request { id, hash } => {
                assert_eq!(id, 123);
                assert_eq!(hash, "deadbeef");
            }
            _ => panic!("Expected Request"),
        }
    }

    #[test]
    fn test_data_message_deserialize_want() {
        let json = r#"{"type":"want","hashes":["hash1","hash2","hash3"]}"#;
        let msg: DataMessage = serde_json::from_str(json).unwrap();
        match msg {
            DataMessage::Want { hashes } => {
                assert_eq!(hashes.len(), 3);
                assert_eq!(hashes[0], "hash1");
            }
            _ => panic!("Expected Want"),
        }
    }

    #[test]
    fn test_data_message_deserialize_have() {
        let json = r#"{"type":"have","hashes":["hash1"]}"#;
        let msg: DataMessage = serde_json::from_str(json).unwrap();
        match msg {
            DataMessage::Have { hashes } => {
                assert_eq!(hashes.len(), 1);
            }
            _ => panic!("Expected Have"),
        }
    }

    #[test]
    fn test_data_message_deserialize_root() {
        let json = r#"{"type":"root","hash":"roothash"}"#;
        let msg: DataMessage = serde_json::from_str(json).unwrap();
        match msg {
            DataMessage::Root { hash } => {
                assert_eq!(hash, "roothash");
            }
            _ => panic!("Expected Root"),
        }
    }

    #[tokio::test]
    async fn test_peer_registry_register_unregister() {
        let registry = PeerRegistry::new();
        let (tx1, _rx1) = mpsc::channel(32);
        let (tx2, _rx2) = mpsc::channel(32);

        let id1 = registry.register(tx1).await;
        let id2 = registry.register(tx2).await;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        {
            let peers = registry.peers.read().await;
            assert_eq!(peers.len(), 2);
        }

        registry.unregister(id1).await;
        {
            let peers = registry.peers.read().await;
            assert_eq!(peers.len(), 1);
            assert!(!peers.contains_key(&id1));
            assert!(peers.contains_key(&id2));
        }
    }

    #[tokio::test]
    async fn test_peer_registry_forward_request_no_peers() {
        let registry = PeerRegistry::new();

        // With no peers, should return None
        let result = registry.forward_request(999, "somehash").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_peer_registry_forward_request_excludes_self() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);

        let id = registry.register(tx).await;

        // Forward should exclude the peer making the request
        // Since there's only one peer (which is excluded), should return None
        let result = registry.forward_request(id, "somehash").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_peer_response_handling() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);
        let peer_id = registry.register(tx).await;
        let request_id = 42u32;

        // Create a pending request
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = registry.pending_requests.write().await;
            pending.insert((peer_id, request_id), resp_tx);
        }

        // Handle response
        let test_data = vec![1, 2, 3, 4];
        registry.handle_peer_response(peer_id, request_id, Some(test_data.clone())).await;

        // Should receive the data
        let result = resp_rx.await.unwrap();
        assert_eq!(result, Some(test_data));
    }

    #[tokio::test]
    async fn test_peer_response_not_found() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);
        let peer_id = registry.register(tx).await;
        let request_id = 42u32;

        // Create a pending request
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = registry.pending_requests.write().await;
            pending.insert((peer_id, request_id), resp_tx);
        }

        // Handle response with None (not found)
        registry.handle_peer_response(peer_id, request_id, None).await;

        // Should receive None
        let result = resp_rx.await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_binary_message_format() {
        // Test that binary messages match the expected format: [4-byte LE id][data]
        let id: u32 = 0x12345678;
        let data = b"test data";

        let mut packet = Vec::with_capacity(4 + data.len());
        packet.extend_from_slice(&id.to_le_bytes());
        packet.extend_from_slice(data);

        // Verify format
        assert_eq!(packet.len(), 4 + data.len());
        assert_eq!(&packet[0..4], &[0x78, 0x56, 0x34, 0x12]); // Little endian
        assert_eq!(&packet[4..], data);

        // Verify we can parse it back
        let parsed_id = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(parsed_id, id);
        assert_eq!(&packet[4..], data);
    }
}
