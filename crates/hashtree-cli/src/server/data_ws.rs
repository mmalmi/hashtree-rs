//! WebSocket endpoint for hashtree data exchange
//!
//! Wire format: [type byte][msgpack body]
//! Request:  [0x00][msgpack: {h: bytes32, htl?: u8}]
//! Response: [0x01][msgpack: {h: bytes32, d: bytes}]
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
use crate::webrtc::types::{DataMessage, DataRequest, DataResponse, PeerHTLConfig, MAX_HTL, decrement_htl, should_forward, encode_request, encode_response, parse_message, hash_to_hex};

/// Delay between sequential peer queries (ms)
const PEER_QUERY_DELAY_MS: u64 = 500;

/// Timeout for a single peer query (ms)
#[allow(dead_code)]
const PEER_QUERY_TIMEOUT_MS: u64 = 2000;

/// A connected peer
struct Peer {
    tx: mpsc::Sender<Message>,
    /// Per-peer HTL config (Freenet-style probabilistic)
    htl_config: PeerHTLConfig,
}

/// Max number of hashes to track per peer (LRU eviction after this)
const MAX_REQUESTED_HASHES_PER_PEER: usize = 1000;

/// Rate limit: max peer queries per window per client
const HTTP_PEER_QUERY_LIMIT: usize = 10;
/// Rate limit window in seconds
const HTTP_PEER_QUERY_WINDOW_SECS: u64 = 10;
/// Max clients to track for rate limiting (LRU eviction)
const MAX_RATE_LIMIT_CLIENTS: usize = 1000;

/// Registry of all connected peers
pub struct PeerRegistry {
    peers: RwLock<HashMap<u64, Peer>>,
    next_id: RwLock<u64>,
    /// Pending requests waiting for responses from peers (keyed by peer_id + hash_hex)
    pending_requests: RwLock<HashMap<(u64, String), oneshot::Sender<Option<Vec<u8>>>>>,
    /// Track hashes we've already requested from each peer (peer_id -> LRU cache of hashes)
    /// Value is () since we only care about presence
    requested_from_peer: Mutex<HashMap<u64, LruCache<String, ()>>>,
    /// Rate limiter for HTTP peer queries per client IP
    http_rate_limits: Mutex<LruCache<String, Vec<std::time::Instant>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            next_id: RwLock::new(1),
            pending_requests: RwLock::new(HashMap::new()),
            requested_from_peer: Mutex::new(HashMap::new()),
            http_rate_limits: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_RATE_LIMIT_CLIENTS).unwrap()
            )),
        }
    }

    /// Check if HTTP peer query is allowed for a client (rate limiting)
    /// Returns true if allowed, false if rate limited
    pub async fn check_http_rate_limit(&self, client_id: &str) -> bool {
        let mut rate_limits = self.http_rate_limits.lock().await;
        let now = std::time::Instant::now();
        let window = Duration::from_secs(HTTP_PEER_QUERY_WINDOW_SECS);

        // Get or create timestamps for this client
        let timestamps = rate_limits.get_or_insert_mut(client_id.to_string(), Vec::new);

        // Remove old timestamps outside the window
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= HTTP_PEER_QUERY_LIMIT {
            debug!("HTTP peer query rate limited for {} ({} queries in {}s)",
                   client_id, timestamps.len(), HTTP_PEER_QUERY_WINDOW_SECS);
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    async fn register(&self, tx: mpsc::Sender<Message>) -> u64 {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let mut peers = self.peers.write().await;
        peers.insert(id, Peer {
            tx,
            htl_config: PeerHTLConfig::new(),
        });
        debug!("Peer {} registered, total: {}", id, peers.len());
        id
    }

    /// Get the HTL config for a peer
    async fn get_htl_config(&self, peer_id: u64) -> Option<PeerHTLConfig> {
        let peers = self.peers.read().await;
        peers.get(&peer_id).map(|p| p.htl_config.clone())
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
    /// Used by WebSocket handler and HTTP handler for peer queries
    /// @param hash - Binary 32-byte hash
    /// @param htl - Hops To Live (will be decremented per-peer before sending)
    pub async fn forward_request(&self, exclude_peer: u64, hash: &[u8], htl: u8) -> Option<Vec<u8>> {
        let hash_hex = hash_to_hex(hash);
        let hash_short = &hash_hex[..16.min(hash_hex.len())];

        let peers = self.peers.read().await;
        let other_peers: Vec<(u64, mpsc::Sender<Message>, PeerHTLConfig)> = peers
            .iter()
            .filter(|(id, _)| **id != exclude_peer)
            .map(|(id, p)| (*id, p.tx.clone(), p.htl_config.clone()))
            .collect();
        drop(peers);

        if other_peers.is_empty() {
            return None;
        }

        // Filter out peers we've already requested this hash from
        let mut requested = self.requested_from_peer.lock().await;
        let peers_to_query: Vec<_> = other_peers
            .into_iter()
            .filter(|(peer_id, _, _)| {
                if let Some(cache) = requested.get(peer_id) {
                    !cache.contains(&hash_hex)
                } else {
                    true
                }
            })
            .collect();
        drop(requested);

        if peers_to_query.is_empty() {
            debug!("Already requested {} from all peers, skipping", hash_short);
            return None;
        }

        debug!("Forwarding request for {} to {} peers", hash_short, peers_to_query.len());

        // Query peers sequentially with delay
        for (peer_id, tx, htl_config) in peers_to_query {
            // Decrement HTL using this peer's config before sending
            let peer_htl = decrement_htl(htl, &htl_config);

            // Skip this peer if HTL expired
            if !should_forward(peer_htl) {
                debug!("HTL expired for peer {}, skipping", peer_id);
                continue;
            }

            // Mark this hash as requested from this peer
            {
                let mut requested = self.requested_from_peer.lock().await;
                let cache = requested.entry(peer_id).or_insert_with(|| {
                    LruCache::new(NonZeroUsize::new(MAX_REQUESTED_HASHES_PER_PEER).unwrap())
                });
                cache.put(hash_hex.clone(), ());
            }

            // Set up response channel (keyed by hash since no request IDs)
            let (resp_tx, resp_rx) = oneshot::channel();
            {
                let mut pending = self.pending_requests.write().await;
                pending.insert((peer_id, hash_hex.clone()), resp_tx);
            }

            // Send request to peer with the decremented HTL
            let req = DataRequest {
                h: hash.to_vec(),
                htl: peer_htl,
            };
            if let Ok(wire) = encode_request(&req) {
                let _ = tx.send(Message::Binary(wire)).await;
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
                pending.remove(&(peer_id, hash_hex.clone()));
            }

            match result {
                Ok(Ok(Some(data))) => {
                    debug!("Got data from peer {} for {}", peer_id, hash_short);
                    return Some(data);
                }
                Ok(Ok(None)) => {
                    debug!("Peer {} doesn't have {}", peer_id, hash_short);
                }
                Ok(Err(_)) => {
                    debug!("Peer {} channel closed", peer_id);
                }
                Err(_) => {
                    debug!("Peer {} timeout for {}", peer_id, hash_short);
                }
            }
        }

        None
    }

    /// Handle a response from a peer (for forwarded requests)
    async fn handle_peer_response(&self, peer_id: u64, hash: &[u8], data: Option<Vec<u8>>) {
        let hash_hex = hash_to_hex(hash);
        let mut pending = self.pending_requests.write().await;
        if let Some(tx) = pending.remove(&(peer_id, hash_hex)) {
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

    /// Create with an existing peer registry (shared with HTTP handlers)
    pub fn with_peers(store: Arc<HashtreeStore>, peers: Arc<PeerRegistry>) -> Self {
        Self { store, peers }
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

    // Process incoming messages (all MessagePack encoded)
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(Message::Binary(data)) => {
                if let Err(e) = handle_message(&data, peer_id, &state, &tx).await {
                    warn!("Error handling message: {}", e);
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {} // Ping/Pong handled by axum, Text ignored (protocol is MessagePack only)
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

/// Handle a MessagePack data message
async fn handle_message(
    data: &[u8],
    peer_id: u64,
    state: &DataWsState,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    let msg = parse_message(data)?;

    match msg {
        DataMessage::Request(req) => {
            handle_request(&req.h, req.htl, peer_id, state, tx).await?;
        }
        DataMessage::Response(res) => {
            // Response from a peer with data
            state.peers.handle_peer_response(peer_id, &res.h, Some(res.d)).await;
        }
    }

    Ok(())
}

/// Handle a data request
async fn handle_request(
    hash: &[u8],
    htl: u8,
    peer_id: u64,
    state: &DataWsState,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    let hash_hex = hash_to_hex(hash);
    let hash_short = &hash_hex[..16.min(hash_hex.len())];

    // First, try local storage
    let result = state.store.get_file(&hash_hex);

    match result {
        Ok(Some(data)) => {
            send_found_response(hash, &data, tx).await?;
            return Ok(());
        }
        Ok(None) => {
            // Not in local storage, try forwarding to other peers
            debug!("Hash {} not in local storage, forwarding to peers", hash_short);
        }
        Err(e) => {
            warn!("Store error for hash {}: {}", hash_hex, e);
        }
    }

    // HTL was already decremented by sender before sending to us.
    // We just check if we should forward (HTL > 0).
    // When we forward to other peers, forward_request will decrement using each peer's config.
    if !should_forward(htl) {
        debug!("HTL expired for {}, not forwarding", hash_short);
        // Stay silent - requester will timeout
        return Ok(());
    }

    // Forward to other peers
    // The forward_request will decrement HTL using each peer's config before sending
    if let Some(data) = state.peers.forward_request(peer_id, hash, htl).await {
        // Store locally for future requests (put_blob computes hash internally)
        if let Err(e) = state.store.put_blob(&data) {
            warn!("Failed to cache forwarded data: {}", e);
        }
        send_found_response(hash, &data, tx).await?;
    }

    // Not found - stay silent, requester will timeout
    Ok(())
}

async fn send_found_response(
    hash: &[u8],
    data: &[u8],
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    // Send response with embedded data
    let response = DataResponse {
        h: hash.to_vec(),
        d: data.to_vec(),
    };
    let wire = encode_response(&response)?;
    tx.send(Message::Binary(wire)).await?;

    let hash_hex = hash_to_hex(hash);
    debug!("Sent {} bytes for hash {}", data.len(), &hash_hex[..16.min(hash_hex.len())]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_message_msgpack_request() {
        let hash = vec![0xab; 32];
        let req = DataRequest {
            h: hash.clone(),
            htl: MAX_HTL,
        };
        let encoded = encode_request(&req).unwrap();
        let decoded = parse_message(&encoded).unwrap();
        match decoded {
            DataMessage::Request(req) => {
                assert_eq!(req.h, hash);
                assert_eq!(req.htl, MAX_HTL);
            }
            _ => panic!("Expected Request"),
        }
    }

    #[test]
    fn test_data_message_msgpack_response() {
        let hash = vec![0xcd; 32];
        let res = DataResponse {
            h: hash.clone(),
            d: vec![1, 2, 3, 4, 5],
        };
        let encoded = encode_response(&res).unwrap();
        let decoded = parse_message(&encoded).unwrap();
        match decoded {
            DataMessage::Response(res) => {
                assert_eq!(res.h, hash);
                assert_eq!(res.d, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_data_message_msgpack_large_data() {
        // Test with 16KB of data (BT v2 chunk size)
        let large_data: Vec<u8> = (0..16 * 1024).map(|i| (i % 256) as u8).collect();
        let hash = vec![0x12; 32];
        let res = DataResponse {
            h: hash.clone(),
            d: large_data.clone(),
        };
        let encoded = encode_response(&res).unwrap();
        let decoded = parse_message(&encoded).unwrap();
        match decoded {
            DataMessage::Response(res) => {
                assert_eq!(res.d.len(), 16 * 1024);
                assert_eq!(res.d[0], 0);
                assert_eq!(res.d[255], 255);
            }
            _ => panic!("Expected Response"),
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
        let test_hash = vec![0x34; 32];
        let result = registry.forward_request(999, &test_hash, MAX_HTL).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_peer_registry_forward_request_excludes_self() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);

        let id = registry.register(tx).await;

        // Forward should exclude the peer making the request
        // Since there's only one peer (which is excluded), should return None
        let test_hash = vec![0x12; 32];
        let result = registry.forward_request(id, &test_hash, MAX_HTL).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_peer_response_handling() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);
        let peer_id = registry.register(tx).await;

        // Create a pending request (keyed by hash hex)
        let test_hash = vec![0xab; 32];
        let hash_hex = hash_to_hex(&test_hash);
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = registry.pending_requests.write().await;
            pending.insert((peer_id, hash_hex.clone()), resp_tx);
        }

        // Handle response
        let test_data = vec![1, 2, 3, 4];
        registry.handle_peer_response(peer_id, &test_hash, Some(test_data.clone())).await;

        // Should receive the data
        let result = resp_rx.await.unwrap();
        assert_eq!(result, Some(test_data));
    }

    #[tokio::test]
    async fn test_peer_response_not_found() {
        let registry = PeerRegistry::new();
        let (tx, _rx) = mpsc::channel(32);
        let peer_id = registry.register(tx).await;

        // Create a pending request (keyed by hash hex)
        let test_hash = vec![0xcd; 32];
        let hash_hex = hash_to_hex(&test_hash);
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = registry.pending_requests.write().await;
            pending.insert((peer_id, hash_hex.clone()), resp_tx);
        }

        // Handle response with None (not found)
        registry.handle_peer_response(peer_id, &test_hash, None).await;

        // Should receive None
        let result = resp_rx.await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_binary_message_format() {
        // Test the new wire format: [type byte][msgpack body]
        let hash = vec![0x12; 32];
        let req = DataRequest { h: hash.clone(), htl: 10 };
        let wire = encode_request(&req).unwrap();

        // Verify format: first byte is type
        assert_eq!(wire[0], 0x00); // MSG_TYPE_REQUEST

        // Verify we can parse it back
        let parsed = parse_message(&wire).unwrap();
        match parsed {
            DataMessage::Request(req) => {
                assert_eq!(req.h, hash);
                assert_eq!(req.htl, 10);
            }
            _ => panic!("Expected Request"),
        }
    }

    #[tokio::test]
    async fn test_http_rate_limit_per_client() {
        let registry = PeerRegistry::new();

        // First 10 queries from client A should be allowed
        for i in 0..HTTP_PEER_QUERY_LIMIT {
            assert!(registry.check_http_rate_limit("192.168.1.1").await,
                    "Query {} from client A should be allowed", i);
        }

        // 11th query from client A should be rate limited
        assert!(!registry.check_http_rate_limit("192.168.1.1").await,
                "Query beyond limit from client A should be blocked");

        // But client B should still be allowed
        assert!(registry.check_http_rate_limit("192.168.1.2").await,
                "Query from different client B should be allowed");
    }
}
