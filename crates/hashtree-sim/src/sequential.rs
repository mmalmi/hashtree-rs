//! Sequential NetworkStore implementation
//!
//! Sends request to one peer at a time, waits for response or timeout,
//! then tries next peer. Lower bandwidth, higher latency.

use async_trait::async_trait;
use hashtree_core::{Hash, Store, StoreError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::channel::{ChannelError, PeerChannel};
use crate::message::{encode_request, encode_response, parse, ParsedMessage, MAX_HTL};
use crate::store::{NetworkStore, SimStore};

/// Sequential store - tries one peer at a time, waits for response or timeout
pub struct SequentialStore {
    /// Local storage
    local: Arc<SimStore>,
    /// Connected peer channels
    peers: RwLock<Vec<Arc<dyn PeerChannel>>>,
    /// Per-peer timeout
    peer_timeout: Duration,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Simulated network latency per send (ms)
    network_latency_ms: u64,
}

impl SequentialStore {
    pub fn new(local: Arc<SimStore>, peer_timeout: Duration) -> Self {
        Self {
            local,
            peers: RwLock::new(Vec::new()),
            peer_timeout,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            network_latency_ms: 0,
        }
    }

    pub fn with_latency(local: Arc<SimStore>, peer_timeout: Duration, network_latency_ms: u64) -> Self {
        Self {
            local,
            peers: RwLock::new(Vec::new()),
            peer_timeout,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            network_latency_ms,
        }
    }

    /// Send data with simulated network latency
    async fn send_with_latency(&self, peer: &dyn PeerChannel, data: Vec<u8>) -> Result<(), ChannelError> {
        if self.network_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.network_latency_ms)).await;
        }
        peer.send(data).await
    }

    /// Add a peer channel
    pub async fn add_peer(&self, channel: Arc<dyn PeerChannel>) {
        self.peers.write().await.push(channel);
    }

    /// Remove disconnected peers
    pub async fn cleanup_peers(&self) {
        self.peers.write().await.retain(|p| p.is_connected());
    }
}

#[async_trait]
impl Store for SequentialStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        self.local.put(hash, data).await
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local.get(hash).await? {
            return Ok(Some(data));
        }

        // Fetch from network
        self.fetch_from_network(hash).await
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.has(hash).await
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.delete(hash).await
    }
}

#[async_trait]
impl NetworkStore for SequentialStore {
    async fn fetch_from_network(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return Ok(None);
        }

        // Use MAX_HTL for sequential requests (single-hop, no forwarding)
        let request_bytes = encode_request(hash, MAX_HTL);

        // Try each peer sequentially
        for peer in peers.iter() {
            // Send request with latency simulation
            self.bytes_sent
                .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);

            if self.send_with_latency(peer.as_ref(), request_bytes.clone()).await.is_err() {
                continue; // Try next peer
            }

            // Wait for response (peer forwards internally if needed)
            match peer.recv(self.peer_timeout).await {
                Ok(response_bytes) => {
                    self.bytes_received
                        .fetch_add(response_bytes.len() as u64, Ordering::Relaxed);

                    match parse(&response_bytes) {
                        Ok(ParsedMessage::Response(res)) => {
                            if let Some(h) = res.hash() {
                                if h == *hash {
                                    // Verify data matches hash
                                    if hashtree_core::sha256(&res.d) == *hash {
                                        // Cache locally and return
                                        let _ = self.local.put(*hash, res.d.clone()).await;
                                        return Ok(Some(res.d));
                                    }
                                    // Malicious: wrong data, try next peer
                                }
                            }
                            // Wrong hash, try next peer
                            continue;
                        }
                        _ => {
                            // Garbage or wrong message, try next peer
                            continue;
                        }
                    }
                }
                Err(ChannelError::Timeout) => {
                    // Timeout means peer is still searching or doesn't have it
                    // Try next peer
                    continue;
                }
                Err(_) => {
                    // Disconnected, try next peer
                    continue;
                }
            }
        }

        Ok(None)
    }

    fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Handler for responding to sequential requests (run on peer side)
///
/// If the peer has data locally, responds with data.
/// If not, forwards the request to its own peers sequentially.
/// Only responds when data is found - no response means "keep waiting" or timeout.
pub async fn handle_request(store: &SequentialStore, request_bytes: &[u8]) -> Option<Vec<u8>> {
    match parse(request_bytes) {
        Ok(ParsedMessage::Request(req)) => {
            let hash = req.hash()?;

            // First check local storage
            if let Some(data) = store.local.get_local(&hash) {
                return Some(encode_response(&hash, &data));
            }

            // Not found locally - forward to our peers (sequential forwarding)
            // This creates multi-hop routing: each node tries its peers one at a time
            // Only respond if we find the data
            match store.fetch_from_network(&hash).await {
                Ok(Some(data)) => Some(encode_response(&hash, &data)),
                _ => None, // Don't respond if not found - let timeout handle it
            }
        }
        _ => None, // Garbage, don't respond
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::MockChannel;

    #[tokio::test]
    async fn test_sequential_local_hit() {
        let local = Arc::new(SimStore::new(1));
        let store = SequentialStore::new(local.clone(), Duration::from_millis(100));

        let data = b"test data";
        let hash = hashtree_core::sha256(data);
        local.put_local(hash, data.to_vec());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_sequential_first_peer_has_it() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_secs(1)));

        let local2 = Arc::new(SimStore::new(2));
        let store2 = Arc::new(SequentialStore::new(local2.clone(), Duration::from_secs(1)));
        let data = b"peer data";
        let hash = hashtree_core::sha256(data);
        local2.put_local(hash, data.to_vec());

        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(Arc::new(chan1)).await;

        let handle = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&store2, &recv).await {
                chan2.send(response).await.unwrap();
            }
        });

        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
        assert!(local1.has_local(&hash));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_sequential_timeout_tries_next() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_millis(100)));

        // Peer 2 doesn't have data and won't respond (simulating forwarding that times out)
        let local2 = Arc::new(SimStore::new(2));
        let store2 = Arc::new(SequentialStore::new(local2.clone(), Duration::from_millis(100)));
        // Peer 3 has data
        let local3 = Arc::new(SimStore::new(3));
        let store3 = Arc::new(SequentialStore::new(local3.clone(), Duration::from_millis(100)));
        let data = b"found on third";
        let hash = hashtree_core::sha256(data);
        local3.put_local(hash, data.to_vec());

        let (chan1_2, chan2) = MockChannel::pair(1, 2);
        let (chan1_3, chan3) = MockChannel::pair(1, 3);
        store1.add_peer(Arc::new(chan1_2)).await;
        store1.add_peer(Arc::new(chan1_3)).await;

        // Handler for peer 2 (doesn't have it, won't respond)
        let handle2 = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            // No response - simulating that peer 2 doesn't find it
            let _ = handle_request(&store2, &recv).await;
            // Don't send response, let it timeout
        });

        // Handler for peer 3 (will send data)
        let handle3 = tokio::spawn(async move {
            let recv = chan3.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&store3, &recv).await {
                chan3.send(response).await.unwrap();
            }
        });

        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        handle2.await.unwrap();
        handle3.await.unwrap();
    }

    #[tokio::test]
    async fn test_sequential_all_timeout() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_millis(50)));

        let local2 = Arc::new(SimStore::new(2));
        let store2 = Arc::new(SequentialStore::new(local2.clone(), Duration::from_millis(50)));
        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(Arc::new(chan1)).await;

        let handle = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            // Peer doesn't have it, no response
            let _ = handle_request(&store2, &recv).await;
        });

        let hash = [42u8; 32];
        let result = store1.get(&hash).await.unwrap();
        assert!(result.is_none());

        handle.await.unwrap();
    }
}
