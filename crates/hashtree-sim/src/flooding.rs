//! Flooding NetworkStore implementation
//!
//! Sends request to all peers simultaneously, returns first valid response.
//! High bandwidth, low latency.

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::channel::PeerChannel;
use crate::message::{encode_request, encode_response, parse, ParsedMessage, RequestId};
use crate::store::{NetworkStore, SimStore};

/// Flooding store - sends to all peers, returns first response
pub struct FloodingStore {
    /// Local storage
    local: Arc<SimStore>,
    /// Connected peer channels
    peers: RwLock<Vec<Arc<dyn PeerChannel>>>,
    /// Request timeout
    timeout: Duration,
    /// Next request ID
    next_request_id: AtomicU32,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
}

impl FloodingStore {
    pub fn new(local: Arc<SimStore>, timeout: Duration) -> Self {
        Self {
            local,
            peers: RwLock::new(Vec::new()),
            timeout,
            next_request_id: AtomicU32::new(1),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Add a peer channel
    pub async fn add_peer(&self, channel: Arc<dyn PeerChannel>) {
        self.peers.write().await.push(channel);
    }

    /// Remove disconnected peers
    pub async fn cleanup_peers(&self) {
        self.peers.write().await.retain(|p| p.is_connected());
    }

    fn next_request_id(&self) -> RequestId {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }
}

#[async_trait]
impl Store for FloodingStore {
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
impl NetworkStore for FloodingStore {
    async fn fetch_from_network(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return Ok(None);
        }

        let request_id = self.next_request_id();
        let request_bytes = encode_request(request_id, hash);
        let request_len = request_bytes.len() as u64;

        // Send to all peers
        let mut handles = Vec::new();
        for peer in peers.iter() {
            let peer = peer.clone();
            let request = request_bytes.clone();
            let timeout = self.timeout;
            let expected_hash = *hash;

            handles.push(tokio::spawn(async move {
                // Send request
                if peer.send(request).await.is_err() {
                    return None;
                }

                // Wait for response
                match peer.recv(timeout).await {
                    Ok(response_bytes) => {
                        // Parse and validate
                        match parse(&response_bytes) {
                            Ok(ParsedMessage::Response { id, hash, data })
                                if id == request_id && hash == expected_hash =>
                            {
                                // Verify data matches hash
                                if hashtree::sha256(&data) == expected_hash {
                                    Some((data, response_bytes.len() as u64))
                                } else {
                                    None // Malicious: wrong data
                                }
                            }
                            _ => None, // Wrong message type or garbage
                        }
                    }
                    Err(_) => None,
                }
            }));
        }

        // Track bytes sent
        self.bytes_sent
            .fetch_add(request_len * peers.len() as u64, Ordering::Relaxed);
        drop(peers);

        // Wait for first valid response
        let mut result = None;
        for handle in handles {
            if let Ok(Some((data, recv_bytes))) = handle.await {
                self.bytes_received.fetch_add(recv_bytes, Ordering::Relaxed);
                // Cache locally
                let _ = self.local.put(*hash, data.clone()).await;
                result = Some(data);
                break;
            }
        }

        Ok(result)
    }

    fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Handler for responding to flooding requests (run on peer side)
pub async fn handle_request(
    local: &SimStore,
    request_bytes: &[u8],
) -> Option<Vec<u8>> {
    match parse(request_bytes) {
        Ok(ParsedMessage::Request { id, hash }) => {
            if let Some(data) = local.get_local(&hash) {
                Some(encode_response(id, &hash, &data))
            } else {
                None // Don't respond if we don't have it (flooding doesn't use not_found)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::MockChannel;

    #[tokio::test]
    async fn test_flooding_local_hit() {
        let local = Arc::new(SimStore::new(1));
        let store = FloodingStore::new(local.clone(), Duration::from_secs(1));

        let data = b"test data";
        let hash = hashtree::sha256(data);
        local.put_local(hash, data.to_vec());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_flooding_network_fetch() {
        // Node 1 (requester)
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(FloodingStore::new(local1.clone(), Duration::from_secs(1)));

        // Node 2 (has data)
        let local2 = Arc::new(SimStore::new(2));
        let data = b"network data";
        let hash = hashtree::sha256(data);
        local2.put_local(hash, data.to_vec());

        // Connect them
        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(Arc::new(chan1)).await;

        // Spawn handler for node 2
        let local2_clone = local2.clone();
        let handle = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&local2_clone, &recv).await {
                chan2.send(response).await.unwrap();
            }
        });

        // Fetch from node 1
        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        // Should be cached locally now
        assert!(local1.has_local(&hash));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_flooding_no_peers() {
        let local = Arc::new(SimStore::new(1));
        let store = FloodingStore::new(local, Duration::from_secs(1));

        let hash = [42u8; 32];
        let result = store.get(&hash).await.unwrap();
        assert!(result.is_none());
    }
}
