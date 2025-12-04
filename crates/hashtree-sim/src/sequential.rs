//! Sequential NetworkStore implementation
//!
//! Sends request to one peer at a time, waits for response or not_found,
//! then tries next peer. Lower bandwidth, higher latency.

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::channel::{ChannelError, PeerChannel};
use crate::message::{
    encode_not_found, encode_request, encode_response, parse, ParsedMessage, RequestId,
};
use crate::store::{NetworkStore, SimStore};

/// Sequential store - tries one peer at a time with not_found responses
pub struct SequentialStore {
    /// Local storage
    local: Arc<SimStore>,
    /// Connected peer channels
    peers: RwLock<Vec<Arc<dyn PeerChannel>>>,
    /// Per-peer timeout
    peer_timeout: Duration,
    /// Next request ID
    next_request_id: AtomicU32,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
}

impl SequentialStore {
    pub fn new(local: Arc<SimStore>, peer_timeout: Duration) -> Self {
        Self {
            local,
            peers: RwLock::new(Vec::new()),
            peer_timeout,
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

        let request_id = self.next_request_id();
        let request_bytes = encode_request(request_id, hash);

        // Try each peer sequentially
        for peer in peers.iter() {
            // Send request
            self.bytes_sent
                .fetch_add(request_bytes.len() as u64, Ordering::Relaxed);

            if peer.send(request_bytes.clone()).await.is_err() {
                continue; // Try next peer
            }

            // Wait for response
            match peer.recv(self.peer_timeout).await {
                Ok(response_bytes) => {
                    self.bytes_received
                        .fetch_add(response_bytes.len() as u64, Ordering::Relaxed);

                    match parse(&response_bytes) {
                        Ok(ParsedMessage::Response { id, hash: h, data })
                            if id == request_id && h == *hash =>
                        {
                            // Verify data matches hash
                            if hashtree::sha256(&data) == *hash {
                                // Cache locally and return
                                let _ = self.local.put(*hash, data.clone()).await;
                                return Ok(Some(data));
                            }
                            // Malicious: wrong data, try next peer
                        }
                        Ok(ParsedMessage::NotFound { id, hash: h })
                            if id == request_id && h == *hash =>
                        {
                            // Peer doesn't have it, try next
                            continue;
                        }
                        _ => {
                            // Garbage or wrong message, try next peer
                            continue;
                        }
                    }
                }
                Err(ChannelError::Timeout) => {
                    // Timeout, try next peer
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
/// Unlike flooding, this always responds (with data or not_found)
pub async fn handle_request(local: &SimStore, request_bytes: &[u8]) -> Option<Vec<u8>> {
    match parse(request_bytes) {
        Ok(ParsedMessage::Request { id, hash }) => {
            if let Some(data) = local.get_local(&hash) {
                Some(encode_response(id, &hash, &data))
            } else {
                Some(encode_not_found(id, &hash))
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
        let hash = hashtree::sha256(data);
        local.put_local(hash, data.to_vec());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_sequential_first_peer_has_it() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_secs(1)));

        let local2 = Arc::new(SimStore::new(2));
        let data = b"peer data";
        let hash = hashtree::sha256(data);
        local2.put_local(hash, data.to_vec());

        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(Arc::new(chan1)).await;

        let local2_clone = local2.clone();
        let handle = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&local2_clone, &recv).await {
                chan2.send(response).await.unwrap();
            }
        });

        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
        assert!(local1.has_local(&hash));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_sequential_not_found_tries_next() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_secs(1)));

        // Peer 2 doesn't have data
        let local2 = Arc::new(SimStore::new(2));
        // Peer 3 has data
        let local3 = Arc::new(SimStore::new(3));
        let data = b"found on third";
        let hash = hashtree::sha256(data);
        local3.put_local(hash, data.to_vec());

        let (chan1_2, chan2) = MockChannel::pair(1, 2);
        let (chan1_3, chan3) = MockChannel::pair(1, 3);
        store1.add_peer(Arc::new(chan1_2)).await;
        store1.add_peer(Arc::new(chan1_3)).await;

        // Handler for peer 2 (will send not_found)
        let local2_clone = local2.clone();
        let handle2 = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&local2_clone, &recv).await {
                chan2.send(response).await.unwrap();
            }
        });

        // Handler for peer 3 (will send data)
        let local3_clone = local3.clone();
        let handle3 = tokio::spawn(async move {
            let recv = chan3.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&local3_clone, &recv).await {
                chan3.send(response).await.unwrap();
            }
        });

        let result = store1.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        handle2.await.unwrap();
        handle3.await.unwrap();
    }

    #[tokio::test]
    async fn test_sequential_all_not_found() {
        let local1 = Arc::new(SimStore::new(1));
        let store1 = Arc::new(SequentialStore::new(local1.clone(), Duration::from_secs(1)));

        let local2 = Arc::new(SimStore::new(2));
        let (chan1, chan2) = MockChannel::pair(1, 2);
        store1.add_peer(Arc::new(chan1)).await;

        let local2_clone = local2.clone();
        let handle = tokio::spawn(async move {
            let recv = chan2.recv(Duration::from_secs(1)).await.unwrap();
            if let Some(response) = handle_request(&local2_clone, &recv).await {
                chan2.send(response).await.unwrap();
            }
        });

        let hash = [42u8; 32];
        let result = store1.get(&hash).await.unwrap();
        assert!(result.is_none());

        handle.await.unwrap();
    }
}
