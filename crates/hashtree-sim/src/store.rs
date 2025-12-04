//! SimStore - Store adapter for simulated nodes
//!
//! Wraps a shared storage map and routes requests through message channels
//! to simulate network delays and node behaviors.

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

use crate::node::NodeId;

/// Request types for store operations (for future async message passing)
#[derive(Debug)]
#[allow(dead_code)]
pub enum StoreRequest {
    Get {
        hash: Hash,
        respond_to: oneshot::Sender<Option<Vec<u8>>>,
    },
    Put {
        hash: Hash,
        data: Vec<u8>,
        respond_to: oneshot::Sender<bool>,
    },
    Has {
        hash: Hash,
        respond_to: oneshot::Sender<bool>,
    },
}

/// Local store implementation for a simulated node
///
/// This implements the hashtree Store trait, allowing SimNodes to use
/// real HashTree operations for merkle tree building and traversal.
#[derive(Debug, Clone)]
pub struct SimStore {
    /// Local data storage (shared within the node)
    data: Arc<RwLock<HashMap<Hash, Vec<u8>>>>,
    /// Node ID for logging/debugging
    #[allow(dead_code)]
    node_id: NodeId,
}

impl SimStore {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            node_id,
        }
    }

    /// Create from existing data (for testing)
    pub fn with_data(node_id: NodeId, data: HashMap<Hash, Vec<u8>>) -> Self {
        Self {
            data: Arc::new(RwLock::new(data)),
            node_id,
        }
    }

    /// Get direct access to stored data (for simulation)
    pub fn get_local(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.data.read().unwrap().get(hash).cloned()
    }

    /// Put data directly (for simulation seeding)
    pub fn put_local(&self, hash: Hash, data: Vec<u8>) -> bool {
        let mut store = self.data.write().unwrap();
        if store.contains_key(&hash) {
            return false;
        }
        store.insert(hash, data);
        true
    }

    /// Check if data exists locally
    pub fn has_local(&self, hash: &Hash) -> bool {
        self.data.read().unwrap().contains_key(hash)
    }

    /// Get number of stored items
    pub fn size(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Get all hashes
    pub fn hashes(&self) -> Vec<Hash> {
        self.data.read().unwrap().keys().copied().collect()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.data.write().unwrap().clear();
    }
}

#[async_trait]
impl Store for SimStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        Ok(self.put_local(hash, data))
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.get_local(hash))
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self.has_local(hash))
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self.data.write().unwrap().remove(hash).is_some())
    }
}

/// Network-aware store that sends requests through channels
///
/// Used when a node needs to fetch data from the network (not just local store).
/// Requests go through the simulation's message routing.
pub struct NetworkStore {
    /// Local store for immediate access
    local: SimStore,
    /// Channel to send network requests
    request_tx: mpsc::Sender<NetworkRequest>,
}

/// Network request for fetching data from other nodes
#[derive(Debug)]
pub struct NetworkRequest {
    pub hash: Hash,
    pub requesting_node: NodeId,
    pub respond_to: oneshot::Sender<Option<Vec<u8>>>,
}

impl NetworkStore {
    pub fn new(local: SimStore, request_tx: mpsc::Sender<NetworkRequest>) -> Self {
        Self { local, request_tx }
    }

    /// Get the local store reference
    pub fn local(&self) -> &SimStore {
        &self.local
    }
}

#[async_trait]
impl Store for NetworkStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        // Put always goes to local store
        self.local.put(hash, data).await
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local.get(hash).await? {
            return Ok(Some(data));
        }

        // Not local - request from network
        let (tx, rx) = oneshot::channel();
        let request = NetworkRequest {
            hash: *hash,
            requesting_node: self.local.node_id,
            respond_to: tx,
        };

        if self.request_tx.send(request).await.is_err() {
            return Err(StoreError::Other("network channel closed".to_string()));
        }

        match rx.await {
            Ok(data) => Ok(data),
            Err(_) => Err(StoreError::Other("network response channel closed".to_string())),
        }
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        // Only check local - network check would be a full get
        self.local.has(hash).await
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.delete(hash).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashtree::{sha256, HashTree, HashTreeConfig};

    #[tokio::test]
    async fn test_sim_store_basic() {
        let store = SimStore::new(1);

        let data = b"hello world";
        let hash = sha256(data);

        // Put should return true for new data
        assert!(store.put(hash, data.to_vec()).await.unwrap());

        // Put should return false for duplicate
        assert!(!store.put(hash, data.to_vec()).await.unwrap());

        // Get should return the data
        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        // Has should return true
        assert!(store.has(&hash).await.unwrap());

        // Delete should return true
        assert!(store.delete(&hash).await.unwrap());

        // Has should now return false
        assert!(!store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_sim_store_local_methods() {
        let store = SimStore::new(42);

        let data = b"test data";
        let hash = sha256(data);

        // Local methods should work
        assert!(store.put_local(hash, data.to_vec()));
        assert!(store.has_local(&hash));
        assert_eq!(store.get_local(&hash), Some(data.to_vec()));
        assert_eq!(store.size(), 1);

        let hashes = store.hashes();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash);
    }

    #[tokio::test]
    async fn test_hashtree_with_sim_store() {
        // Create a SimStore and wrap in Arc for HashTree
        let store = Arc::new(SimStore::new(1));

        // Create a HashTree using our SimStore (public mode for testing)
        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        // Store content through HashTree
        let data = b"Hello from simulated node!";
        let cid = tree.put(data).await.unwrap();

        // Verify we can retrieve it
        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        // Verify the store has the content
        assert!(store.has_local(&cid.hash));
        assert_eq!(store.size(), 1);
    }

    #[tokio::test]
    async fn test_hashtree_chunked_content() {
        let store = Arc::new(SimStore::new(2));

        // Small chunk size to force chunking
        let tree = HashTree::new(
            HashTreeConfig::new(store.clone())
                .public()
                .with_chunk_size(50),
        );

        // Data larger than chunk size
        let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        let cid = tree.put(&data).await.unwrap();

        // Verify round-trip
        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        // Store should have multiple chunks + tree node
        assert!(store.size() > 1);
    }
}
