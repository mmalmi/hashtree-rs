//! Store implementations for simulation
//!
//! - `SimStore` - local-only storage
//! - `NetworkStore` trait - adds network fetch capability
//! - Different NetworkStore implementations for different routing strategies

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::NodeId;

/// Local store implementation for a simulated node
///
/// This implements the hashtree Store trait for local-only storage.
#[derive(Debug, Clone)]
pub struct SimStore {
    /// Local data storage
    data: Arc<RwLock<HashMap<Hash, Vec<u8>>>>,
    /// Node ID for logging/debugging
    #[allow(dead_code)]
    pub node_id: NodeId,
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

    /// Get direct access to stored data
    pub fn get_local(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.data.read().unwrap().get(hash).cloned()
    }

    /// Put data directly
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

/// Network-aware store trait
///
/// Extends Store with network fetch capability. Different implementations
/// use different routing strategies (flooding, sequential, etc.)
#[async_trait]
pub trait NetworkStore: Store + Send + Sync {
    /// Fetch from network (called when local lookup fails)
    async fn fetch_from_network(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError>;

    /// Get bytes sent
    fn bytes_sent(&self) -> u64;

    /// Get bytes received
    fn bytes_received(&self) -> u64;
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

        assert!(store.put(hash, data.to_vec()).await.unwrap());
        assert!(!store.put(hash, data.to_vec()).await.unwrap());

        let result = store.get(&hash).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));

        assert!(store.has(&hash).await.unwrap());
        assert!(store.delete(&hash).await.unwrap());
        assert!(!store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_hashtree_with_sim_store() {
        let store = Arc::new(SimStore::new(1));
        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        let data = b"Hello from simulated node!";
        let cid = tree.put(data).await.unwrap();

        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        assert!(store.has_local(&cid.hash));
    }
}
