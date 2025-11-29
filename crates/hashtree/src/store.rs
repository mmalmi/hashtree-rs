//! Content-addressed key-value store interfaces and implementations

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::types::{to_hex, Hash};

/// Content-addressed key-value store interface
#[async_trait]
pub trait Store: Send + Sync {
    /// Store data by its hash
    /// Returns true if newly stored, false if already existed
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError>;

    /// Retrieve data by hash
    /// Returns data or None if not found
    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError>;

    /// Check if hash exists
    async fn has(&self, hash: &Hash) -> Result<bool, StoreError>;

    /// Delete by hash
    /// Returns true if deleted, false if didn't exist
    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError>;
}

/// Store error type
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Store error: {0}")]
    Other(String),
}

/// In-memory content-addressed store
/// Useful for testing and temporary data
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get number of stored items
    pub fn size(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Get total bytes stored
    pub fn total_bytes(&self) -> usize {
        self.data
            .read()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.data.write().unwrap().clear();
    }

    /// List all hashes
    pub fn keys(&self) -> Vec<Hash> {
        self.data
            .read()
            .unwrap()
            .keys()
            .filter_map(|hex| {
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Some(hash)
            })
            .collect()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        let key = to_hex(&hash);
        let mut store = self.data.write().unwrap();
        if store.contains_key(&key) {
            return Ok(false);
        }
        // Store a copy to prevent external mutation
        store.insert(key, data);
        Ok(true)
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        let key = to_hex(hash);
        let store = self.data.read().unwrap();
        // Return a copy to prevent external mutation
        Ok(store.get(&key).cloned())
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        let key = to_hex(hash);
        Ok(self.data.read().unwrap().contains_key(&key))
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        let key = to_hex(hash);
        Ok(self.data.write().unwrap().remove(&key).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[tokio::test]
    async fn test_put_returns_true_for_new() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        let result = store.put(hash, data).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_put_returns_false_for_duplicate() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        store.put(hash, data.clone()).await.unwrap();
        let result = store.put(hash, data).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_get_returns_data() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        store.put(hash, data.clone()).await.unwrap();
        let result = store.get(&hash).await.unwrap();

        assert_eq!(result, Some(data));
    }

    #[tokio::test]
    async fn test_get_returns_none_for_missing() {
        let store = MemoryStore::new();
        let hash = [0u8; 32];

        let result = store.get(&hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_has_returns_true() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        store.put(hash, data).await.unwrap();
        assert!(store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_has_returns_false() {
        let store = MemoryStore::new();
        let hash = [0u8; 32];

        assert!(!store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_returns_true() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        store.put(hash, data).await.unwrap();
        let result = store.delete(&hash).await.unwrap();

        assert!(result);
        assert!(!store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_returns_false() {
        let store = MemoryStore::new();
        let hash = [0u8; 32];

        let result = store.delete(&hash).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_size() {
        let store = MemoryStore::new();
        assert_eq!(store.size(), 0);

        let data1 = vec![1u8];
        let data2 = vec![2u8];
        let hash1 = sha256(&data1);
        let hash2 = sha256(&data2);

        store.put(hash1, data1).await.unwrap();
        store.put(hash2, data2).await.unwrap();

        assert_eq!(store.size(), 2);
    }

    #[tokio::test]
    async fn test_total_bytes() {
        let store = MemoryStore::new();
        assert_eq!(store.total_bytes(), 0);

        let data1 = vec![1u8, 2, 3];
        let data2 = vec![4u8, 5];
        let hash1 = sha256(&data1);
        let hash2 = sha256(&data2);

        store.put(hash1, data1).await.unwrap();
        store.put(hash2, data2).await.unwrap();

        assert_eq!(store.total_bytes(), 5);
    }

    #[tokio::test]
    async fn test_clear() {
        let store = MemoryStore::new();
        let data = vec![1u8, 2, 3];
        let hash = sha256(&data);

        store.put(hash, data).await.unwrap();
        store.clear();

        assert_eq!(store.size(), 0);
        assert!(!store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_keys() {
        let store = MemoryStore::new();
        assert!(store.keys().is_empty());

        let data1 = vec![1u8];
        let data2 = vec![2u8];
        let hash1 = sha256(&data1);
        let hash2 = sha256(&data2);

        store.put(hash1, data1).await.unwrap();
        store.put(hash2, data2).await.unwrap();

        let keys = store.keys();
        assert_eq!(keys.len(), 2);

        let mut hex_keys: Vec<_> = keys.iter().map(to_hex).collect();
        hex_keys.sort();
        let mut expected: Vec<_> = vec![to_hex(&hash1), to_hex(&hash2)];
        expected.sort();
        assert_eq!(hex_keys, expected);
    }
}
