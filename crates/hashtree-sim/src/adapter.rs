//! Network adapter for HashTree
//!
//! Bridges the HashTree Store trait with the simulated network,
//! allowing nodes to fetch content from peers via the simulation.
//!
//! ## Architecture
//!
//! The NetworkAdapter provides a unified interface that:
//! 1. Checks local storage first (immediate)
//! 2. Falls back to network requests (async via channels)
//!
//! This allows HashTree operations to transparently work with
//! the discrete event simulation.

use async_trait::async_trait;
use hashtree::{Hash, Store, StoreError};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::node::NodeId;
use crate::store::SimStore;

/// A fetch request to the network
#[derive(Debug)]
pub struct FetchRequest {
    pub hash: Hash,
    pub requesting_node: NodeId,
    pub respond_to: oneshot::Sender<FetchResult>,
}

/// Result of a network fetch
#[derive(Debug, Clone)]
pub enum FetchResult {
    Found(Vec<u8>),
    NotFound,
    Error(String),
}

/// Network adapter that implements Store trait
///
/// This is the primary interface for HashTree operations in the simulation.
/// It provides a unified view of local + network storage.
pub struct NetworkAdapter {
    /// This node's ID
    node_id: NodeId,
    /// Local store for immediate access
    local: Arc<SimStore>,
    /// Channel to send network fetch requests (None = local only mode)
    fetch_tx: Option<mpsc::Sender<FetchRequest>>,
}

impl NetworkAdapter {
    /// Create a new network adapter with network access
    pub fn new(
        node_id: NodeId,
        local: Arc<SimStore>,
        fetch_tx: mpsc::Sender<FetchRequest>,
    ) -> Self {
        Self {
            node_id,
            local,
            fetch_tx: Some(fetch_tx),
        }
    }

    /// Create a simple adapter that only uses local storage (no network)
    pub fn local_only(node_id: NodeId, local: Arc<SimStore>) -> Self {
        Self {
            node_id,
            local,
            fetch_tx: None,
        }
    }

    /// Get the node ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get the local store
    pub fn local(&self) -> &Arc<SimStore> {
        &self.local
    }

    /// Check if network access is available
    pub fn has_network(&self) -> bool {
        self.fetch_tx.is_some()
    }
}

#[async_trait]
impl Store for NetworkAdapter {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        // Put always goes to local store
        self.local.put(hash, data).await
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local.get(hash).await? {
            return Ok(Some(data));
        }

        // Not local - try network if available
        let fetch_tx = match &self.fetch_tx {
            Some(tx) => tx,
            None => return Ok(None), // Local only mode
        };

        let (tx, rx) = oneshot::channel();
        let request = FetchRequest {
            hash: *hash,
            requesting_node: self.node_id,
            respond_to: tx,
        };

        if fetch_tx.send(request).await.is_err() {
            // Channel closed - network not available
            return Ok(None);
        }

        match rx.await {
            Ok(FetchResult::Found(data)) => {
                // Cache locally
                let _ = self.local.put(*hash, data.clone()).await;
                Ok(Some(data))
            }
            Ok(FetchResult::NotFound) => Ok(None),
            Ok(FetchResult::Error(e)) => Err(StoreError::Other(e)),
            Err(_) => Ok(None), // Channel closed
        }
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        // Only check local - network check would need a full get
        self.local.has(hash).await
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local.delete(hash).await
    }
}

/// Mock network for testing HashTree operations
///
/// Simulates a network of nodes where content can be fetched
/// from any node that has it. This is simpler than the full
/// discrete event Network - it's synchronous and doesn't simulate latency.
///
/// Use this for unit tests. Use the full `Network` for latency/behavior testing.
pub struct MockNetwork {
    /// All nodes in the network
    nodes: Vec<Arc<SimStore>>,
    /// Fetch request receiver
    fetch_rx: mpsc::Receiver<FetchRequest>,
    /// Fetch request sender (for creating adapters)
    fetch_tx: mpsc::Sender<FetchRequest>,
}

impl MockNetwork {
    /// Create a new mock network
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            nodes: Vec::new(),
            fetch_rx: rx,
            fetch_tx: tx,
        }
    }

    /// Add a node's store to the network
    pub fn add_node(&mut self, store: Arc<SimStore>) {
        self.nodes.push(store);
    }

    /// Create a network adapter for a node
    pub fn create_adapter(&self, node_id: NodeId, local: Arc<SimStore>) -> NetworkAdapter {
        NetworkAdapter::new(node_id, local, self.fetch_tx.clone())
    }

    /// Find content across all nodes (synchronous lookup)
    fn find_content(&self, hash: &Hash) -> FetchResult {
        for node in &self.nodes {
            if let Some(data) = node.get_local(hash) {
                return FetchResult::Found(data);
            }
        }
        FetchResult::NotFound
    }

    /// Run the network in a background task
    ///
    /// This spawns a task that processes fetch requests by searching
    /// all nodes for the requested content.
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(request) = self.fetch_rx.recv().await {
                let result = self.find_content(&request.hash);
                let _ = request.respond_to.send(result);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashtree::{sha256, HashTree, HashTreeConfig};

    #[tokio::test]
    async fn test_local_only_adapter() {
        let store = Arc::new(SimStore::new(1));
        let adapter = Arc::new(NetworkAdapter::local_only(1, store));

        assert!(!adapter.has_network());

        let tree = HashTree::new(HashTreeConfig::new(adapter.clone()).public());

        let data = b"local only content";
        let cid = tree.put(data).await.unwrap();

        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_mock_network_fetch() {
        let mut network = MockNetwork::new(100);

        // Node 1 has content
        let node1_store = Arc::new(SimStore::new(1));
        let data = b"shared content";
        let hash = sha256(data);
        node1_store.put_local(hash, data.to_vec());
        network.add_node(node1_store.clone());

        // Node 2 doesn't have it locally
        let node2_store = Arc::new(SimStore::new(2));
        network.add_node(node2_store.clone());

        // Create adapter for node 2
        let adapter = Arc::new(network.create_adapter(2, node2_store.clone()));
        assert!(adapter.has_network());

        // Spawn network handler
        let handle = network.spawn();

        // Node 2 should be able to fetch from network
        let tree = HashTree::new(HashTreeConfig::new(adapter.clone()).public());

        // Create a Cid for the existing content
        let cid = hashtree::Cid {
            hash,
            key: None,
            size: data.len() as u64,
        };

        let retrieved = tree.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        // Should now be cached locally
        assert!(node2_store.has_local(&hash));

        // Clean up
        handle.abort();
    }

    #[tokio::test]
    async fn test_mock_network_not_found() {
        let mut network = MockNetwork::new(100);

        let node_store = Arc::new(SimStore::new(1));
        network.add_node(node_store.clone());

        let adapter = Arc::new(network.create_adapter(1, node_store));
        let handle = network.spawn();

        let tree = HashTree::new(HashTreeConfig::new(adapter).public());

        // Try to get non-existent content
        let fake_hash = [42u8; 32];
        let cid = hashtree::Cid {
            hash: fake_hash,
            key: None,
            size: 0,
        };

        let result = tree.get(&cid).await.unwrap();
        assert!(result.is_none());

        handle.abort();
    }

    #[tokio::test]
    async fn test_chunked_content_across_network() {
        let mut network = MockNetwork::new(100);

        // Node 1 stores chunked content
        let node1_store = Arc::new(SimStore::new(1));
        let adapter1 = Arc::new(NetworkAdapter::local_only(1, node1_store.clone()));
        let tree1 = HashTree::new(
            HashTreeConfig::new(adapter1)
                .public()
                .with_chunk_size(50),
        );

        // Store large content (will be chunked)
        let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        let cid = tree1.put(&data).await.unwrap();

        network.add_node(node1_store.clone());

        // Node 2 fetches it
        let node2_store = Arc::new(SimStore::new(2));
        network.add_node(node2_store.clone());

        let adapter2 = Arc::new(network.create_adapter(2, node2_store.clone()));
        let handle = network.spawn();

        let tree2 = HashTree::new(HashTreeConfig::new(adapter2).public());

        // Fetch the chunked content
        let retrieved = tree2.get(&cid).await.unwrap().unwrap();
        assert_eq!(retrieved, data);

        // Node 2 should have cached all chunks
        assert!(node2_store.size() > 0);

        handle.abort();
    }
}
