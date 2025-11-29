//! BEP52 tree builder with 16 KiB block size
//!
//! Builds BitTorrent v2 compatible merkle trees from file data.

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::merkle::{merkle_num_leafs, merkle_root};
use crate::store::{Store, StoreError};
use crate::{Hash, BEP52_BLOCK_SIZE, ZERO_HASH};

/// Builder configuration
#[derive(Clone)]
pub struct Bep52Config<S: Store> {
    pub store: Option<Arc<S>>,
    pub piece_size: Option<usize>,
}

impl<S: Store> Default for Bep52Config<S> {
    fn default() -> Self {
        Self {
            store: None,
            piece_size: None,
        }
    }
}

impl<S: Store> Bep52Config<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(mut self, store: Arc<S>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_piece_size(mut self, piece_size: usize) -> Self {
        self.piece_size = Some(piece_size);
        self
    }
}

/// Result of building a BEP52 tree
#[derive(Debug, Clone)]
pub struct Bep52Result {
    /// Root hash (pieces root for torrent)
    pub root: Hash,
    /// Total file size
    pub size: u64,
    /// Number of 16KB blocks
    pub block_count: usize,
    /// Leaf hashes (block hashes)
    pub leaf_hashes: Vec<Hash>,
    /// Piece layer hashes (if piece_size configured)
    pub piece_layers: Option<Vec<Hash>>,
}

/// Builder error type
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    #[error("Invalid piece size: {0}")]
    InvalidPieceSize(String),
}

/// Hash a single block of data
fn hash_block(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// BEP52 tree builder
pub struct Bep52TreeBuilder<S: Store> {
    store: Option<Arc<S>>,
    piece_size: Option<usize>,
}

impl<S: Store> Bep52TreeBuilder<S> {
    pub fn new(config: Bep52Config<S>) -> Self {
        Self {
            store: config.store,
            piece_size: config.piece_size,
        }
    }

    /// Build tree from raw data
    pub async fn build_from_data(&self, data: &[u8]) -> Result<Bep52Result, BuilderError> {
        let size = data.len() as u64;

        // Empty file
        if data.is_empty() {
            return Ok(Bep52Result {
                root: ZERO_HASH,
                size: 0,
                block_count: 0,
                leaf_hashes: vec![],
                piece_layers: None,
            });
        }

        // Split into 16KB blocks and hash each
        let mut leaf_hashes: Vec<Hash> = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + BEP52_BLOCK_SIZE).min(data.len());
            let block = &data[offset..end];
            let hash = hash_block(block);

            // Store block if store configured
            if let Some(store) = &self.store {
                store.put(hash, block.to_vec()).await?;
            }

            leaf_hashes.push(hash);
            offset = end;
        }

        self.build_from_hashes(leaf_hashes, size).await
    }

    /// Build tree from pre-computed leaf hashes
    pub async fn build_from_hashes(
        &self,
        leaf_hashes: Vec<Hash>,
        size: u64,
    ) -> Result<Bep52Result, BuilderError> {
        let block_count = leaf_hashes.len();

        if block_count == 0 {
            return Ok(Bep52Result {
                root: ZERO_HASH,
                size,
                block_count: 0,
                leaf_hashes: vec![],
                piece_layers: None,
            });
        }

        // Compute piece layers if configured
        let piece_layers = if let Some(piece_size) = self.piece_size {
            if piece_size < BEP52_BLOCK_SIZE || !piece_size.is_power_of_two() {
                return Err(BuilderError::InvalidPieceSize(
                    "piece_size must be >= 16KB and power of 2".to_string(),
                ));
            }
            let blocks_per_piece = piece_size / BEP52_BLOCK_SIZE;
            Some(self.compute_piece_layers(&leaf_hashes, blocks_per_piece))
        } else {
            None
        };

        // Compute root
        let num_leafs = merkle_num_leafs(block_count);
        let root = merkle_root(&leaf_hashes, Some(num_leafs));

        Ok(Bep52Result {
            root,
            size,
            block_count,
            leaf_hashes,
            piece_layers,
        })
    }

    /// Compute piece layer hashes
    fn compute_piece_layers(&self, leaf_hashes: &[Hash], blocks_per_piece: usize) -> Vec<Hash> {
        leaf_hashes
            .chunks(blocks_per_piece)
            .map(|piece_blocks| {
                let num_leafs = merkle_num_leafs(piece_blocks.len());
                merkle_root(piece_blocks, Some(num_leafs))
            })
            .collect()
    }
}

/// Streaming BEP52 builder for large files
pub struct Bep52StreamBuilder<S: Store> {
    store: Option<Arc<S>>,
    piece_size: Option<usize>,
    buffer: Vec<u8>,
    leaf_hashes: Vec<Hash>,
    total_size: u64,
}

impl<S: Store> Bep52StreamBuilder<S> {
    pub fn new(config: Bep52Config<S>) -> Self {
        Self {
            store: config.store,
            piece_size: config.piece_size,
            buffer: Vec::with_capacity(BEP52_BLOCK_SIZE),
            leaf_hashes: Vec::new(),
            total_size: 0,
        }
    }

    /// Append data to the stream
    pub async fn append(&mut self, data: &[u8]) -> Result<(), BuilderError> {
        let mut offset = 0;

        while offset < data.len() {
            let space = BEP52_BLOCK_SIZE - self.buffer.len();
            let to_write = space.min(data.len() - offset);

            self.buffer.extend_from_slice(&data[offset..offset + to_write]);
            offset += to_write;

            // Flush full block
            if self.buffer.len() == BEP52_BLOCK_SIZE {
                self.flush_block().await?;
            }
        }

        self.total_size += data.len() as u64;
        Ok(())
    }

    /// Flush current buffer as a block
    async fn flush_block(&mut self) -> Result<(), BuilderError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let block = std::mem::take(&mut self.buffer);
        let hash = hash_block(&block);

        if let Some(store) = &self.store {
            store.put(hash, block).await?;
        }

        self.leaf_hashes.push(hash);
        self.buffer = Vec::with_capacity(BEP52_BLOCK_SIZE);
        Ok(())
    }

    /// Finalize the stream and return result
    pub async fn finalize(mut self) -> Result<Bep52Result, BuilderError> {
        // Flush remaining buffer
        self.flush_block().await?;

        let builder = Bep52TreeBuilder {
            store: self.store,
            piece_size: self.piece_size,
        };

        builder.build_from_hashes(self.leaf_hashes, self.total_size).await
    }

    /// Get current stats
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            blocks: self.leaf_hashes.len(),
            buffered: self.buffer.len(),
            total_size: self.total_size,
        }
    }
}

/// Stream builder stats
#[derive(Debug, Clone, PartialEq)]
pub struct StreamStats {
    pub blocks: usize,
    pub buffered: usize,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::merkle_hash_pair;
    use crate::store::MemoryStore;

    #[tokio::test]
    async fn test_empty_data() {
        let builder: Bep52TreeBuilder<MemoryStore> = Bep52TreeBuilder::new(Bep52Config::default());
        let result = builder.build_from_data(&[]).await.unwrap();

        assert_eq!(result.root, ZERO_HASH);
        assert_eq!(result.size, 0);
        assert_eq!(result.block_count, 0);
        assert!(result.leaf_hashes.is_empty());
    }

    #[tokio::test]
    async fn test_single_block() {
        let store = Arc::new(MemoryStore::new());
        let config = Bep52Config::new().with_store(store.clone());
        let builder = Bep52TreeBuilder::new(config);

        let data = vec![1u8; 1000]; // Less than 16KB
        let result = builder.build_from_data(&data).await.unwrap();

        assert_eq!(result.size, 1000);
        assert_eq!(result.block_count, 1);
        assert_eq!(result.leaf_hashes.len(), 1);
        assert_eq!(result.root, result.leaf_hashes[0]);
        assert_eq!(store.size(), 1);
    }

    #[tokio::test]
    async fn test_multiple_blocks() {
        let store = Arc::new(MemoryStore::new());
        let config = Bep52Config::new().with_store(store.clone());
        let builder = Bep52TreeBuilder::new(config);

        // 2.5 blocks worth of data with unique content per block
        // Use different fill values for each block so they hash differently
        let mut data = Vec::with_capacity(BEP52_BLOCK_SIZE * 2 + 1000);
        data.extend(vec![1u8; BEP52_BLOCK_SIZE]);  // Block 1
        data.extend(vec![2u8; BEP52_BLOCK_SIZE]);  // Block 2
        data.extend(vec![3u8; 1000]);              // Block 3 (partial)

        let result = builder.build_from_data(&data).await.unwrap();

        assert_eq!(result.size, data.len() as u64);
        assert_eq!(result.block_count, 3);
        assert_eq!(result.leaf_hashes.len(), 3);
        assert_eq!(store.size(), 3);
    }

    #[tokio::test]
    async fn test_two_blocks_root() {
        let builder: Bep52TreeBuilder<MemoryStore> = Bep52TreeBuilder::new(Bep52Config::default());

        // Exactly 2 blocks
        let data = vec![42u8; BEP52_BLOCK_SIZE * 2];
        let result = builder.build_from_data(&data).await.unwrap();

        // Root should be hash of the two leaf hashes
        let expected = merkle_hash_pair(&result.leaf_hashes[0], &result.leaf_hashes[1]);
        assert_eq!(result.root, expected);
    }

    #[tokio::test]
    async fn test_with_piece_layers() {
        let config: Bep52Config<MemoryStore> = Bep52Config::new()
            .with_piece_size(BEP52_BLOCK_SIZE * 4); // 4 blocks per piece
        let builder = Bep52TreeBuilder::new(config);

        // 10 blocks = 3 pieces (4 + 4 + 2)
        let data = vec![1u8; BEP52_BLOCK_SIZE * 10];
        let result = builder.build_from_data(&data).await.unwrap();

        assert!(result.piece_layers.is_some());
        let layers = result.piece_layers.unwrap();
        assert_eq!(layers.len(), 3);
    }

    #[tokio::test]
    async fn test_invalid_piece_size() {
        let config: Bep52Config<MemoryStore> = Bep52Config::new()
            .with_piece_size(1000); // Not power of 2
        let builder = Bep52TreeBuilder::new(config);

        let data = vec![1u8; BEP52_BLOCK_SIZE * 2];
        let result = builder.build_from_data(&data).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_stream_builder() {
        let store = Arc::new(MemoryStore::new());
        let config = Bep52Config::new().with_store(store.clone());
        let mut stream = Bep52StreamBuilder::new(config);

        // Append data in chunks
        stream.append(&[1u8; 5000]).await.unwrap();
        stream.append(&[2u8; 5000]).await.unwrap();
        stream.append(&[3u8; 10000]).await.unwrap();

        let result = stream.finalize().await.unwrap();

        assert_eq!(result.size, 20000);
        assert_eq!(result.block_count, 2); // ceil(20000 / 16384) = 2
    }

    #[tokio::test]
    async fn test_stream_stats() {
        let config: Bep52Config<MemoryStore> = Bep52Config::default();
        let mut stream = Bep52StreamBuilder::new(config);

        assert_eq!(stream.stats().blocks, 0);
        assert_eq!(stream.stats().buffered, 0);
        assert_eq!(stream.stats().total_size, 0);

        stream.append(&[0u8; 8000]).await.unwrap();
        assert_eq!(stream.stats().buffered, 8000);
        assert_eq!(stream.stats().total_size, 8000);

        stream.append(&[0u8; 10000]).await.unwrap(); // Crosses boundary
        assert_eq!(stream.stats().blocks, 1);
        assert_eq!(stream.stats().buffered, 18000 - BEP52_BLOCK_SIZE);
        assert_eq!(stream.stats().total_size, 18000);
    }

    #[tokio::test]
    async fn test_builder_vs_stream_same_result() {
        let data = vec![42u8; BEP52_BLOCK_SIZE * 3 + 5000];

        // Build with TreeBuilder
        let builder: Bep52TreeBuilder<MemoryStore> = Bep52TreeBuilder::new(Bep52Config::default());
        let result1 = builder.build_from_data(&data).await.unwrap();

        // Build with StreamBuilder
        let mut stream: Bep52StreamBuilder<MemoryStore> = Bep52StreamBuilder::new(Bep52Config::default());
        stream.append(&data[..10000]).await.unwrap();
        stream.append(&data[10000..]).await.unwrap();
        let result2 = stream.finalize().await.unwrap();

        // Results should be identical
        assert_eq!(result1.root, result2.root);
        assert_eq!(result1.size, result2.size);
        assert_eq!(result1.block_count, result2.block_count);
        assert_eq!(result1.leaf_hashes, result2.leaf_hashes);
    }
}
