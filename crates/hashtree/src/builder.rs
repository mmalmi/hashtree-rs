//! Tree builder with chunking and fanout support
//!
//! - Large files are split into chunks
//! - Large directories are split into sub-trees
//! - Supports streaming appends
//! - Supports CBOR or binary (BEP52-style) merkle algorithms

use std::collections::HashMap;
use std::sync::Arc;

use crate::codec::encode_and_hash;
use crate::hash::sha256;
use crate::store::Store;
use crate::types::{DirEntry, Hash, Link, TreeNode};

/// Default chunk size: 256KB
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// BEP52 chunk size: 16KB
pub const BEP52_CHUNK_SIZE: usize = 16 * 1024;

/// Default max links per tree node (fanout)
pub const DEFAULT_MAX_LINKS: usize = 174;

/// Merkle tree algorithm for file chunking
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MerkleAlgorithm {
    /// CBOR-encoded tree nodes with variable fanout (default)
    #[default]
    Cbor,
    /// Binary merkle tree with hash pairs, power-of-2 padding (BEP52-style)
    Binary,
}

/// Builder configuration
#[derive(Clone)]
pub struct BuilderConfig<S: Store> {
    pub store: Arc<S>,
    pub chunk_size: usize,
    pub max_links: usize,
    pub merkle_algorithm: MerkleAlgorithm,
}

impl<S: Store> BuilderConfig<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_links: DEFAULT_MAX_LINKS,
            merkle_algorithm: MerkleAlgorithm::default(),
        }
    }

    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub fn with_max_links(mut self, max_links: usize) -> Self {
        self.max_links = max_links;
        self
    }

    pub fn with_merkle_algorithm(mut self, algorithm: MerkleAlgorithm) -> Self {
        self.merkle_algorithm = algorithm;
        self
    }
}

/// Result of put_file operation
#[derive(Debug, Clone)]
pub struct PutFileResult {
    /// Root hash of the file tree
    pub hash: Hash,
    /// Total size in bytes
    pub size: u64,
    /// Leaf hashes (chunk hashes) - useful for binary mode verification
    pub leaf_hashes: Vec<Hash>,
}

/// TreeBuilder - builds content-addressed merkle trees
pub struct TreeBuilder<S: Store> {
    store: Arc<S>,
    chunk_size: usize,
    max_links: usize,
    merkle_algorithm: MerkleAlgorithm,
}

impl<S: Store> TreeBuilder<S> {
    pub fn new(config: BuilderConfig<S>) -> Self {
        Self {
            store: config.store,
            chunk_size: config.chunk_size,
            max_links: config.max_links,
            merkle_algorithm: config.merkle_algorithm,
        }
    }

    /// Store a blob directly (small data)
    /// Returns the content hash
    pub async fn put_blob(&self, data: &[u8]) -> Result<Hash, BuilderError> {
        let hash = sha256(data);
        self.store
            .put(hash, data.to_vec())
            .await
            .map_err(|e| BuilderError::Store(e.to_string()))?;
        Ok(hash)
    }

    /// Store a file, chunking if necessary
    /// Returns PutFileResult with root hash, size, and leaf hashes
    pub async fn put_file(&self, data: &[u8]) -> Result<PutFileResult, BuilderError> {
        let size = data.len() as u64;

        // Small file - store as single blob
        if data.len() <= self.chunk_size {
            let hash = self.put_blob(data).await?;
            return Ok(PutFileResult {
                hash,
                size,
                leaf_hashes: vec![hash],
            });
        }

        // Large file - chunk it
        let mut chunk_hashes: Vec<Hash> = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + self.chunk_size).min(data.len());
            let chunk = &data[offset..end];
            let hash = self.put_blob(chunk).await?;
            chunk_hashes.push(hash);
            offset = end;
        }

        // Build tree from chunks using selected algorithm
        let root_hash = match self.merkle_algorithm {
            MerkleAlgorithm::Binary => self.build_binary_tree(&chunk_hashes),
            MerkleAlgorithm::Cbor => {
                let chunks: Vec<Link> = chunk_hashes
                    .iter()
                    .enumerate()
                    .map(|(i, &hash)| {
                        let chunk_size = if i < chunk_hashes.len() - 1 {
                            self.chunk_size as u64
                        } else {
                            (data.len() - i * self.chunk_size) as u64
                        };
                        Link {
                            hash,
                            name: None,
                            size: Some(chunk_size),
                        }
                    })
                    .collect();
                self.build_tree(chunks, Some(size)).await?
            }
        };

        Ok(PutFileResult {
            hash: root_hash,
            size,
            leaf_hashes: chunk_hashes,
        })
    }

    /// Build a binary merkle tree (BEP52 style)
    /// Uses hash pairs with zero-padding to power of 2
    /// Does not store intermediate nodes - only computes root
    fn build_binary_tree(&self, leaf_hashes: &[Hash]) -> Hash {
        if leaf_hashes.is_empty() {
            return [0u8; 32];
        }
        if leaf_hashes.len() == 1 {
            return leaf_hashes[0];
        }

        // Pad to power of 2
        let num_leaves = next_power_of_2(leaf_hashes.len());
        let zero = [0u8; 32];

        let mut current: Vec<Hash> = leaf_hashes.to_vec();
        let mut pad_hash = zero;
        let mut level_size = num_leaves;

        while level_size > 1 {
            let mut next_level: Vec<Hash> = Vec::with_capacity(level_size / 2);

            for i in (0..level_size).step_by(2) {
                let left = if i < current.len() { current[i] } else { pad_hash };
                let right = if i + 1 < current.len() { current[i + 1] } else { pad_hash };
                next_level.push(hash_pair(&left, &right));
            }

            // Update pad hash for next level
            pad_hash = hash_pair(&pad_hash, &pad_hash);
            current = next_level;
            level_size /= 2;
        }

        current[0]
    }

    /// Build a balanced tree from links
    /// Handles fanout by creating intermediate nodes
    async fn build_tree(&self, links: Vec<Link>, total_size: Option<u64>) -> Result<Hash, BuilderError> {
        // Single link with matching size - return it directly
        if links.len() == 1 {
            if let Some(ts) = total_size {
                if links[0].size == Some(ts) {
                    return Ok(links[0].hash);
                }
            }
        }

        // Fits in one node
        if links.len() <= self.max_links {
            let node = TreeNode {
                links,
                total_size,
                metadata: None,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Need to split into sub-trees
        let mut sub_trees: Vec<Link> = Vec::new();

        for batch in links.chunks(self.max_links) {
            let batch_size: u64 = batch.iter().filter_map(|l| l.size).sum();

            let node = TreeNode {
                links: batch.to_vec(),
                total_size: Some(batch_size),
                metadata: None,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;

            sub_trees.push(Link {
                hash,
                name: None,
                size: Some(batch_size),
            });
        }

        // Recursively build parent level
        Box::pin(self.build_tree(sub_trees, total_size)).await
    }

    /// Build a directory from entries
    /// Entries can be files or subdirectories
    pub async fn put_directory(
        &self,
        entries: Vec<DirEntry>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, BuilderError> {
        // Sort entries by name for deterministic hashing
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        let links: Vec<Link> = sorted
            .into_iter()
            .map(|e| Link {
                hash: e.hash,
                name: Some(e.name),
                size: e.size,
            })
            .collect();

        let total_size: u64 = links.iter().filter_map(|l| l.size).sum();

        // Fits in one node
        if links.len() <= self.max_links {
            let node = TreeNode {
                links,
                total_size: Some(total_size),
                metadata,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Large directory - create sub-trees
        // Group by first character for balanced distribution
        let mut groups: HashMap<char, Vec<Link>> = HashMap::new();

        for link in &links {
            let key = link
                .name
                .as_ref()
                .and_then(|n| n.chars().next())
                .map(|c| c.to_ascii_lowercase())
                .unwrap_or('\0');
            groups.entry(key).or_default().push(link.clone());
        }

        // If groups are still too large, split numerically
        let max_group_size = groups.values().map(|g| g.len()).max().unwrap_or(0);
        if groups.len() == 1 || max_group_size > self.max_links {
            return self
                .build_directory_by_chunks(links, total_size, metadata)
                .await;
        }

        // Build sub-tree for each group
        let mut sub_dirs: Vec<DirEntry> = Vec::new();
        let mut sorted_groups: Vec<_> = groups.into_iter().collect();
        sorted_groups.sort_by(|a, b| a.0.cmp(&b.0));

        for (key, group_links) in sorted_groups {
            let group_size: u64 = group_links.iter().filter_map(|l| l.size).sum();

            if group_links.len() <= self.max_links {
                let node = TreeNode {
                    links: group_links,
                    total_size: Some(group_size),
                    metadata: None,
                };
                let (data, hash) = encode_and_hash(&node)?;
                self.store
                    .put(hash, data)
                    .await
                    .map_err(|e| BuilderError::Store(e.to_string()))?;
                sub_dirs.push(DirEntry {
                    name: format!("_{}", key),
                    hash,
                    size: Some(group_size),
                });
            } else {
                // Recursively split this group
                let hash = self
                    .build_directory_by_chunks(group_links, group_size, None)
                    .await?;
                sub_dirs.push(DirEntry {
                    name: format!("_{}", key),
                    hash,
                    size: Some(group_size),
                });
            }
        }

        Box::pin(self.put_directory(sub_dirs, metadata)).await
    }

    /// Split directory into numeric chunks when grouping doesn't help
    async fn build_directory_by_chunks(
        &self,
        links: Vec<Link>,
        total_size: u64,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, BuilderError> {
        let mut sub_trees: Vec<Link> = Vec::new();

        for (i, batch) in links.chunks(self.max_links).enumerate() {
            let batch_size: u64 = batch.iter().filter_map(|l| l.size).sum();

            let node = TreeNode {
                links: batch.to_vec(),
                total_size: Some(batch_size),
                metadata: None,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;

            sub_trees.push(Link {
                hash,
                name: Some(format!("_chunk_{}", i * self.max_links)),
                size: Some(batch_size),
            });
        }

        if sub_trees.len() <= self.max_links {
            let node = TreeNode {
                links: sub_trees,
                total_size: Some(total_size),
                metadata,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Recursively build more levels
        Box::pin(self.build_directory_by_chunks(sub_trees, total_size, metadata)).await
    }

    /// Create a tree node with custom metadata
    pub async fn put_tree_node(
        &self,
        links: Vec<Link>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, BuilderError> {
        let total_size: u64 = links.iter().filter_map(|l| l.size).sum();

        let node = TreeNode {
            links,
            total_size: Some(total_size),
            metadata,
        };

        let (data, hash) = encode_and_hash(&node)?;
        self.store
            .put(hash, data)
            .await
            .map_err(|e| BuilderError::Store(e.to_string()))?;
        Ok(hash)
    }
}

/// StreamBuilder - supports incremental appends
pub struct StreamBuilder<S: Store> {
    store: Arc<S>,
    chunk_size: usize,
    max_links: usize,

    // Current partial chunk being built
    buffer: Vec<u8>,

    // Completed chunks
    chunks: Vec<Link>,
    total_size: u64,
}

impl<S: Store> StreamBuilder<S> {
    pub fn new(config: BuilderConfig<S>) -> Self {
        Self {
            store: config.store,
            chunk_size: config.chunk_size,
            max_links: config.max_links,
            buffer: Vec::with_capacity(config.chunk_size),
            chunks: Vec::new(),
            total_size: 0,
        }
    }

    /// Append data to the stream
    pub async fn append(&mut self, data: &[u8]) -> Result<(), BuilderError> {
        let mut offset = 0;

        while offset < data.len() {
            let space = self.chunk_size - self.buffer.len();
            let to_write = space.min(data.len() - offset);

            self.buffer.extend_from_slice(&data[offset..offset + to_write]);
            offset += to_write;

            // Flush full chunk
            if self.buffer.len() == self.chunk_size {
                self.flush_chunk().await?;
            }
        }

        self.total_size += data.len() as u64;
        Ok(())
    }

    /// Flush current buffer as a chunk
    async fn flush_chunk(&mut self) -> Result<(), BuilderError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let chunk = std::mem::take(&mut self.buffer);
        let hash = sha256(&chunk);
        self.store
            .put(hash, chunk.clone())
            .await
            .map_err(|e| BuilderError::Store(e.to_string()))?;

        self.chunks.push(Link {
            hash,
            name: None,
            size: Some(chunk.len() as u64),
        });

        self.buffer = Vec::with_capacity(self.chunk_size);
        Ok(())
    }

    /// Get current root hash without finalizing
    /// Useful for checkpoints
    pub async fn current_root(&mut self) -> Result<Option<Hash>, BuilderError> {
        if self.chunks.is_empty() && self.buffer.is_empty() {
            return Ok(None);
        }

        // Temporarily include buffer
        let mut temp_chunks = self.chunks.clone();
        if !self.buffer.is_empty() {
            let chunk = self.buffer.clone();
            let hash = sha256(&chunk);
            self.store
                .put(hash, chunk.clone())
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            temp_chunks.push(Link {
                hash,
                name: None,
                size: Some(chunk.len() as u64),
            });
        }

        let hash = self.build_tree_from_chunks(&temp_chunks, self.total_size).await?;
        Ok(Some(hash))
    }

    /// Finalize the stream and return root hash
    pub async fn finalize(mut self) -> Result<(Hash, u64), BuilderError> {
        // Flush remaining buffer
        self.flush_chunk().await?;

        if self.chunks.is_empty() {
            // Empty stream - return hash of empty data
            let empty_hash = sha256(&[]);
            self.store
                .put(empty_hash, vec![])
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            return Ok((empty_hash, 0));
        }

        let hash = self.build_tree_from_chunks(&self.chunks, self.total_size).await?;
        Ok((hash, self.total_size))
    }

    /// Build balanced tree from chunks
    async fn build_tree_from_chunks(
        &self,
        chunks: &[Link],
        total_size: u64,
    ) -> Result<Hash, BuilderError> {
        if chunks.len() == 1 {
            return Ok(chunks[0].hash);
        }

        if chunks.len() <= self.max_links {
            let node = TreeNode {
                links: chunks.to_vec(),
                total_size: Some(total_size),
                metadata: None,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Build intermediate level
        let mut sub_trees: Vec<Link> = Vec::new();
        for batch in chunks.chunks(self.max_links) {
            let batch_size: u64 = batch.iter().filter_map(|l| l.size).sum();

            let node = TreeNode {
                links: batch.to_vec(),
                total_size: Some(batch_size),
                metadata: None,
            };
            let (data, hash) = encode_and_hash(&node)?;
            self.store
                .put(hash, data)
                .await
                .map_err(|e| BuilderError::Store(e.to_string()))?;

            sub_trees.push(Link {
                hash,
                name: None,
                size: Some(batch_size),
            });
        }

        Box::pin(self.build_tree_from_chunks(&sub_trees, total_size)).await
    }

    /// Get stats
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            chunks: self.chunks.len(),
            buffered: self.buffer.len(),
            total_size: self.total_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamStats {
    pub chunks: usize,
    pub buffered: usize,
    pub total_size: u64,
}

/// Builder error type
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Store error: {0}")]
    Store(String),
    #[error("Codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),
}

/// Hash two 32-byte values together
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

/// Next power of 2 >= n
fn next_power_of_2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    n.next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use crate::types::to_hex;

    fn make_store() -> Arc<MemoryStore> {
        Arc::new(MemoryStore::new())
    }

    #[tokio::test]
    async fn test_put_blob() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));

        let data = vec![1u8, 2, 3, 4, 5];
        let hash = builder.put_blob(&data).await.unwrap();

        assert_eq!(hash.len(), 32);
        assert!(store.has(&hash).await.unwrap());

        let retrieved = store.get(&hash).await.unwrap();
        assert_eq!(retrieved, Some(data));
    }

    #[tokio::test]
    async fn test_put_blob_correct_hash() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store));

        let data = vec![1u8, 2, 3];
        let hash = builder.put_blob(&data).await.unwrap();
        let expected_hash = sha256(&data);

        assert_eq!(to_hex(&hash), to_hex(&expected_hash));
    }

    #[tokio::test]
    async fn test_put_file_small() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));

        let data = vec![1u8, 2, 3, 4, 5];
        let result = builder.put_file(&data).await.unwrap();

        assert_eq!(result.size, 5);
        let retrieved = store.get(&result.hash).await.unwrap();
        assert_eq!(retrieved, Some(data));
    }

    #[tokio::test]
    async fn test_put_file_chunked() {
        let store = make_store();
        let config = BuilderConfig::new(store.clone()).with_chunk_size(1024);
        let builder = TreeBuilder::new(config);

        let mut data = vec![0u8; 1024 * 2 + 100];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let result = builder.put_file(&data).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        // Verify store has multiple items (chunks + tree node)
        assert!(store.size() > 1);
    }

    #[tokio::test]
    async fn test_put_directory() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));

        let file1 = vec![1u8, 2, 3];
        let file2 = vec![4u8, 5, 6, 7];

        let hash1 = builder.put_blob(&file1).await.unwrap();
        let hash2 = builder.put_blob(&file2).await.unwrap();

        let dir_hash = builder
            .put_directory(
                vec![
                    DirEntry::new("a.txt", hash1).with_size(file1.len() as u64),
                    DirEntry::new("b.txt", hash2).with_size(file2.len() as u64),
                ],
                None,
            )
            .await
            .unwrap();

        assert!(store.has(&dir_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_put_directory_sorted() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));

        let hash = builder.put_blob(&[1u8]).await.unwrap();

        let dir_hash = builder
            .put_directory(
                vec![
                    DirEntry::new("zebra", hash),
                    DirEntry::new("apple", hash),
                    DirEntry::new("mango", hash),
                ],
                None,
            )
            .await
            .unwrap();

        let data = store.get(&dir_hash).await.unwrap().unwrap();
        let node = crate::codec::decode_tree_node(&data).unwrap();

        let names: Vec<_> = node.links.iter().filter_map(|l| l.name.clone()).collect();
        assert_eq!(names, vec!["apple", "mango", "zebra"]);
    }

    #[tokio::test]
    async fn test_put_tree_node_with_metadata() {
        let store = make_store();
        let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));

        let hash = builder.put_blob(&[1u8]).await.unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), serde_json::json!(2));
        metadata.insert("created".to_string(), serde_json::json!("2024-01-01"));

        let node_hash = builder
            .put_tree_node(
                vec![Link {
                    hash,
                    name: Some("test".to_string()),
                    size: Some(1),
                }],
                Some(metadata.clone()),
            )
            .await
            .unwrap();

        let data = store.get(&node_hash).await.unwrap().unwrap();
        let node = crate::codec::decode_tree_node(&data).unwrap();

        assert!(node.metadata.is_some());
        let m = node.metadata.unwrap();
        assert_eq!(m.get("version"), Some(&serde_json::json!(2)));
    }

    #[tokio::test]
    async fn test_stream_builder() {
        let store = make_store();
        let config = BuilderConfig::new(store.clone()).with_chunk_size(100);
        let mut stream = StreamBuilder::new(config);

        stream.append(&[1u8, 2, 3]).await.unwrap();
        stream.append(&[4u8, 5]).await.unwrap();
        stream.append(&[6u8, 7, 8, 9]).await.unwrap();

        let (hash, size) = stream.finalize().await.unwrap();

        assert_eq!(size, 9);
        assert!(store.has(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_stream_stats() {
        let store = make_store();
        let config = BuilderConfig::new(store).with_chunk_size(100);
        let mut stream = StreamBuilder::new(config);

        assert_eq!(stream.stats().chunks, 0);
        assert_eq!(stream.stats().buffered, 0);
        assert_eq!(stream.stats().total_size, 0);

        stream.append(&[0u8; 50]).await.unwrap();
        assert_eq!(stream.stats().buffered, 50);
        assert_eq!(stream.stats().total_size, 50);

        stream.append(&[0u8; 60]).await.unwrap(); // Crosses boundary
        assert_eq!(stream.stats().chunks, 1);
        assert_eq!(stream.stats().buffered, 10);
        assert_eq!(stream.stats().total_size, 110);
    }

    #[tokio::test]
    async fn test_stream_current_root() {
        let store = make_store();
        let config = BuilderConfig::new(store).with_chunk_size(100);
        let mut stream = StreamBuilder::new(config);

        stream.append(&[1u8, 2, 3]).await.unwrap();
        let root1 = stream.current_root().await.unwrap();

        stream.append(&[4u8, 5, 6]).await.unwrap();
        let root2 = stream.current_root().await.unwrap();

        // Roots should be different
        assert_ne!(to_hex(&root1.unwrap()), to_hex(&root2.unwrap()));
    }

    #[tokio::test]
    async fn test_stream_empty() {
        let store = make_store();
        let config = BuilderConfig::new(store.clone());
        let stream = StreamBuilder::new(config);

        let (hash, size) = stream.finalize().await.unwrap();
        assert_eq!(size, 0);
        assert!(store.has(&hash).await.unwrap());
    }
}
