//! HashTree - Unified merkle tree operations
//!
//! Single struct for creating, reading, and editing content-addressed merkle trees.
//! Mirrors the hashtree-ts HashTree class API.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::stream::{self, Stream};

use crate::builder::{BuilderConfig, BuilderError, StreamBuilder, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_LINKS};
use crate::codec::{decode_tree_node, encode_and_hash, is_directory_node, is_tree_node};
use crate::hash::sha256;
use crate::reader::{ReaderError, TreeEntry, WalkEntry};
use crate::store::Store;
use crate::types::{to_hex, DirEntry, Hash, Link, TreeNode};

/// HashTree configuration
#[derive(Clone)]
pub struct HashTreeConfig<S: Store> {
    pub store: Arc<S>,
    pub chunk_size: usize,
    pub max_links: usize,
}

impl<S: Store> HashTreeConfig<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_links: DEFAULT_MAX_LINKS,
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
}

/// Result of put_file operation
#[derive(Debug, Clone)]
pub struct PutFileResult {
    pub hash: Hash,
    pub size: u64,
}

/// HashTree error type
#[derive(Debug, thiserror::Error)]
pub enum HashTreeError {
    #[error("Store error: {0}")]
    Store(String),
    #[error("Codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),
    #[error("Missing chunk: {0}")]
    MissingChunk(String),
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("Entry not found: {0}")]
    EntryNotFound(String),
}

impl From<BuilderError> for HashTreeError {
    fn from(e: BuilderError) -> Self {
        match e {
            BuilderError::Store(s) => HashTreeError::Store(s),
            BuilderError::Codec(c) => HashTreeError::Codec(c),
        }
    }
}

impl From<ReaderError> for HashTreeError {
    fn from(e: ReaderError) -> Self {
        match e {
            ReaderError::Store(s) => HashTreeError::Store(s),
            ReaderError::Codec(c) => HashTreeError::Codec(c),
            ReaderError::MissingChunk(s) => HashTreeError::MissingChunk(s),
        }
    }
}

/// HashTree - unified create, read, and edit merkle tree operations
pub struct HashTree<S: Store> {
    store: Arc<S>,
    chunk_size: usize,
    max_links: usize,
}

impl<S: Store> HashTree<S> {
    pub fn new(config: HashTreeConfig<S>) -> Self {
        Self {
            store: config.store,
            chunk_size: config.chunk_size,
            max_links: config.max_links,
        }
    }

    // ============ CREATE ============

    /// Store a blob directly (small data)
    /// Returns the content hash
    pub async fn put_blob(&self, data: &[u8]) -> Result<Hash, HashTreeError> {
        let hash = sha256(data);
        self.store
            .put(hash, data.to_vec())
            .await
            .map_err(|e| HashTreeError::Store(e.to_string()))?;
        Ok(hash)
    }

    /// Store a file, chunking if necessary
    /// Returns root hash and total size
    pub async fn put_file(&self, data: &[u8]) -> Result<PutFileResult, HashTreeError> {
        let size = data.len() as u64;

        // Small file - store as single blob
        if data.len() <= self.chunk_size {
            let hash = self.put_blob(data).await?;
            return Ok(PutFileResult { hash, size });
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

        // Build tree from chunks
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
                    key: None,
                }
            })
            .collect();

        let root_hash = self.build_tree(chunks, Some(size)).await?;
        Ok(PutFileResult { hash: root_hash, size })
    }

    /// Build a directory from entries
    pub async fn put_directory(
        &self,
        entries: Vec<DirEntry>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, HashTreeError> {
        // Sort entries by name for deterministic hashing
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        let links: Vec<Link> = sorted
            .into_iter()
            .map(|e| Link {
                hash: e.hash,
                name: Some(e.name),
                size: e.size,
                key: None,
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
                .map_err(|e| HashTreeError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Large directory - create sub-trees
        self.build_directory_by_chunks(links, total_size, metadata).await
    }

    /// Build a balanced tree from links
    async fn build_tree(&self, links: Vec<Link>, total_size: Option<u64>) -> Result<Hash, HashTreeError> {
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
                .map_err(|e| HashTreeError::Store(e.to_string()))?;
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
                .map_err(|e| HashTreeError::Store(e.to_string()))?;

            sub_trees.push(Link {
                hash,
                name: None,
                size: Some(batch_size),
                key: None,
            });
        }

        // Recursively build parent level
        Box::pin(self.build_tree(sub_trees, total_size)).await
    }

    /// Split directory into numeric chunks
    async fn build_directory_by_chunks(
        &self,
        links: Vec<Link>,
        total_size: u64,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, HashTreeError> {
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
                .map_err(|e| HashTreeError::Store(e.to_string()))?;

            sub_trees.push(Link {
                hash,
                name: Some(format!("_chunk_{}", i * self.max_links)),
                size: Some(batch_size),
                key: None,
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
                .map_err(|e| HashTreeError::Store(e.to_string()))?;
            return Ok(hash);
        }

        // Recursively build more levels
        Box::pin(self.build_directory_by_chunks(sub_trees, total_size, metadata)).await
    }

    /// Create a tree node with custom links and metadata
    pub async fn put_tree_node(
        &self,
        links: Vec<Link>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Hash, HashTreeError> {
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
            .map_err(|e| HashTreeError::Store(e.to_string()))?;
        Ok(hash)
    }

    // ============ READ ============

    /// Get raw data by hash
    pub async fn get_blob(&self, hash: &Hash) -> Result<Option<Vec<u8>>, HashTreeError> {
        self.store
            .get(hash)
            .await
            .map_err(|e| HashTreeError::Store(e.to_string()))
    }

    /// Get and decode a tree node
    pub async fn get_tree_node(&self, hash: &Hash) -> Result<Option<TreeNode>, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(None),
        };

        if !is_tree_node(&data) {
            return Ok(None);
        }

        let node = decode_tree_node(&data)?;
        Ok(Some(node))
    }

    /// Check if hash points to a tree node
    pub async fn is_tree(&self, hash: &Hash) -> Result<bool, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(false),
        };
        Ok(is_tree_node(&data))
    }

    /// Check if hash points to a directory (tree with named links)
    pub async fn is_directory(&self, hash: &Hash) -> Result<bool, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(false),
        };
        Ok(is_directory_node(&data))
    }

    /// Read a complete file (reassemble chunks if needed)
    pub async fn read_file(&self, hash: &Hash) -> Result<Option<Vec<u8>>, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(None),
        };

        // Check if it's a tree (chunked file) or raw blob
        if !is_tree_node(&data) {
            return Ok(Some(data));
        }

        // It's a tree - reassemble chunks
        let node = decode_tree_node(&data)?;
        let assembled = self.assemble_chunks(&node).await?;
        Ok(Some(assembled))
    }

    /// Recursively assemble chunks from tree
    async fn assemble_chunks(&self, node: &TreeNode) -> Result<Vec<u8>, HashTreeError> {
        let mut parts: Vec<Vec<u8>> = Vec::new();

        for link in &node.links {
            let child_data = self
                .store
                .get(&link.hash)
                .await
                .map_err(|e| HashTreeError::Store(e.to_string()))?
                .ok_or_else(|| HashTreeError::MissingChunk(to_hex(&link.hash)))?;

            if is_tree_node(&child_data) {
                let child_node = decode_tree_node(&child_data)?;
                parts.push(Box::pin(self.assemble_chunks(&child_node)).await?);
            } else {
                parts.push(child_data);
            }
        }

        // Concatenate all parts
        let total_length: usize = parts.iter().map(|p| p.len()).sum();
        let mut result = Vec::with_capacity(total_length);
        for part in parts {
            result.extend_from_slice(&part);
        }

        Ok(result)
    }

    /// Read a file as stream of chunks
    /// Returns an async stream that yields chunks as they are read
    pub fn read_file_stream(
        &self,
        hash: Hash,
    ) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, HashTreeError>> + Send + '_>> {
        Box::pin(stream::unfold(
            ReadStreamState::Init { hash, tree: self },
            |state| async move {
                match state {
                    ReadStreamState::Init { hash, tree } => {
                        let data = match tree.store.get(&hash).await {
                            Ok(Some(d)) => d,
                            Ok(None) => return None,
                            Err(e) => return Some((Err(HashTreeError::Store(e.to_string())), ReadStreamState::Done)),
                        };

                        if !is_tree_node(&data) {
                            // Single blob - yield it and finish
                            return Some((Ok(data), ReadStreamState::Done));
                        }

                        // Tree node - start streaming chunks
                        let node = match decode_tree_node(&data) {
                            Ok(n) => n,
                            Err(e) => return Some((Err(HashTreeError::Codec(e)), ReadStreamState::Done)),
                        };

                        // Create stack with all links to process
                        let mut stack: Vec<StreamStackItem> = Vec::new();
                        for link in node.links.into_iter().rev() {
                            stack.push(StreamStackItem::Hash(link.hash));
                        }

                        // Process first item
                        tree.process_stream_stack(&mut stack).await
                    }
                    ReadStreamState::Processing { mut stack, tree } => {
                        tree.process_stream_stack(&mut stack).await
                    }
                    ReadStreamState::Done => None,
                }
            },
        ))
    }

    async fn process_stream_stack<'a>(
        &'a self,
        stack: &mut Vec<StreamStackItem>,
    ) -> Option<(Result<Vec<u8>, HashTreeError>, ReadStreamState<'a, S>)> {
        while let Some(item) = stack.pop() {
            match item {
                StreamStackItem::Hash(hash) => {
                    let data = match self.store.get(&hash).await {
                        Ok(Some(d)) => d,
                        Ok(None) => {
                            return Some((
                                Err(HashTreeError::MissingChunk(to_hex(&hash))),
                                ReadStreamState::Done,
                            ))
                        }
                        Err(e) => {
                            return Some((
                                Err(HashTreeError::Store(e.to_string())),
                                ReadStreamState::Done,
                            ))
                        }
                    };

                    if is_tree_node(&data) {
                        // Nested tree - push its children to stack
                        let node = match decode_tree_node(&data) {
                            Ok(n) => n,
                            Err(e) => return Some((Err(HashTreeError::Codec(e)), ReadStreamState::Done)),
                        };
                        for link in node.links.into_iter().rev() {
                            stack.push(StreamStackItem::Hash(link.hash));
                        }
                    } else {
                        // Leaf blob - yield it
                        return Some((Ok(data), ReadStreamState::Processing { stack: std::mem::take(stack), tree: self }));
                    }
                }
            }
        }
        None
    }

    /// Read file chunks as Vec (non-streaming version)
    pub async fn read_file_chunks(&self, hash: &Hash) -> Result<Vec<Vec<u8>>, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(vec![]),
        };

        if !is_tree_node(&data) {
            return Ok(vec![data]);
        }

        let node = decode_tree_node(&data)?;
        self.collect_chunks(&node).await
    }

    async fn collect_chunks(&self, node: &TreeNode) -> Result<Vec<Vec<u8>>, HashTreeError> {
        let mut chunks = Vec::new();

        for link in &node.links {
            let child_data = self
                .store
                .get(&link.hash)
                .await
                .map_err(|e| HashTreeError::Store(e.to_string()))?
                .ok_or_else(|| HashTreeError::MissingChunk(to_hex(&link.hash)))?;

            if is_tree_node(&child_data) {
                let child_node = decode_tree_node(&child_data)?;
                chunks.extend(Box::pin(self.collect_chunks(&child_node)).await?);
            } else {
                chunks.push(child_data);
            }
        }

        Ok(chunks)
    }

    /// List directory entries
    pub async fn list_directory(&self, hash: &Hash) -> Result<Vec<TreeEntry>, HashTreeError> {
        let node = match self.get_tree_node(hash).await? {
            Some(n) => n,
            None => return Ok(vec![]),
        };

        let mut entries = Vec::new();

        for link in &node.links {
            // Skip internal chunk nodes
            if let Some(ref name) = link.name {
                if name.starts_with("_chunk_") || name.starts_with('_') {
                    let sub_entries = Box::pin(self.list_directory(&link.hash)).await?;
                    entries.extend(sub_entries);
                    continue;
                }
            }

            let child_is_dir = self.is_directory(&link.hash).await?;
            entries.push(TreeEntry {
                name: link.name.clone().unwrap_or_else(|| to_hex(&link.hash)),
                hash: link.hash,
                size: link.size,
                is_tree: child_is_dir,
            });
        }

        Ok(entries)
    }

    /// Resolve a path within a tree
    pub async fn resolve_path(&self, root_hash: &Hash, path: &str) -> Result<Option<Hash>, HashTreeError> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();

        let mut current_hash = *root_hash;

        for part in parts {
            let node = match self.get_tree_node(&current_hash).await? {
                Some(n) => n,
                None => return Ok(None),
            };

            if let Some(link) = self.find_link(&node, part) {
                current_hash = link.hash;
            } else {
                // Check internal nodes
                match self.find_in_subtrees(&node, part).await? {
                    Some(hash) => current_hash = hash,
                    None => return Ok(None),
                }
            }
        }

        Ok(Some(current_hash))
    }

    fn find_link(&self, node: &TreeNode, name: &str) -> Option<Link> {
        node.links
            .iter()
            .find(|l| l.name.as_deref() == Some(name))
            .cloned()
    }

    async fn find_in_subtrees(&self, node: &TreeNode, name: &str) -> Result<Option<Hash>, HashTreeError> {
        for link in &node.links {
            if !link.name.as_ref().map(|n| n.starts_with('_')).unwrap_or(false) {
                continue;
            }

            let sub_node = match self.get_tree_node(&link.hash).await? {
                Some(n) => n,
                None => continue,
            };

            if let Some(found) = self.find_link(&sub_node, name) {
                return Ok(Some(found.hash));
            }

            if let Some(deep_found) = Box::pin(self.find_in_subtrees(&sub_node, name)).await? {
                return Ok(Some(deep_found));
            }
        }

        Ok(None)
    }

    /// Get total size of a tree
    pub async fn get_size(&self, hash: &Hash) -> Result<u64, HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(0),
        };

        if !is_tree_node(&data) {
            return Ok(data.len() as u64);
        }

        let node = decode_tree_node(&data)?;
        if let Some(total_size) = node.total_size {
            return Ok(total_size);
        }

        // Calculate from children
        let mut total = 0u64;
        for link in &node.links {
            total += match link.size {
                Some(s) => s,
                None => Box::pin(self.get_size(&link.hash)).await?,
            };
        }
        Ok(total)
    }

    /// Walk entire tree depth-first (returns Vec)
    pub async fn walk(&self, hash: &Hash, path: &str) -> Result<Vec<WalkEntry>, HashTreeError> {
        let mut entries = Vec::new();
        self.walk_recursive(hash, path, &mut entries).await?;
        Ok(entries)
    }

    async fn walk_recursive(
        &self,
        hash: &Hash,
        path: &str,
        entries: &mut Vec<WalkEntry>,
    ) -> Result<(), HashTreeError> {
        let data = match self.store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
            Some(d) => d,
            None => return Ok(()),
        };

        if !is_tree_node(&data) {
            entries.push(WalkEntry {
                path: path.to_string(),
                hash: *hash,
                is_tree: false,
                size: Some(data.len() as u64),
            });
            return Ok(());
        }

        let node = decode_tree_node(&data)?;
        entries.push(WalkEntry {
            path: path.to_string(),
            hash: *hash,
            is_tree: true,
            size: node.total_size,
        });

        for link in &node.links {
            let child_path = match &link.name {
                Some(name) => {
                    if name.starts_with("_chunk_") || name.starts_with('_') {
                        Box::pin(self.walk_recursive(&link.hash, path, entries)).await?;
                        continue;
                    }
                    if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{}/{}", path, name)
                    }
                }
                None => path.to_string(),
            };

            Box::pin(self.walk_recursive(&link.hash, &child_path, entries)).await?;
        }

        Ok(())
    }

    /// Walk tree as stream
    pub fn walk_stream(
        &self,
        hash: Hash,
        initial_path: String,
    ) -> Pin<Box<dyn Stream<Item = Result<WalkEntry, HashTreeError>> + Send + '_>> {
        Box::pin(stream::unfold(
            WalkStreamState::Init { hash, path: initial_path, tree: self },
            |state| async move {
                match state {
                    WalkStreamState::Init { hash, path, tree } => {
                        let data = match tree.store.get(&hash).await {
                            Ok(Some(d)) => d,
                            Ok(None) => return None,
                            Err(e) => {
                                return Some((
                                    Err(HashTreeError::Store(e.to_string())),
                                    WalkStreamState::Done,
                                ))
                            }
                        };

                        if !is_tree_node(&data) {
                            let entry = WalkEntry {
                                path,
                                hash,
                                is_tree: false,
                                size: Some(data.len() as u64),
                            };
                            return Some((Ok(entry), WalkStreamState::Done));
                        }

                        let node = match decode_tree_node(&data) {
                            Ok(n) => n,
                            Err(e) => return Some((Err(HashTreeError::Codec(e)), WalkStreamState::Done)),
                        };

                        let entry = WalkEntry {
                            path: path.clone(),
                            hash,
                            is_tree: true,
                            size: node.total_size,
                        };

                        // Create stack with children to process
                        let mut stack: Vec<WalkStackItem> = Vec::new();
                        for link in node.links.into_iter().rev() {
                            let child_path = match &link.name {
                                Some(name) if !name.starts_with('_') => {
                                    if path.is_empty() {
                                        name.clone()
                                    } else {
                                        format!("{}/{}", path, name)
                                    }
                                }
                                _ => path.clone(),
                            };
                            stack.push(WalkStackItem { hash: link.hash, path: child_path });
                        }

                        Some((Ok(entry), WalkStreamState::Processing { stack, tree }))
                    }
                    WalkStreamState::Processing { mut stack, tree } => {
                        tree.process_walk_stack(&mut stack).await
                    }
                    WalkStreamState::Done => None,
                }
            },
        ))
    }

    async fn process_walk_stack<'a>(
        &'a self,
        stack: &mut Vec<WalkStackItem>,
    ) -> Option<(Result<WalkEntry, HashTreeError>, WalkStreamState<'a, S>)> {
        while let Some(item) = stack.pop() {
            let data = match self.store.get(&item.hash).await {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    return Some((
                        Err(HashTreeError::Store(e.to_string())),
                        WalkStreamState::Done,
                    ))
                }
            };

            if !is_tree_node(&data) {
                let entry = WalkEntry {
                    path: item.path,
                    hash: item.hash,
                    is_tree: false,
                    size: Some(data.len() as u64),
                };
                return Some((Ok(entry), WalkStreamState::Processing { stack: std::mem::take(stack), tree: self }));
            }

            let node = match decode_tree_node(&data) {
                Ok(n) => n,
                Err(e) => return Some((Err(HashTreeError::Codec(e)), WalkStreamState::Done)),
            };

            let entry = WalkEntry {
                path: item.path.clone(),
                hash: item.hash,
                is_tree: true,
                size: node.total_size,
            };

            // Push children to stack
            for link in node.links.into_iter().rev() {
                let child_path = match &link.name {
                    Some(name) if !name.starts_with('_') => {
                        if item.path.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", item.path, name)
                        }
                    }
                    _ => item.path.clone(),
                };
                stack.push(WalkStackItem { hash: link.hash, path: child_path });
            }

            return Some((Ok(entry), WalkStreamState::Processing { stack: std::mem::take(stack), tree: self }));
        }
        None
    }

    // ============ EDIT ============

    /// Add or update an entry in a directory
    /// Returns new root hash (immutable operation)
    pub async fn set_entry(
        &self,
        root_hash: &Hash,
        path: &[&str],
        name: &str,
        hash: Hash,
        size: u64,
    ) -> Result<Hash, HashTreeError> {
        let dir_hash = self.resolve_path_array(root_hash, path).await?;
        let dir_hash = dir_hash.ok_or_else(|| HashTreeError::PathNotFound(path.join("/")))?;

        let entries = self.list_directory(&dir_hash).await?;
        let mut new_entries: Vec<DirEntry> = entries
            .into_iter()
            .filter(|e| e.name != name)
            .map(|e| DirEntry {
                name: e.name,
                hash: e.hash,
                size: e.size,
            })
            .collect();

        new_entries.push(DirEntry {
            name: name.to_string(),
            hash,
            size: Some(size),
        });

        let new_dir_hash = self.put_directory(new_entries, None).await?;
        self.rebuild_path(root_hash, path, new_dir_hash).await
    }

    /// Remove an entry from a directory
    /// Returns new root hash
    pub async fn remove_entry(
        &self,
        root_hash: &Hash,
        path: &[&str],
        name: &str,
    ) -> Result<Hash, HashTreeError> {
        let dir_hash = self.resolve_path_array(root_hash, path).await?;
        let dir_hash = dir_hash.ok_or_else(|| HashTreeError::PathNotFound(path.join("/")))?;

        let entries = self.list_directory(&dir_hash).await?;
        let new_entries: Vec<DirEntry> = entries
            .into_iter()
            .filter(|e| e.name != name)
            .map(|e| DirEntry {
                name: e.name,
                hash: e.hash,
                size: e.size,
            })
            .collect();

        let new_dir_hash = self.put_directory(new_entries, None).await?;
        self.rebuild_path(root_hash, path, new_dir_hash).await
    }

    /// Rename an entry in a directory
    /// Returns new root hash
    pub async fn rename_entry(
        &self,
        root_hash: &Hash,
        path: &[&str],
        old_name: &str,
        new_name: &str,
    ) -> Result<Hash, HashTreeError> {
        if old_name == new_name {
            return Ok(*root_hash);
        }

        let dir_hash = self.resolve_path_array(root_hash, path).await?;
        let dir_hash = dir_hash.ok_or_else(|| HashTreeError::PathNotFound(path.join("/")))?;

        let entries = self.list_directory(&dir_hash).await?;
        let entry = entries
            .iter()
            .find(|e| e.name == old_name)
            .ok_or_else(|| HashTreeError::EntryNotFound(old_name.to_string()))?;

        let entry_hash = entry.hash;
        let entry_size = entry.size;

        let new_entries: Vec<DirEntry> = entries
            .into_iter()
            .filter(|e| e.name != old_name)
            .map(|e| DirEntry {
                name: e.name,
                hash: e.hash,
                size: e.size,
            })
            .chain(std::iter::once(DirEntry {
                name: new_name.to_string(),
                hash: entry_hash,
                size: entry_size,
            }))
            .collect();

        let new_dir_hash = self.put_directory(new_entries, None).await?;
        self.rebuild_path(root_hash, path, new_dir_hash).await
    }

    /// Move an entry to a different directory
    /// Returns new root hash
    pub async fn move_entry(
        &self,
        root_hash: &Hash,
        source_path: &[&str],
        name: &str,
        target_path: &[&str],
    ) -> Result<Hash, HashTreeError> {
        let source_dir_hash = self.resolve_path_array(root_hash, source_path).await?;
        let source_dir_hash = source_dir_hash.ok_or_else(|| HashTreeError::PathNotFound(source_path.join("/")))?;

        let source_entries = self.list_directory(&source_dir_hash).await?;
        let entry = source_entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| HashTreeError::EntryNotFound(name.to_string()))?;

        let entry_hash = entry.hash;
        let entry_size = entry.size.unwrap_or(0);

        // Remove from source
        let new_root = self.remove_entry(root_hash, source_path, name).await?;

        // Add to target
        self.set_entry(&new_root, target_path, name, entry_hash, entry_size).await
    }

    async fn resolve_path_array(&self, root_hash: &Hash, path: &[&str]) -> Result<Option<Hash>, HashTreeError> {
        if path.is_empty() {
            return Ok(Some(*root_hash));
        }
        self.resolve_path(root_hash, &path.join("/")).await
    }

    async fn rebuild_path(
        &self,
        root_hash: &Hash,
        path: &[&str],
        new_child_hash: Hash,
    ) -> Result<Hash, HashTreeError> {
        if path.is_empty() {
            return Ok(new_child_hash);
        }

        let mut child_hash = new_child_hash;
        let parts: Vec<&str> = path.to_vec();

        for i in (0..parts.len()).rev() {
            let child_name = parts[i];
            let parent_path = &parts[..i];

            let parent_hash = if parent_path.is_empty() {
                *root_hash
            } else {
                self.resolve_path_array(root_hash, parent_path)
                    .await?
                    .ok_or_else(|| HashTreeError::PathNotFound(parent_path.join("/")))?
            };

            let parent_entries = self.list_directory(&parent_hash).await?;
            let new_parent_entries: Vec<DirEntry> = parent_entries
                .into_iter()
                .map(|e| {
                    if e.name == child_name {
                        DirEntry {
                            name: e.name,
                            hash: child_hash,
                            size: e.size,
                        }
                    } else {
                        DirEntry {
                            name: e.name,
                            hash: e.hash,
                            size: e.size,
                        }
                    }
                })
                .collect();

            child_hash = self.put_directory(new_parent_entries, None).await?;
        }

        Ok(child_hash)
    }

    // ============ UTILITY ============

    /// Get the underlying store
    pub fn get_store(&self) -> Arc<S> {
        self.store.clone()
    }

    /// Create a StreamBuilder for incremental file building
    pub fn stream_builder(&self) -> StreamBuilder<S> {
        StreamBuilder::new(BuilderConfig::new(self.store.clone())
            .with_chunk_size(self.chunk_size)
            .with_max_links(self.max_links))
    }
}

// Internal state types for streaming

enum StreamStackItem {
    Hash(Hash),
}

enum ReadStreamState<'a, S: Store> {
    Init { hash: Hash, tree: &'a HashTree<S> },
    Processing { stack: Vec<StreamStackItem>, tree: &'a HashTree<S> },
    Done,
}

struct WalkStackItem {
    hash: Hash,
    path: String,
}

enum WalkStreamState<'a, S: Store> {
    Init { hash: Hash, path: String, tree: &'a HashTree<S> },
    Processing { stack: Vec<WalkStackItem>, tree: &'a HashTree<S> },
    Done,
}

/// Verify tree integrity - checks that all referenced hashes exist
pub async fn verify_tree<S: Store>(
    store: Arc<S>,
    root_hash: &Hash,
) -> Result<crate::reader::VerifyResult, HashTreeError> {
    let mut missing = Vec::new();
    let mut visited = std::collections::HashSet::new();

    verify_recursive(store, root_hash, &mut missing, &mut visited).await?;

    Ok(crate::reader::VerifyResult {
        valid: missing.is_empty(),
        missing,
    })
}

async fn verify_recursive<S: Store>(
    store: Arc<S>,
    hash: &Hash,
    missing: &mut Vec<Hash>,
    visited: &mut std::collections::HashSet<String>,
) -> Result<(), HashTreeError> {
    let hex = to_hex(hash);
    if visited.contains(&hex) {
        return Ok(());
    }
    visited.insert(hex);

    let data = match store.get(hash).await.map_err(|e| HashTreeError::Store(e.to_string()))? {
        Some(d) => d,
        None => {
            missing.push(*hash);
            return Ok(());
        }
    };

    if is_tree_node(&data) {
        let node = decode_tree_node(&data)?;
        for link in &node.links {
            Box::pin(verify_recursive(store.clone(), &link.hash, missing, visited)).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn make_tree() -> (Arc<MemoryStore>, HashTree<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let tree = HashTree::new(HashTreeConfig::new(store.clone()));
        (store, tree)
    }

    #[tokio::test]
    async fn test_put_and_read_blob() {
        let (_store, tree) = make_tree();

        let data = vec![1, 2, 3, 4, 5];
        let hash = tree.put_blob(&data).await.unwrap();

        let result = tree.get_blob(&hash).await.unwrap();
        assert_eq!(result, Some(data));
    }

    #[tokio::test]
    async fn test_put_and_read_file_small() {
        let (_store, tree) = make_tree();

        let data = b"Hello, World!";
        let result = tree.put_file(data).await.unwrap();

        assert_eq!(result.size, data.len() as u64);

        let read_data = tree.read_file(&result.hash).await.unwrap();
        assert_eq!(read_data, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_put_and_read_directory() {
        let (_store, tree) = make_tree();

        let file1 = tree.put_blob(b"content1").await.unwrap();
        let file2 = tree.put_blob(b"content2").await.unwrap();

        let dir_hash = tree
            .put_directory(
                vec![
                    DirEntry::new("a.txt", file1).with_size(8),
                    DirEntry::new("b.txt", file2).with_size(8),
                ],
                None,
            )
            .await
            .unwrap();

        let entries = tree.list_directory(&dir_hash).await.unwrap();
        assert_eq!(entries.len(), 2);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
    }

    #[tokio::test]
    async fn test_is_directory() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"data").await.unwrap();
        let dir_hash = tree.put_directory(vec![], None).await.unwrap();

        assert!(!tree.is_directory(&file_hash).await.unwrap());
        assert!(tree.is_directory(&dir_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_resolve_path() {
        let (_store, tree) = make_tree();

        let file_hash = tree.put_blob(b"nested").await.unwrap();
        let sub_dir = tree.put_directory(
            vec![DirEntry::new("file.txt", file_hash).with_size(6)],
            None,
        ).await.unwrap();
        let root_dir = tree.put_directory(
            vec![DirEntry::new("subdir", sub_dir)],
            None,
        ).await.unwrap();

        let resolved = tree.resolve_path(&root_dir, "subdir/file.txt").await.unwrap();
        assert_eq!(resolved, Some(file_hash));
    }
}
