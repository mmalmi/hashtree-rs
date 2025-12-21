//! Hashtree-backed git object and ref storage using LMDB persistence
//!
//! Stores git objects and refs in a hashtree merkle tree:
//!   root/
//!     .git/
//!       HEAD -> "ref: refs/heads/main"
//!       refs/heads/main -> <commit-sha1>
//!       objects/XX/YYYY... -> zlib-compressed loose object (standard git layout)
//!
//! The root hash (SHA-256) is the content-addressed identifier for the entire repo state.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hashtree_core::{sha256, DirEntry, HashTree, HashTreeConfig, LinkType, Store};
use hashtree_lmdb::LmdbBlobStore;
use sha1::{Sha1, Digest};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, info};

use super::object::{parse_tree, GitObject, ObjectId, ObjectType};
use super::refs::{validate_ref_name, Ref};
use super::{Error, Result};

/// Box type for async recursion
type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Runtime executor - either owns a runtime or reuses an existing one
enum RuntimeExecutor {
    Owned(Runtime),
    Handle(Handle),
}

impl RuntimeExecutor {
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        match self {
            RuntimeExecutor::Owned(rt) => rt.block_on(f),
            RuntimeExecutor::Handle(handle) => tokio::task::block_in_place(|| handle.block_on(f)),
        }
    }
}

/// Git storage backed by HashTree with LMDB persistence
pub struct GitStorage {
    store: Arc<LmdbBlobStore>,
    tree: HashTree<LmdbBlobStore>,
    runtime: RuntimeExecutor,
    /// In-memory state for the current session
    objects: std::sync::RwLock<HashMap<String, Vec<u8>>>,
    refs: std::sync::RwLock<HashMap<String, String>>,
    root_hash: std::sync::RwLock<Option<[u8; 32]>>,
}

impl GitStorage {
    /// Open or create a git storage at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let runtime = match Handle::try_current() {
            Ok(handle) => RuntimeExecutor::Handle(handle),
            Err(_) => {
                let rt = Runtime::new()
                    .map_err(|e| Error::StorageError(format!("tokio runtime: {}", e)))?;
                RuntimeExecutor::Owned(rt)
            }
        };

        let store_path = path.as_ref().join("blobs");
        let store = Arc::new(
            LmdbBlobStore::new(&store_path)
                .map_err(|e| Error::StorageError(format!("lmdb: {}", e)))?,
        );

        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        Ok(Self {
            store,
            tree,
            runtime,
            objects: std::sync::RwLock::new(HashMap::new()),
            refs: std::sync::RwLock::new(HashMap::new()),
            root_hash: std::sync::RwLock::new(None),
        })
    }

    /// Write an object, returning its ID
    fn write_object(&self, obj: &GitObject) -> Result<ObjectId> {
        let oid = obj.id();
        let key = oid.to_hex();

        let loose = obj.to_loose_format();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&loose)?;
        let compressed = encoder.finish()?;

        let mut objects = self.objects.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        objects.insert(key, compressed);

        // Invalidate cached root
        if let Ok(mut root) = self.root_hash.write() {
            *root = None;
        }

        Ok(oid)
    }

    /// Write raw object data (type + content already parsed)
    pub fn write_raw_object(&self, obj_type: ObjectType, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(obj_type, content.to_vec());
        self.write_object(&obj)
    }

    /// Read an object by ID from in-memory cache
    #[allow(dead_code)]
    fn read_object(&self, oid: &ObjectId) -> Result<GitObject> {
        let key = oid.to_hex();
        let objects = self.objects.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let compressed = objects
            .get(&key)
            .ok_or_else(|| Error::ObjectNotFound(key.clone()))?;

        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut data = Vec::new();
        decoder.read_to_end(&mut data)?;

        GitObject::from_loose_format(&data)
    }

    /// Write a ref
    pub fn write_ref(&self, name: &str, target: &Ref) -> Result<()> {
        validate_ref_name(name)?;

        let value = match target {
            Ref::Direct(oid) => oid.to_hex(),
            Ref::Symbolic(target) => format!("ref: {}", target),
        };

        let mut refs = self.refs.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        refs.insert(name.to_string(), value);

        // Invalidate cached root
        if let Ok(mut root) = self.root_hash.write() {
            *root = None;
        }

        Ok(())
    }

    /// Read a ref
    #[allow(dead_code)]
    pub fn read_ref(&self, name: &str) -> Result<Option<Ref>> {
        let refs = self.refs.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;

        match refs.get(name) {
            Some(value) => {
                if let Some(target) = value.strip_prefix("ref: ") {
                    Ok(Some(Ref::Symbolic(target.to_string())))
                } else {
                    let oid = ObjectId::from_hex(value)
                        .ok_or_else(|| Error::StorageError(format!("invalid ref: {}", value)))?;
                    Ok(Some(Ref::Direct(oid)))
                }
            }
            None => Ok(None),
        }
    }

    /// List all refs
    #[allow(dead_code)]
    pub fn list_refs(&self) -> Result<HashMap<String, String>> {
        let refs = self.refs.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        Ok(refs.clone())
    }

    /// Delete a ref
    pub fn delete_ref(&self, name: &str) -> Result<bool> {
        let mut refs = self.refs.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let existed = refs.remove(name).is_some();

        // Invalidate cached root
        if let Ok(mut root) = self.root_hash.write() {
            *root = None;
        }

        Ok(existed)
    }

    /// Get the cached root hash (returns None if tree hasn't been built)
    #[allow(dead_code)]
    pub fn get_root_hash(&self) -> Result<Option<[u8; 32]>> {
        let root = self.root_hash.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        Ok(*root)
    }

    /// Get the default branch name
    #[allow(dead_code)]
    pub fn default_branch(&self) -> Result<Option<String>> {
        let refs = self.refs.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;

        if let Some(head) = refs.get("HEAD") {
            if let Some(target) = head.strip_prefix("ref: ") {
                return Ok(Some(target.to_string()));
            }
        }
        Ok(None)
    }

    /// Get the tree SHA from a commit object
    fn get_commit_tree(&self, commit_oid: &str, objects: &HashMap<String, Vec<u8>>) -> Option<String> {
        let compressed = objects.get(commit_oid)?;

        // Decompress the object
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).ok()?;

        // Parse git object format: "type size\0content"
        let null_pos = decompressed.iter().position(|&b| b == 0)?;
        let content = &decompressed[null_pos + 1..];

        // Parse commit content - first line is "tree <sha>"
        let content_str = std::str::from_utf8(content).ok()?;
        let first_line = content_str.lines().next()?;
        if first_line.starts_with("tree ") {
            Some(first_line[5..].to_string())
        } else {
            None
        }
    }

    /// Get git object content (decompressed, without header)
    fn get_object_content(&self, oid: &str, objects: &HashMap<String, Vec<u8>>) -> Option<(ObjectType, Vec<u8>)> {
        let compressed = objects.get(oid)?;

        // Decompress the object
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).ok()?;

        // Parse git object format: "type size\0content"
        let null_pos = decompressed.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&decompressed[..null_pos]).ok()?;
        let obj_type = if header.starts_with("blob") {
            ObjectType::Blob
        } else if header.starts_with("tree") {
            ObjectType::Tree
        } else if header.starts_with("commit") {
            ObjectType::Commit
        } else {
            return None;
        };
        let content = decompressed[null_pos + 1..].to_vec();
        Some((obj_type, content))
    }

    /// Build the hashtree and return the root hash
    pub fn build_tree(&self) -> Result<[u8; 32]> {
        // Check if we have a cached root
        if let Ok(root) = self.root_hash.read() {
            if let Some(hash) = *root {
                return Ok(hash);
            }
        }

        let objects = self.objects.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let refs = self.refs.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;

        // Get default branch from HEAD or find first branch ref
        let (default_branch, commit_sha) = if let Some(head) = refs.get("HEAD") {
            let branch = head.strip_prefix("ref: ").map(String::from);
            let sha = branch.as_ref().and_then(|b| refs.get(b)).cloned();
            (branch, sha)
        } else {
            // No HEAD ref - find first refs/heads/* ref directly
            let mut branch_info: Option<(String, String)> = None;
            for (ref_name, sha) in refs.iter() {
                if ref_name.starts_with("refs/heads/") {
                    branch_info = Some((ref_name.clone(), sha.clone()));
                    break;
                }
            }
            match branch_info {
                Some((branch, sha)) => (Some(branch), Some(sha)),
                None => (None, None),
            }
        };

        // Get tree SHA from commit
        let tree_sha = commit_sha.as_ref()
            .and_then(|sha| self.get_commit_tree(sha, &objects));

        // Clone objects for async block
        let objects_clone = objects.clone();

        let root_hash = self.runtime.block_on(async {
            // Build objects directory
            let objects_hash = self.build_objects_dir(&objects).await?;

            // Build refs directory
            let refs_hash = self.build_refs_dir(&refs).await?;

            // Build HEAD file - use default_branch if no explicit HEAD
            // Git expects HEAD to end with newline, so add it if missing
            let head_content = refs.get("HEAD")
                .map(|h| if h.ends_with('\n') { h.clone() } else { format!("{}\n", h) })
                .or_else(|| default_branch.as_ref().map(|b| format!("ref: {}\n", b)))
                .unwrap_or_else(|| "ref: refs/heads/main\n".to_string());
            debug!("HEAD content: {:?}", head_content);
            let head_hash = self.tree.put_blob(head_content.as_bytes()).await
                .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;
            debug!("HEAD hash: {}", hex::encode(head_hash));

            // Build .git directory
            let mut git_entries = vec![
                DirEntry::new("HEAD", head_hash).with_size(head_content.len() as u64),
                DirEntry::new("objects", objects_hash).with_link_type(LinkType::Dir),
                DirEntry::new("refs", refs_hash).with_link_type(LinkType::Dir),
            ];

            // Add config if we have a default branch
            if let Some(ref branch) = default_branch {
                let config = format!(
                    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n[init]\n\tdefaultBranch = {}\n",
                    branch.trim_start_matches("refs/heads/")
                );
                let config_hash = self.tree.put_blob(config.as_bytes()).await
                    .map_err(|e| Error::StorageError(format!("put config: {}", e)))?;
                git_entries.push(DirEntry::new("config", config_hash).with_size(config.len() as u64));
            }

            // Build and add index file if we have a tree SHA
            if let Some(ref tree_oid) = tree_sha {
                match self.build_index_file(tree_oid, &objects_clone) {
                    Ok(index_data) => {
                        let index_hash = self.tree.put_blob(&index_data).await
                            .map_err(|e| Error::StorageError(format!("put index: {}", e)))?;
                        git_entries.push(DirEntry::new("index", index_hash).with_size(index_data.len() as u64));
                        info!("Added git index file ({} bytes)", index_data.len());
                    }
                    Err(e) => {
                        debug!("Failed to build git index file: {} - continuing without index", e);
                    }
                }
            }

            let git_cid = self.tree.put_directory(git_entries).await
                .map_err(|e| Error::StorageError(format!("put .git: {}", e)))?;

            // Build root entries starting with .git
            let mut root_entries = vec![DirEntry::new(".git", git_cid.hash).with_link_type(LinkType::Dir)];

            // Add working tree files if we have a tree SHA
            if let Some(ref tree_oid) = tree_sha {
                let working_tree_entries = self.build_working_tree_entries(tree_oid, &objects_clone).await?;
                root_entries.extend(working_tree_entries);
                info!("Added {} working tree entries to root", root_entries.len() - 1);
            }

            // Sort entries for deterministic ordering
            root_entries.sort_by(|a, b| a.name.cmp(&b.name));

            let root_cid = self.tree.put_directory(root_entries).await
                .map_err(|e| Error::StorageError(format!("put root: {}", e)))?;

            info!("Built hashtree root: {} (.git dir: {})", hex::encode(root_cid.hash), hex::encode(git_cid.hash));

            Ok::<[u8; 32], Error>(root_cid.hash)
        })?;

        // Cache the root hash
        if let Ok(mut root) = self.root_hash.write() {
            *root = Some(root_hash);
        }

        Ok(root_hash)
    }

    /// Build working tree entries from a git tree object
    async fn build_working_tree_entries(
        &self,
        tree_oid: &str,
        objects: &HashMap<String, Vec<u8>>,
    ) -> Result<Vec<DirEntry>> {
        let mut entries = Vec::new();

        // Get tree content
        let (obj_type, content) = self.get_object_content(tree_oid, objects)
            .ok_or_else(|| Error::ObjectNotFound(tree_oid.to_string()))?;

        if obj_type != ObjectType::Tree {
            return Err(Error::InvalidObjectType(format!("expected tree, got {:?}", obj_type)));
        }

        // Parse tree entries
        let tree_entries = parse_tree(&content)?;

        for entry in tree_entries {
            let oid_hex = entry.oid.to_hex();

            if entry.is_tree() {
                // Recursively build subdirectory
                let sub_entries = self.build_working_tree_entries_boxed(&oid_hex, objects).await?;

                // Create subdirectory in hashtree
                let dir_cid = self.tree.put_directory(sub_entries).await
                    .map_err(|e| Error::StorageError(format!("put dir {}: {}", entry.name, e)))?;

                entries.push(
                    DirEntry::new(&entry.name, dir_cid.hash)
                        .with_link_type(LinkType::Dir)
                );
            } else {
                // Get blob content
                if let Some((ObjectType::Blob, blob_content)) = self.get_object_content(&oid_hex, objects) {
                    let blob_hash = self.tree.put_blob(&blob_content).await
                        .map_err(|e| Error::StorageError(format!("put blob {}: {}", entry.name, e)))?;

                    entries.push(
                        DirEntry::new(&entry.name, blob_hash)
                            .with_size(blob_content.len() as u64)
                    );
                }
            }
        }

        // Sort for deterministic ordering
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(entries)
    }

    /// Boxed version for async recursion
    fn build_working_tree_entries_boxed<'a>(
        &'a self,
        tree_oid: &'a str,
        objects: &'a HashMap<String, Vec<u8>>,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>>> {
        Box::pin(self.build_working_tree_entries(tree_oid, objects))
    }

    /// Build the objects directory using HashTree
    async fn build_objects_dir(&self, objects: &HashMap<String, Vec<u8>>) -> Result<[u8; 32]> {
        if objects.is_empty() {
            let empty_hash = sha256(b"");
            self.store.put(empty_hash, vec![]).await
                .map_err(|e| Error::StorageError(format!("put empty objects: {}", e)))?;
            return Ok(empty_hash);
        }

        // Group objects by first 2 characters of SHA (git loose object structure)
        // Git expects objects/XX/YYYYYY... where XX is first 2 hex chars
        let mut buckets: HashMap<String, Vec<(String, Vec<u8>)>> = HashMap::new();
        for (oid, data) in objects {
            let prefix = &oid[..2];
            let suffix = &oid[2..];
            buckets.entry(prefix.to_string())
                .or_default()
                .push((suffix.to_string(), data.clone()));
        }

        // Build subdirectories for each prefix
        let mut top_entries = Vec::new();
        for (prefix, objs) in buckets {
            let mut sub_entries = Vec::new();
            for (suffix, data) in objs {
                let hash = self.tree.put_blob(&data).await
                    .map_err(|e| Error::StorageError(format!("put object {}{}: {}", prefix, suffix, e)))?;
                sub_entries.push(DirEntry::new(suffix, hash).with_size(data.len() as u64));
            }
            // Sort for deterministic ordering
            sub_entries.sort_by(|a, b| a.name.cmp(&b.name));

            let sub_cid = self.tree.put_directory(sub_entries).await
                .map_err(|e| Error::StorageError(format!("put objects/{}: {}", prefix, e)))?;
            top_entries.push(DirEntry::new(prefix, sub_cid.hash).with_link_type(LinkType::Dir));
        }

        // Sort for deterministic ordering
        top_entries.sort_by(|a, b| a.name.cmp(&b.name));

        let bucket_count = top_entries.len();
        let cid = self.tree.put_directory(top_entries).await
            .map_err(|e| Error::StorageError(format!("put objects dir: {}", e)))?;

        debug!("Built objects dir with {} buckets: {}", bucket_count, hex::encode(cid.hash));
        Ok(cid.hash)
    }

    /// Build the refs directory using HashTree
    async fn build_refs_dir(&self, refs: &HashMap<String, String>) -> Result<[u8; 32]> {
        // Group refs by category (heads, tags, etc.)
        let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for (ref_name, value) in refs {
            let parts: Vec<&str> = ref_name.split('/').collect();
            if parts.len() >= 3 && parts[0] == "refs" {
                let category = parts[1].to_string();
                let name = parts[2..].join("/");
                groups.entry(category).or_default().push((name, value.clone()));
            }
        }

        let mut ref_entries = Vec::new();

        for (category, refs_in_category) in groups {
            let mut cat_entries = Vec::new();
            for (name, value) in refs_in_category {
                let hash = self.tree.put_blob(value.as_bytes()).await
                    .map_err(|e| Error::StorageError(format!("put ref: {}", e)))?;
                debug!("refs/{}/{} -> blob {}", category, name, hex::encode(hash));
                cat_entries.push(DirEntry::new(name, hash).with_size(value.len() as u64));
            }

            cat_entries.sort_by(|a, b| a.name.cmp(&b.name));

            let cat_cid = self.tree.put_directory(cat_entries).await
                .map_err(|e| Error::StorageError(format!("put {} dir: {}", category, e)))?;
            debug!("refs/{} dir -> {}", category, hex::encode(cat_cid.hash));
            ref_entries.push(DirEntry::new(category, cat_cid.hash).with_link_type(LinkType::Dir));
        }

        if ref_entries.is_empty() {
            let empty_hash = sha256(b"");
            self.store.put(empty_hash, vec![]).await
                .map_err(|e| Error::StorageError(format!("put empty refs: {}", e)))?;
            return Ok(empty_hash);
        }

        ref_entries.sort_by(|a, b| a.name.cmp(&b.name));

        let refs_cid = self.tree.put_directory(ref_entries).await
            .map_err(|e| Error::StorageError(format!("put refs dir: {}", e)))?;
        debug!("refs dir -> {}", hex::encode(refs_cid.hash));
        Ok(refs_cid.hash)
    }

    /// Build git index file from tree entries
    /// Returns the raw binary content of the index file
    fn build_index_file(
        &self,
        tree_oid: &str,
        objects: &HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        // Collect all file entries from the tree (recursively)
        let mut entries: Vec<(String, [u8; 20], u32, u32)> = Vec::new(); // (path, sha1, mode, size)
        self.collect_tree_entries_for_index(tree_oid, objects, "", &mut entries)?;

        // Sort entries by path (git index requirement)
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let entry_count = entries.len() as u32;
        debug!("Building git index with {} entries", entry_count);

        // Build index content
        let mut index_data = Vec::new();

        // Header: DIRC + version 2 + entry count
        index_data.extend_from_slice(b"DIRC");
        index_data.extend_from_slice(&2u32.to_be_bytes()); // version 2
        index_data.extend_from_slice(&entry_count.to_be_bytes());

        // Current time for ctime/mtime (doesn't matter much for our use case)
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        for (path, sha1, mode, size) in &entries {
            let entry_start = index_data.len();

            // ctime sec, nsec
            index_data.extend_from_slice(&now_sec.to_be_bytes());
            index_data.extend_from_slice(&0u32.to_be_bytes());
            // mtime sec, nsec
            index_data.extend_from_slice(&now_sec.to_be_bytes());
            index_data.extend_from_slice(&0u32.to_be_bytes());
            // dev, ino (use 0)
            index_data.extend_from_slice(&0u32.to_be_bytes());
            index_data.extend_from_slice(&0u32.to_be_bytes());
            // mode
            index_data.extend_from_slice(&mode.to_be_bytes());
            // uid, gid (use 0)
            index_data.extend_from_slice(&0u32.to_be_bytes());
            index_data.extend_from_slice(&0u32.to_be_bytes());
            // file size
            index_data.extend_from_slice(&size.to_be_bytes());
            // SHA-1
            index_data.extend_from_slice(sha1);
            // flags: path length (max 0xFFF) in low 12 bits
            let path_len = std::cmp::min(path.len(), 0xFFF) as u16;
            index_data.extend_from_slice(&path_len.to_be_bytes());
            // path (NUL-terminated)
            index_data.extend_from_slice(path.as_bytes());
            index_data.push(0); // NUL terminator

            // Pad to 8-byte boundary relative to entry start
            let entry_len = index_data.len() - entry_start;
            let padding = (8 - (entry_len % 8)) % 8;
            for _ in 0..padding {
                index_data.push(0);
            }
        }

        // Calculate SHA-1 checksum of everything and append
        let mut hasher = Sha1::new();
        hasher.update(&index_data);
        let checksum = hasher.finalize();
        index_data.extend_from_slice(&checksum);

        debug!("Built git index: {} bytes, {} entries", index_data.len(), entry_count);
        Ok(index_data)
    }

    /// Collect file entries from a git tree for building the index
    fn collect_tree_entries_for_index(
        &self,
        tree_oid: &str,
        objects: &HashMap<String, Vec<u8>>,
        prefix: &str,
        entries: &mut Vec<(String, [u8; 20], u32, u32)>,
    ) -> Result<()> {
        let (obj_type, content) = self.get_object_content(tree_oid, objects)
            .ok_or_else(|| Error::ObjectNotFound(tree_oid.to_string()))?;

        if obj_type != ObjectType::Tree {
            return Err(Error::InvalidObjectType(format!("expected tree, got {:?}", obj_type)));
        }

        let tree_entries = parse_tree(&content)?;

        for entry in tree_entries {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", prefix, entry.name)
            };

            let oid_hex = entry.oid.to_hex();

            if entry.is_tree() {
                // Recursively process subdirectory
                self.collect_tree_entries_for_index(&oid_hex, objects, &path, entries)?;
            } else {
                // Get blob content for size and SHA-1
                if let Some((ObjectType::Blob, blob_content)) = self.get_object_content(&oid_hex, objects) {
                    // Convert hex SHA to bytes
                    let mut sha1_bytes = [0u8; 20];
                    if let Ok(bytes) = hex::decode(&oid_hex) {
                        if bytes.len() == 20 {
                            sha1_bytes.copy_from_slice(&bytes);
                        }
                    }

                    // Mode: use entry.mode or default to regular file
                    let mode = entry.mode;
                    let size = blob_content.len() as u32;

                    entries.push((path, sha1_bytes, mode, size));
                }
            }
        }

        Ok(())
    }

    /// Get the underlying store
    pub fn store(&self) -> &Arc<LmdbBlobStore> {
        &self.store
    }

    /// Get the HashTree for direct access
    #[allow(dead_code)]
    pub fn hashtree(&self) -> &HashTree<LmdbBlobStore> {
        &self.tree
    }

    /// Push all blobs to file servers
    #[allow(dead_code)]
    pub fn push_to_file_servers(
        &self,
        blossom: &hashtree_blossom::BlossomClient,
    ) -> Result<(usize, usize)> {
        let hashes = self.store.list()
            .map_err(|e| Error::StorageError(format!("list hashes: {}", e)))?;

        info!("Pushing {} blobs to file servers", hashes.len());

        let mut uploaded = 0;
        let mut existed = 0;

        self.runtime.block_on(async {
            for hash in &hashes {
                let hex_hash = hex::encode(hash);
                let data = match self.store.get_sync(hash) {
                    Ok(Some(d)) => d,
                    _ => continue,
                };

                match blossom.upload_if_missing(&data).await {
                    Ok((_, true)) => {
                        debug!("Uploaded {}", &hex_hash[..12]);
                        uploaded += 1;
                    }
                    Ok((_, false)) => {
                        existed += 1;
                    }
                    Err(e) => {
                        debug!("Failed to upload {}: {}", &hex_hash[..12], e);
                    }
                }
            }
        });

        info!("Upload complete: {} new, {} already existed", uploaded, existed);
        Ok((uploaded, existed))
    }

    /// Clear all state (for testing or re-initialization)
    #[allow(dead_code)]
    pub fn clear(&self) -> Result<()> {
        let mut objects = self.objects.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let mut refs = self.refs.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let mut root = self.root_hash.write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;

        objects.clear();
        refs.clear();
        *root = None;
        Ok(())
    }
}
