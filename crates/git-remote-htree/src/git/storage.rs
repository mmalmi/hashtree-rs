//! Hashtree-backed git object and ref storage using LMDB persistence
//!
//! Stores git objects and refs in a hashtree merkle tree:
//!   root/
//!     .git/
//!       HEAD -> "ref: refs/heads/main"
//!       refs/heads/main -> <commit-sha1>
//!       objects/<sha1> -> zlib-compressed loose object
//!
//! The root hash (SHA-256) is the content-addressed identifier for the entire repo state.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hashtree_core::{sha256, DirEntry, HashTree, HashTreeConfig, LinkType, Store};
use hashtree_lmdb::LmdbBlobStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, info};

use super::object::{GitObject, ObjectId, ObjectType};
use super::refs::{validate_ref_name, Ref};
use super::{Error, Result};

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
    pub fn get_root_hash(&self) -> Result<Option<[u8; 32]>> {
        let root = self.root_hash.read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        Ok(*root)
    }

    /// Get the default branch name
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

        let default_branch = if let Some(head) = refs.get("HEAD") {
            head.strip_prefix("ref: ").map(String::from)
        } else {
            None
        };

        let root_hash = self.runtime.block_on(async {
            // Build objects directory
            let objects_hash = self.build_objects_dir(&objects).await?;

            // Build refs directory
            let refs_hash = self.build_refs_dir(&refs).await?;

            // Build HEAD file
            let head_content = refs.get("HEAD")
                .cloned()
                .unwrap_or_else(|| "ref: refs/heads/main".to_string());
            let head_hash = self.tree.put_blob(head_content.as_bytes()).await
                .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;

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

            let git_cid = self.tree.put_directory(git_entries).await
                .map_err(|e| Error::StorageError(format!("put .git: {}", e)))?;

            // Build root with just .git
            let root_entries = vec![DirEntry::new(".git", git_cid.hash).with_link_type(LinkType::Dir)];
            let root_cid = self.tree.put_directory(root_entries).await
                .map_err(|e| Error::StorageError(format!("put root: {}", e)))?;

            info!("Built hashtree root: {} (.git dir: {})", hex::encode(root_cid.hash), hex::encode(git_cid.hash));

            // Verify the root is stored correctly
            if let Ok(Some(data)) = self.store.get(&root_cid.hash).await {
                info!("Root blob stored: {} bytes, starts with: {:?}", data.len(), &data[..data.len().min(20)]);
            }

            Ok::<[u8; 32], Error>(root_cid.hash)
        })?;

        // Cache the root hash
        if let Ok(mut root) = self.root_hash.write() {
            *root = Some(root_hash);
        }

        Ok(root_hash)
    }

    /// Build the objects directory using HashTree
    async fn build_objects_dir(&self, objects: &HashMap<String, Vec<u8>>) -> Result<[u8; 32]> {
        if objects.is_empty() {
            let empty_hash = sha256(b"");
            self.store.put(empty_hash, vec![]).await
                .map_err(|e| Error::StorageError(format!("put empty objects: {}", e)))?;
            return Ok(empty_hash);
        }

        // Store objects flat with full SHA1 as filename
        let mut entries = Vec::with_capacity(objects.len());
        for (oid, data) in objects {
            let hash = self.tree.put_blob(data).await
                .map_err(|e| Error::StorageError(format!("put object {}: {}", oid, e)))?;
            entries.push(DirEntry::new(oid.clone(), hash).with_size(data.len() as u64));
        }

        // Sort for deterministic ordering
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let cid = self.tree.put_directory(entries).await
            .map_err(|e| Error::StorageError(format!("put objects dir: {}", e)))?;

        debug!("Built objects dir with {} entries: {}", objects.len(), hex::encode(cid.hash));
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

    /// Get the underlying store
    pub fn store(&self) -> &Arc<LmdbBlobStore> {
        &self.store
    }

    /// Get the HashTree for direct access
    pub fn hashtree(&self) -> &HashTree<LmdbBlobStore> {
        &self.tree
    }

    /// Push all blobs to file servers
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
