use anyhow::{Context, Result};
use heed::{Database, EnvOpenOptions};
use heed::types::*;
use hashtree_lmdb::LmdbBlobStore;
use hashtree::{
    HashTree, HashTreeConfig, Cid,
    sha256, to_hex, from_hex, Hash, TreeNode, DirEntry as HashTreeDirEntry,
};
use hashtree::store::{Store, StoreError};
use std::path::Path;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use futures::executor::block_on as sync_block_on;

#[cfg(feature = "s3")]
use tokio::sync::mpsc;

use crate::config::S3Config;

/// Message for background S3 sync
#[cfg(feature = "s3")]
enum S3SyncMessage {
    Upload { hash: Hash, data: Vec<u8> },
    Delete { hash: Hash },
}

/// Storage router - LMDB primary with optional S3 backup
///
/// Write path: LMDB first (fast), then queue S3 upload (non-blocking)
/// Read path: LMDB first, fall back to S3 if miss
pub struct StorageRouter {
    /// Primary local store (always used)
    local: Arc<LmdbBlobStore>,
    /// Optional S3 client for backup
    #[cfg(feature = "s3")]
    s3_client: Option<aws_sdk_s3::Client>,
    #[cfg(feature = "s3")]
    s3_bucket: Option<String>,
    #[cfg(feature = "s3")]
    s3_prefix: String,
    /// Channel to send uploads to background task
    #[cfg(feature = "s3")]
    sync_tx: Option<mpsc::UnboundedSender<S3SyncMessage>>,
}

impl StorageRouter {
    /// Create router with LMDB only
    pub fn new(local: Arc<LmdbBlobStore>) -> Self {
        Self {
            local,
            #[cfg(feature = "s3")]
            s3_client: None,
            #[cfg(feature = "s3")]
            s3_bucket: None,
            #[cfg(feature = "s3")]
            s3_prefix: String::new(),
            #[cfg(feature = "s3")]
            sync_tx: None,
        }
    }

    /// Create router with LMDB + S3 backup
    #[cfg(feature = "s3")]
    pub async fn with_s3(local: Arc<LmdbBlobStore>, config: &S3Config) -> Result<Self, anyhow::Error> {
        use aws_sdk_s3::Client as S3Client;

        // Build AWS config
        let mut aws_config_loader = aws_config::from_env();
        aws_config_loader = aws_config_loader.region(aws_sdk_s3::config::Region::new(config.region.clone()));
        let aws_config = aws_config_loader.load().await;

        // Build S3 client with custom endpoint
        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);
        s3_config_builder = s3_config_builder
            .endpoint_url(&config.endpoint)
            .force_path_style(true);

        let s3_client = S3Client::from_conf(s3_config_builder.build());
        let bucket = config.bucket.clone();
        let prefix = config.prefix.clone().unwrap_or_default();

        // Create background sync channel
        let (sync_tx, mut sync_rx) = mpsc::unbounded_channel::<S3SyncMessage>();

        // Spawn background sync task
        let sync_client = s3_client.clone();
        let sync_bucket = bucket.clone();
        let sync_prefix = prefix.clone();

        tokio::spawn(async move {
            use aws_sdk_s3::primitives::ByteStream;

            tracing::info!("S3 background sync task started");

            while let Some(msg) = sync_rx.recv().await {
                match msg {
                    S3SyncMessage::Upload { hash, data } => {
                        let key = format!("{}{}", sync_prefix, to_hex(&hash));
                        tracing::debug!("S3 uploading {} ({} bytes)", &key[..16.min(key.len())], data.len());

                        if let Err(e) = sync_client
                            .put_object()
                            .bucket(&sync_bucket)
                            .key(&key)
                            .body(ByteStream::from(data))
                            .send()
                            .await
                        {
                            tracing::error!("S3 upload failed for {}: {}", &key[..16.min(key.len())], e);
                        }
                    }
                    S3SyncMessage::Delete { hash } => {
                        let key = format!("{}{}", sync_prefix, to_hex(&hash));
                        tracing::debug!("S3 deleting {}", &key[..16.min(key.len())]);

                        if let Err(e) = sync_client
                            .delete_object()
                            .bucket(&sync_bucket)
                            .key(&key)
                            .send()
                            .await
                        {
                            tracing::error!("S3 delete failed for {}: {}", &key[..16.min(key.len())], e);
                        }
                    }
                }
            }
        });

        tracing::info!("S3 storage initialized: bucket={}, prefix={}", bucket, prefix);

        Ok(Self {
            local,
            s3_client: Some(s3_client),
            s3_bucket: Some(bucket),
            s3_prefix: prefix,
            sync_tx: Some(sync_tx),
        })
    }

    /// Store data - writes to LMDB, queues S3 upload in background
    pub fn put_sync(&self, hash: Hash, data: &[u8]) -> Result<bool, StoreError> {
        // Always write to local first
        let is_new = self.local.put_sync(hash, data)?;

        // Queue S3 upload if configured (non-blocking)
        #[cfg(feature = "s3")]
        if is_new {
            if let Some(ref tx) = self.sync_tx {
                let _ = tx.send(S3SyncMessage::Upload { hash, data: data.to_vec() });
            }
        }

        Ok(is_new)
    }

    /// Get data - tries LMDB first, falls back to S3
    pub fn get_sync(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local.get_sync(hash)? {
            return Ok(Some(data));
        }

        // Fall back to S3 if configured
        #[cfg(feature = "s3")]
        if let (Some(ref client), Some(ref bucket)) = (&self.s3_client, &self.s3_bucket) {
            let key = format!("{}{}", self.s3_prefix, to_hex(hash));

            match sync_block_on(async {
                client.get_object()
                    .bucket(bucket)
                    .key(&key)
                    .send()
                    .await
            }) {
                Ok(output) => {
                    if let Ok(body) = sync_block_on(output.body.collect()) {
                        let data = body.into_bytes().to_vec();
                        // Cache locally for future reads
                        let _ = self.local.put_sync(*hash, &data);
                        return Ok(Some(data));
                    }
                }
                Err(e) => {
                    let service_err = e.into_service_error();
                    if !service_err.is_no_such_key() {
                        tracing::warn!("S3 get failed: {}", service_err);
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check if hash exists
    pub fn exists(&self, hash: &Hash) -> Result<bool, StoreError> {
        // Check local first
        if self.local.exists(hash)? {
            return Ok(true);
        }

        // Check S3 if configured
        #[cfg(feature = "s3")]
        if let (Some(ref client), Some(ref bucket)) = (&self.s3_client, &self.s3_bucket) {
            let key = format!("{}{}", self.s3_prefix, to_hex(hash));

            match sync_block_on(async {
                client.head_object()
                    .bucket(bucket)
                    .key(&key)
                    .send()
                    .await
            }) {
                Ok(_) => return Ok(true),
                Err(e) => {
                    let service_err = e.into_service_error();
                    if !service_err.is_not_found() {
                        tracing::warn!("S3 head failed: {}", service_err);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Delete data from both stores
    pub fn delete_sync(&self, hash: &Hash) -> Result<bool, StoreError> {
        let deleted = self.local.delete_sync(hash)?;

        // Queue S3 delete if configured
        #[cfg(feature = "s3")]
        if let Some(ref tx) = self.sync_tx {
            let _ = tx.send(S3SyncMessage::Delete { hash: *hash });
        }

        Ok(deleted)
    }

    /// Get stats from local store
    pub fn stats(&self) -> Result<hashtree_lmdb::LmdbStats, StoreError> {
        self.local.stats()
    }

    /// List all hashes from local store
    pub fn list(&self) -> Result<Vec<Hash>, StoreError> {
        self.local.list()
    }

    /// Get the underlying LMDB store for HashTree operations
    pub fn local_store(&self) -> Arc<LmdbBlobStore> {
        Arc::clone(&self.local)
    }
}

pub struct HashtreeStore {
    env: heed::Env,
    /// Set of pinned hashes (hex strings, prevents garbage collection)
    pins: Database<Str, Unit>,
    /// Maps SHA256 hex -> root hash hex (for blossom compatibility)
    sha256_index: Database<Str, Str>,
    /// Maps SHA256 hex -> pubkey (blob ownership for blossom)
    blob_owners: Database<Str, Str>,
    /// Maps pubkey -> blob metadata JSON (for blossom list)
    pubkey_blobs: Database<Str, Bytes>,
    /// Storage router - handles LMDB + optional S3
    router: StorageRouter,
}

impl HashtreeStore {
    /// Create a new store with local LMDB storage only
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_s3(path, None)
    }

    /// Create a new store with optional S3 backend
    /// If s3_config is Some, blobs will be synced to S3 in the background
    pub fn with_s3<P: AsRef<Path>>(path: P, s3_config: Option<&S3Config>) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(10 * 1024 * 1024 * 1024) // 10GB
                .max_dbs(5)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;
        let pins = env.create_database(&mut wtxn, Some("pins"))?;
        let sha256_index = env.create_database(&mut wtxn, Some("sha256_index"))?;
        let blob_owners = env.create_database(&mut wtxn, Some("blob_owners"))?;
        let pubkey_blobs = env.create_database(&mut wtxn, Some("pubkey_blobs"))?;
        wtxn.commit()?;

        // Create local LMDB blob store
        let lmdb_store = Arc::new(LmdbBlobStore::new(path.join("blobs"))
            .map_err(|e| anyhow::anyhow!("Failed to create blob store: {}", e))?);

        // Create storage router with optional S3
        #[cfg(feature = "s3")]
        let router = if let Some(s3_cfg) = s3_config {
            tracing::info!("Initializing S3 storage backend: bucket={}, endpoint={}",
                s3_cfg.bucket, s3_cfg.endpoint);

            sync_block_on(async {
                StorageRouter::with_s3(lmdb_store, s3_cfg).await
            })?
        } else {
            StorageRouter::new(lmdb_store)
        };

        #[cfg(not(feature = "s3"))]
        let router = {
            if s3_config.is_some() {
                tracing::warn!("S3 config provided but S3 feature not enabled. Using local storage only.");
            }
            StorageRouter::new(lmdb_store)
        };

        Ok(Self {
            env,
            pins,
            sha256_index,
            blob_owners,
            pubkey_blobs,
            router,
        })
    }

    /// Get the storage router
    pub fn router(&self) -> &StorageRouter {
        &self.router
    }

    /// Get the underlying LMDB store for HashTree operations
    pub fn blob_store_arc(&self) -> Arc<LmdbBlobStore> {
        self.router.local_store()
    }

    /// Upload a file and return its CID (public/unencrypted)
    pub fn upload_file<P: AsRef<Path>>(&self, file_path: P) -> Result<String> {
        let file_path = file_path.as_ref();
        let file_content = std::fs::read(file_path)?;

        // Compute SHA256 hash of file content for blossom compatibility
        let content_sha256 = sha256(&file_content);
        let sha256_hex = to_hex(&content_sha256);

        // Use hashtree to store the file (public mode - no encryption)
        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        let cid = sync_block_on(async {
            tree.put(&file_content).await
        }).context("Failed to store file")?;

        let root_hex = to_hex(&cid.hash);

        let mut wtxn = self.env.write_txn()?;

        // Store SHA256 -> root hash mapping for blossom compatibility
        self.sha256_index.put(&mut wtxn, &sha256_hex, &root_hex)?;

        // Auto-pin on upload
        self.pins.put(&mut wtxn, &root_hex, &())?;

        wtxn.commit()?;

        Ok(root_hex)
    }

    /// Upload a file from a stream with progress callbacks
    pub fn upload_file_stream<R: Read, F>(
        &self,
        mut reader: R,
        _file_name: impl Into<String>,
        mut callback: F,
    ) -> Result<String>
    where
        F: FnMut(&str),
    {
        // Read all data first to compute SHA256
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        // Compute SHA256 hash of file content for blossom compatibility
        let content_sha256 = sha256(&data);
        let sha256_hex = to_hex(&content_sha256);

        // Use HashTree.put for upload (public mode for blossom)
        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        let cid = sync_block_on(async {
            tree.put(&data).await
        }).context("Failed to store file")?;

        let root_hex = to_hex(&cid.hash);
        callback(&root_hex);

        let mut wtxn = self.env.write_txn()?;

        // Store SHA256 -> root hash mapping for blossom compatibility
        self.sha256_index.put(&mut wtxn, &sha256_hex, &root_hex)?;

        // Auto-pin on upload
        self.pins.put(&mut wtxn, &root_hex, &())?;

        wtxn.commit()?;

        Ok(root_hex)
    }

    /// Upload a directory and return its root hash (hex)
    /// Respects .gitignore by default
    pub fn upload_dir<P: AsRef<Path>>(&self, dir_path: P) -> Result<String> {
        self.upload_dir_with_options(dir_path, true)
    }

    /// Upload a directory with options (public mode - no encryption)
    pub fn upload_dir_with_options<P: AsRef<Path>>(&self, dir_path: P, respect_gitignore: bool) -> Result<String> {
        let dir_path = dir_path.as_ref();

        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        let root_cid = sync_block_on(async {
            self.upload_dir_recursive(&tree, dir_path, dir_path, respect_gitignore).await
        }).context("Failed to upload directory")?;

        let root_hex = to_hex(&root_cid.hash);

        let mut wtxn = self.env.write_txn()?;
        self.pins.put(&mut wtxn, &root_hex, &())?;
        wtxn.commit()?;

        Ok(root_hex)
    }

    async fn upload_dir_recursive<S: Store>(
        &self,
        tree: &HashTree<S>,
        _root_path: &Path,
        current_path: &Path,
        respect_gitignore: bool,
    ) -> Result<Cid> {
        use ignore::WalkBuilder;
        use std::collections::HashMap;

        // Build directory structure from flat file list - store full Cid with key
        let mut dir_contents: HashMap<String, Vec<(String, Cid)>> = HashMap::new();
        dir_contents.insert(String::new(), Vec::new()); // Root

        let walker = WalkBuilder::new(current_path)
            .git_ignore(respect_gitignore)
            .git_global(respect_gitignore)
            .git_exclude(respect_gitignore)
            .hidden(false)
            .build();

        for result in walker {
            let entry = result?;
            let path = entry.path();

            // Skip the root directory itself
            if path == current_path {
                continue;
            }

            let relative = path.strip_prefix(current_path)
                .unwrap_or(path);

            if path.is_file() {
                let content = std::fs::read(path)?;
                let cid = tree.put(&content).await
                    .map_err(|e| anyhow::anyhow!("Failed to upload file {}: {}", path.display(), e))?;

                // Get parent directory path and file name
                let parent = relative.parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let name = relative.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                dir_contents.entry(parent).or_default().push((name, cid));
            } else if path.is_dir() {
                // Ensure directory entry exists
                let dir_path = relative.to_string_lossy().to_string();
                dir_contents.entry(dir_path).or_default();
            }
        }

        // Build directory tree bottom-up
        self.build_directory_tree(tree, &mut dir_contents).await
    }

    async fn build_directory_tree<S: Store>(
        &self,
        tree: &HashTree<S>,
        dir_contents: &mut std::collections::HashMap<String, Vec<(String, Cid)>>,
    ) -> Result<Cid> {
        // Sort directories by depth (deepest first) to build bottom-up
        let mut dirs: Vec<String> = dir_contents.keys().cloned().collect();
        dirs.sort_by(|a, b| {
            let depth_a = a.matches('/').count() + if a.is_empty() { 0 } else { 1 };
            let depth_b = b.matches('/').count() + if b.is_empty() { 0 } else { 1 };
            depth_b.cmp(&depth_a) // Deepest first
        });

        let mut dir_cids: std::collections::HashMap<String, Cid> = std::collections::HashMap::new();

        for dir_path in dirs {
            let files = dir_contents.get(&dir_path).cloned().unwrap_or_default();

            let mut entries: Vec<HashTreeDirEntry> = files.into_iter()
                .map(|(name, cid)| HashTreeDirEntry::from_cid(name, &cid))
                .collect();

            // Add subdirectory entries
            for (subdir_path, cid) in &dir_cids {
                let parent = std::path::Path::new(subdir_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if parent == dir_path {
                    let name = std::path::Path::new(subdir_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    entries.push(HashTreeDirEntry::from_cid(name, cid));
                }
            }

            let cid = tree.put_directory(entries).await
                .map_err(|e| anyhow::anyhow!("Failed to create directory node: {}", e))?;

            dir_cids.insert(dir_path, cid);
        }

        // Return root Cid
        dir_cids.get("")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No root directory"))
    }

    /// Upload a file with CHK encryption, returns CID in format "hash:key"
    pub fn upload_file_encrypted<P: AsRef<Path>>(&self, file_path: P) -> Result<String> {
        let file_path = file_path.as_ref();
        let file_content = std::fs::read(file_path)?;

        // Use unified API with encryption enabled (default)
        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store));

        let cid = sync_block_on(async {
            tree.put(&file_content).await
        }).map_err(|e| anyhow::anyhow!("Failed to encrypt file: {}", e))?;

        let cid_str = cid.to_string();

        let mut wtxn = self.env.write_txn()?;
        self.pins.put(&mut wtxn, &cid_str, &())?;
        wtxn.commit()?;

        Ok(cid_str)
    }

    /// Upload a directory with CHK encryption, returns CID
    /// Respects .gitignore by default
    pub fn upload_dir_encrypted<P: AsRef<Path>>(&self, dir_path: P) -> Result<String> {
        self.upload_dir_encrypted_with_options(dir_path, true)
    }

    /// Upload a directory with CHK encryption and options
    /// Returns CID as "hash:key" format for encrypted directories
    pub fn upload_dir_encrypted_with_options<P: AsRef<Path>>(&self, dir_path: P, respect_gitignore: bool) -> Result<String> {
        let dir_path = dir_path.as_ref();
        let store = self.router.local_store();

        // Use unified API with encryption enabled (default)
        let tree = HashTree::new(HashTreeConfig::new(store));

        let root_cid = sync_block_on(async {
            self.upload_dir_recursive(&tree, dir_path, dir_path, respect_gitignore).await
        }).context("Failed to upload encrypted directory")?;

        let cid_str = root_cid.to_string(); // Returns "hash:key" or "hash"

        let mut wtxn = self.env.write_txn()?;
        // Pin by hash only (the key is for decryption, not identification)
        self.pins.put(&mut wtxn, &to_hex(&root_cid.hash), &())?;
        wtxn.commit()?;

        Ok(cid_str)
    }

    /// Get tree node by hash (hex)
    pub fn get_tree_node(&self, hash_hex: &str) -> Result<Option<TreeNode>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        sync_block_on(async {
            tree.get_tree_node(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get tree node: {}", e))
        })
    }

    /// Look up root hash by SHA256 hash (blossom compatibility)
    pub fn get_cid_by_sha256(&self, sha256_hex: &str) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.sha256_index.get(&rtxn, sha256_hex)?.map(|s| s.to_string()))
    }

    /// Store a raw blob, returns SHA256 hash as hex.
    pub fn put_blob(&self, data: &[u8]) -> Result<String> {
        let hash = sha256(data);
        self.router.put_sync(hash, data)
            .map_err(|e| anyhow::anyhow!("Failed to store blob: {}", e))?;
        Ok(to_hex(&hash))
    }

    /// Get a raw blob by SHA256 hex hash.
    pub fn get_blob(&self, sha256_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        self.router.get_sync(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to get blob: {}", e))
    }

    /// Check if a blob exists by SHA256 hex hash.
    pub fn blob_exists(&self, sha256_hex: &str) -> Result<bool> {
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        self.router.exists(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to check blob: {}", e))
    }

    // === Blossom ownership tracking ===

    /// Set the owner (pubkey) of a blob for Blossom protocol
    pub fn set_blob_owner(&self, sha256_hex: &str, pubkey: &str) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut wtxn = self.env.write_txn()?;

        // Store sha256 -> pubkey mapping
        self.blob_owners.put(&mut wtxn, sha256_hex, pubkey)?;

        // Get existing blobs for this pubkey
        let mut blobs: Vec<BlobMetadata> = self
            .pubkey_blobs
            .get(&wtxn, pubkey)?
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();

        // Check if blob already exists for this pubkey
        if !blobs.iter().any(|b| b.sha256 == sha256_hex) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Get size from root hash lookup
            let size = self
                .get_cid_by_sha256(sha256_hex)?
                .and_then(|cid| self.get_file_chunk_metadata(&cid).ok().flatten())
                .map(|m| m.total_size)
                .unwrap_or(0);

            blobs.push(BlobMetadata {
                sha256: sha256_hex.to_string(),
                size,
                mime_type: "application/octet-stream".to_string(),
                uploaded: now,
            });

            let blobs_json = serde_json::to_vec(&blobs)?;
            self.pubkey_blobs.put(&mut wtxn, pubkey, &blobs_json)?;
        }

        wtxn.commit()?;
        Ok(())
    }

    /// Get the owner (pubkey) of a blob
    pub fn get_blob_owner(&self, sha256_hex: &str) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.blob_owners.get(&rtxn, sha256_hex)?.map(|s| s.to_string()))
    }

    /// Delete a blossom blob and remove ownership tracking
    pub fn delete_blossom_blob(&self, sha256_hex: &str) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;

        // Get owner first
        let owner = self.blob_owners.get(&wtxn, sha256_hex)?.map(|s| s.to_string());

        // Delete from sha256_index
        let root_hex = self.sha256_index.get(&wtxn, sha256_hex)?.map(|s| s.to_string());
        if let Some(ref root_hex) = root_hex {
            // Unpin
            self.pins.delete(&mut wtxn, root_hex)?;
        }
        self.sha256_index.delete(&mut wtxn, sha256_hex)?;

        // Delete ownership
        self.blob_owners.delete(&mut wtxn, sha256_hex)?;

        // Remove from pubkey's blob list
        if let Some(ref pubkey) = owner {
            if let Some(blobs_bytes) = self.pubkey_blobs.get(&wtxn, pubkey)? {
                if let Ok(mut blobs) = serde_json::from_slice::<Vec<BlobMetadata>>(blobs_bytes) {
                    blobs.retain(|b| b.sha256 != sha256_hex);
                    let blobs_json = serde_json::to_vec(&blobs)?;
                    self.pubkey_blobs.put(&mut wtxn, pubkey, &blobs_json)?;
                }
            }
        }

        // Delete raw blob (by content hash)
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        let _ = self.router.delete_sync(&hash);

        wtxn.commit()?;
        Ok(root_hex.is_some())
    }

    /// List all blobs owned by a pubkey (for Blossom /list endpoint)
    pub fn list_blobs_by_pubkey(&self, pubkey: &str) -> Result<Vec<crate::server::blossom::BlobDescriptor>> {
        let rtxn = self.env.read_txn()?;

        let blobs: Vec<BlobMetadata> = self
            .pubkey_blobs
            .get(&rtxn, pubkey)?
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();

        Ok(blobs
            .into_iter()
            .map(|b| crate::server::blossom::BlobDescriptor {
                url: format!("/{}", b.sha256),
                sha256: b.sha256,
                size: b.size,
                mime_type: b.mime_type,
                uploaded: b.uploaded,
            })
            .collect())
    }

    /// Get a single chunk/blob by hash (hex)
    pub fn get_chunk(&self, chunk_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(chunk_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;
        self.router.get_sync(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to get chunk: {}", e))
    }

    /// Get file content by hash (hex)
    /// Returns raw bytes (caller handles decryption if needed)
    pub fn get_file(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        sync_block_on(async {
            tree.read_file(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))
        })
    }

    /// Get chunk metadata for a file (chunk list, sizes, total size)
    pub fn get_file_chunk_metadata(&self, hash_hex: &str) -> Result<Option<FileChunkMetadata>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        sync_block_on(async {
            // First check if the hash exists in the store at all
            // (either as a blob or tree node)
            let exists = store.has(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check existence: {}", e))?;

            if !exists {
                return Ok(None);
            }

            // Get total size
            let total_size = tree.get_size(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get size: {}", e))?;

            // Check if it's a tree (chunked) or blob
            let is_tree_node = tree.is_tree(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check tree: {}", e))?;

            if !is_tree_node {
                // Single blob, not chunked
                return Ok(Some(FileChunkMetadata {
                    total_size,
                    chunk_cids: vec![],
                    chunk_sizes: vec![],
                    is_chunked: false,
                }));
            }

            // Get tree node to extract chunk info
            let node = match tree.get_tree_node(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get tree node: {}", e))? {
                Some(n) => n,
                None => return Ok(None),
            };

            // Check if it's a directory (has named links)
            let is_directory = tree.is_directory(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check directory: {}", e))?;

            if is_directory {
                return Ok(None); // Not a file
            }

            // Extract chunk info from links
            let chunk_cids: Vec<String> = node.links.iter().map(|l| to_hex(&l.hash)).collect();
            let chunk_sizes: Vec<u64> = node.links.iter().map(|l| l.size).collect();

            Ok(Some(FileChunkMetadata {
                total_size,
                chunk_cids,
                chunk_sizes,
                is_chunked: !node.links.is_empty(),
            }))
        })
    }

    /// Get byte range from file
    pub fn get_file_range(&self, hash_hex: &str, start: u64, end: Option<u64>) -> Result<Option<(Vec<u8>, u64)>> {
        let metadata = match self.get_file_chunk_metadata(hash_hex)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.total_size == 0 {
            return Ok(Some((Vec::new(), 0)));
        }

        if start >= metadata.total_size {
            return Ok(None);
        }

        let end = end.unwrap_or(metadata.total_size - 1).min(metadata.total_size - 1);

        // For non-chunked files, load entire file
        if !metadata.is_chunked {
            let content = self.get_file(hash_hex)?.unwrap_or_default();
            let range_content = if start < content.len() as u64 {
                content[start as usize..=(end as usize).min(content.len() - 1)].to_vec()
            } else {
                Vec::new()
            };
            return Ok(Some((range_content, metadata.total_size)));
        }

        // For chunked files, load only needed chunks
        let mut result = Vec::new();
        let mut current_offset = 0u64;

        for (i, chunk_cid) in metadata.chunk_cids.iter().enumerate() {
            let chunk_size = metadata.chunk_sizes[i];
            let chunk_end = current_offset + chunk_size - 1;

            // Check if this chunk overlaps with requested range
            if chunk_end >= start && current_offset <= end {
                let chunk_content = match self.get_chunk(chunk_cid)? {
                    Some(content) => content,
                    None => {
                        return Err(anyhow::anyhow!("Chunk {} not found", chunk_cid));
                    }
                };

                let chunk_read_start = if current_offset >= start {
                    0
                } else {
                    (start - current_offset) as usize
                };

                let chunk_read_end = if chunk_end <= end {
                    chunk_size as usize - 1
                } else {
                    (end - current_offset) as usize
                };

                result.extend_from_slice(&chunk_content[chunk_read_start..=chunk_read_end]);
            }

            current_offset += chunk_size;

            if current_offset > end {
                break;
            }
        }

        Ok(Some((result, metadata.total_size)))
    }

    /// Stream file range as chunks using Arc for async/Send contexts
    pub fn stream_file_range_chunks_owned(
        self: Arc<Self>,
        hash_hex: &str,
        start: u64,
        end: u64,
    ) -> Result<Option<FileRangeChunksOwned>> {
        let metadata = match self.get_file_chunk_metadata(hash_hex)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.total_size == 0 || start >= metadata.total_size {
            return Ok(None);
        }

        let end = end.min(metadata.total_size - 1);

        Ok(Some(FileRangeChunksOwned {
            store: self,
            metadata,
            start,
            end,
            current_chunk_idx: 0,
            current_offset: 0,
        }))
    }

    /// Get directory structure by hash (hex)
    pub fn get_directory_listing(&self, hash_hex: &str) -> Result<Option<DirectoryListing>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        sync_block_on(async {
            // Check if it's a directory
            let is_dir = tree.is_directory(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check directory: {}", e))?;

            if !is_dir {
                return Ok(None);
            }

            // Get directory entries (public Cid - no encryption key)
            let cid = hashtree::Cid::public(hash, 0);
            let tree_entries = tree.list_directory(&cid).await
                .map_err(|e| anyhow::anyhow!("Failed to list directory: {}", e))?;

            let entries: Vec<DirEntry> = tree_entries.into_iter().map(|e| DirEntry {
                name: e.name,
                cid: to_hex(&e.hash),
                is_directory: e.link_type.is_tree(),
                size: e.size,
            }).collect();

            Ok(Some(DirectoryListing {
                dir_name: String::new(),
                entries,
            }))
        })
    }

    /// Pin a hash (prevent garbage collection)
    pub fn pin(&self, hash_hex: &str) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.pins.put(&mut wtxn, hash_hex, &())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Unpin a hash (allow garbage collection)
    pub fn unpin(&self, hash_hex: &str) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.pins.delete(&mut wtxn, hash_hex)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Check if hash is pinned
    pub fn is_pinned(&self, hash_hex: &str) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.pins.get(&rtxn, hash_hex)?.is_some())
    }

    /// List all pinned hashes
    pub fn list_pins(&self) -> Result<Vec<String>> {
        let rtxn = self.env.read_txn()?;
        let mut pins = Vec::new();

        for item in self.pins.iter(&rtxn)? {
            let (hash_hex, _) = item?;
            pins.push(hash_hex.to_string());
        }

        Ok(pins)
    }

    /// List all pinned hashes with names
    pub fn list_pins_with_names(&self) -> Result<Vec<PinnedItem>> {
        let rtxn = self.env.read_txn()?;
        let store = self.router.local_store();
        let tree = HashTree::new(HashTreeConfig::new(store).public());
        let mut pins = Vec::new();

        for item in self.pins.iter(&rtxn)? {
            let (hash_hex, _) = item?;
            let hash_hex_str = hash_hex.to_string();

            // Try to determine if it's a directory
            let is_directory = if let Ok(hash) = from_hex(&hash_hex_str) {
                sync_block_on(async {
                    tree.is_directory(&hash).await.unwrap_or(false)
                })
            } else {
                false
            };

            pins.push(PinnedItem {
                cid: hash_hex_str,
                name: "Unknown".to_string(),
                is_directory,
            });
        }

        Ok(pins)
    }

    /// Get storage statistics
    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let rtxn = self.env.read_txn()?;
        let total_pins = self.pins.len(&rtxn)? as usize;

        let stats = self.router.stats()
            .map_err(|e| anyhow::anyhow!("Failed to get stats: {}", e))?;

        Ok(StorageStats {
            total_dags: stats.count,
            pinned_dags: total_pins,
            total_bytes: stats.total_bytes,
        })
    }

    /// Garbage collect unpinned content
    pub fn gc(&self) -> Result<GcStats> {
        let rtxn = self.env.read_txn()?;

        // Get all pinned hashes
        let pinned: HashSet<String> = self.pins.iter(&rtxn)?
            .filter_map(|item| item.ok())
            .map(|(hash_hex, _)| hash_hex.to_string())
            .collect();

        drop(rtxn);

        // Get all stored hashes
        let all_hashes = self.router.list()
            .map_err(|e| anyhow::anyhow!("Failed to list hashes: {}", e))?;

        // Delete unpinned hashes
        let mut deleted = 0;
        let mut freed_bytes = 0u64;

        for hash in all_hashes {
            let hash_hex = to_hex(&hash);
            if !pinned.contains(&hash_hex) {
                if let Ok(Some(data)) = self.router.get_sync(&hash) {
                    freed_bytes += data.len() as u64;
                    let _ = self.router.delete_sync(&hash);
                    deleted += 1;
                }
            }
        }

        Ok(GcStats {
            deleted_dags: deleted,
            freed_bytes,
        })
    }
}

#[derive(Debug)]
pub struct StorageStats {
    pub total_dags: usize,
    pub pinned_dags: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FileChunkMetadata {
    pub total_size: u64,
    pub chunk_cids: Vec<String>,
    pub chunk_sizes: Vec<u64>,
    pub is_chunked: bool,
}

/// Owned iterator for async streaming
pub struct FileRangeChunksOwned {
    store: Arc<HashtreeStore>,
    metadata: FileChunkMetadata,
    start: u64,
    end: u64,
    current_chunk_idx: usize,
    current_offset: u64,
}

impl Iterator for FileRangeChunksOwned {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.metadata.is_chunked || self.current_chunk_idx >= self.metadata.chunk_cids.len() {
            return None;
        }

        if self.current_offset > self.end {
            return None;
        }

        let chunk_cid = &self.metadata.chunk_cids[self.current_chunk_idx];
        let chunk_size = self.metadata.chunk_sizes[self.current_chunk_idx];
        let chunk_end = self.current_offset + chunk_size - 1;

        self.current_chunk_idx += 1;

        if chunk_end < self.start || self.current_offset > self.end {
            self.current_offset += chunk_size;
            return self.next();
        }

        let chunk_content = match self.store.get_chunk(chunk_cid) {
            Ok(Some(content)) => content,
            Ok(None) => {
                return Some(Err(anyhow::anyhow!("Chunk {} not found", chunk_cid)));
            }
            Err(e) => {
                return Some(Err(e));
            }
        };

        let chunk_read_start = if self.current_offset >= self.start {
            0
        } else {
            (self.start - self.current_offset) as usize
        };

        let chunk_read_end = if chunk_end <= self.end {
            chunk_size as usize - 1
        } else {
            (self.end - self.current_offset) as usize
        };

        let result = chunk_content[chunk_read_start..=chunk_read_end].to_vec();
        self.current_offset += chunk_size;

        Some(Ok(result))
    }
}

#[derive(Debug)]
pub struct GcStats {
    pub deleted_dags: usize,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub cid: String,
    pub is_directory: bool,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DirectoryListing {
    pub dir_name: String,
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Clone)]
pub struct PinnedItem {
    pub cid: String,
    pub name: String,
    pub is_directory: bool,
}

/// Blob metadata for Blossom protocol
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobMetadata {
    pub sha256: String,
    pub size: u64,
    pub mime_type: String,
    pub uploaded: u64,
}

// Implement ContentStore trait for WebRTC data exchange
impl crate::webrtc::ContentStore for HashtreeStore {
    fn get(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        self.get_chunk(hash_hex)
    }
}
