//! Hashtree-backed git object and ref storage using LMDB persistence
//!
//! Stores git objects and refs in a hashtree merkle tree:
//!   root/
//!     refs/
//!       heads/main -> <commit-sha1>
//!       tags/v1.0 -> <tag-sha1>
//!       HEAD -> "ref: refs/heads/main" or <sha1>
//!     objects/
//!       <sha1> -> zlib-compressed loose object
//!
//! The root hash (SHA-256) is the content-addressed identifier for the entire repo state.
//! All hashtree nodes are persisted to LMDB via LmdbBlobStore.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hashtree::{sha256, BuilderConfig, DirEntry, Store, TreeBuilder, TreeReader};
use hashtree_lmdb::LmdbBlobStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::runtime::Runtime;

use crate::object::{GitObject, ObjectId, ObjectType};
use crate::refs::{validate_ref_name, NamedRef, Ref};
use crate::{Error, Result};

/// Interior mutable state for GitStorage
struct GitStorageState {
    /// Git objects: SHA-1 hex -> zlib-compressed loose object (cached in memory)
    objects: HashMap<String, Vec<u8>>,
    /// Refs: name -> value ("ref: <target>" for symbolic, or SHA-1 hex)
    refs: HashMap<String, String>,
    /// Cached root hash (invalidated on mutation)
    root_hash: Option<[u8; 32]>,
}

/// Git storage backed by hashtree with LMDB persistence
pub struct GitStorage {
    store: Arc<LmdbBlobStore>,
    runtime: Runtime,
    state: RwLock<GitStorageState>,
}

impl GitStorage {
    /// Open or create a git storage at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let runtime =
            Runtime::new().map_err(|e| Error::StorageError(format!("tokio runtime: {}", e)))?;

        let store_path = path.as_ref().join("hashtree");
        let store = Arc::new(
            LmdbBlobStore::new(&store_path)
                .map_err(|e| Error::StorageError(format!("lmdb: {}", e)))?,
        );

        Ok(Self {
            store,
            runtime,
            state: RwLock::new(GitStorageState {
                objects: HashMap::new(),
                refs: HashMap::new(),
                root_hash: None,
            }),
        })
    }

    // === Object operations ===

    /// Check if an object exists
    pub fn has_object(&self, oid: &ObjectId) -> Result<bool> {
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        Ok(state.objects.contains_key(&oid.to_hex()))
    }

    /// Read an object by ID
    pub fn read_object(&self, oid: &ObjectId) -> Result<GitObject> {
        let key = oid.to_hex();
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let compressed = state
            .objects
            .get(&key)
            .ok_or_else(|| Error::ObjectNotFound(key.clone()))?;

        // Decompress
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut data = Vec::new();
        decoder.read_to_end(&mut data)?;

        GitObject::from_loose_format(&data)
    }

    /// Write an object, returning its ID
    pub fn write_object(&self, obj: &GitObject) -> Result<ObjectId> {
        let oid = obj.id();
        let key = oid.to_hex();

        // Compress
        let loose = obj.to_loose_format();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&loose)?;
        let compressed = encoder.finish()?;

        let mut state = self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        state.objects.insert(key, compressed);
        state.root_hash = None; // Invalidate cache

        Ok(oid)
    }

    /// Write a blob, returning its ID
    pub fn write_blob(&self, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(ObjectType::Blob, content.to_vec());
        self.write_object(&obj)
    }

    /// Write a tree, returning its ID
    pub fn write_tree(&self, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(ObjectType::Tree, content.to_vec());
        self.write_object(&obj)
    }

    /// Write a commit, returning its ID
    pub fn write_commit(&self, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(ObjectType::Commit, content.to_vec());
        self.write_object(&obj)
    }

    /// Write a tag, returning its ID
    pub fn write_tag(&self, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(ObjectType::Tag, content.to_vec());
        self.write_object(&obj)
    }

    /// Write raw object data (type + content already parsed)
    pub fn write_raw_object(&self, obj_type: ObjectType, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(obj_type, content.to_vec());
        self.write_object(&obj)
    }

    /// List all object IDs
    pub fn list_objects(&self) -> Result<Vec<ObjectId>> {
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let mut oids = Vec::new();
        for key in state.objects.keys() {
            if let Some(oid) = ObjectId::from_hex(key) {
                oids.push(oid);
            }
        }
        Ok(oids)
    }

    // === Ref operations ===

    /// Read a ref
    pub fn read_ref(&self, name: &str) -> Result<Ref> {
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let value = state
            .refs
            .get(name)
            .ok_or_else(|| Error::RefNotFound(name.into()))?;

        if let Some(target) = value.strip_prefix("ref: ") {
            Ok(Ref::Symbolic(target.to_string()))
        } else {
            let oid = ObjectId::from_hex(value)
                .ok_or_else(|| Error::InvalidObjectFormat("invalid oid in ref".into()))?;
            Ok(Ref::Direct(oid))
        }
    }

    /// Write a ref
    pub fn write_ref(&self, name: &str, target: &Ref) -> Result<()> {
        validate_ref_name(name)?;

        let value = match target {
            Ref::Direct(oid) => oid.to_hex(),
            Ref::Symbolic(target) => format!("ref: {}", target),
        };

        let mut state = self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        state.refs.insert(name.to_string(), value);
        state.root_hash = None;

        Ok(())
    }

    /// Delete a ref
    pub fn delete_ref(&self, name: &str) -> Result<bool> {
        let mut state = self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let deleted = state.refs.remove(name).is_some();
        state.root_hash = None;
        Ok(deleted)
    }

    /// Resolve a ref to its final object ID (follows symbolic refs)
    pub fn resolve_ref(&self, name: &str) -> Result<ObjectId> {
        let mut current = name.to_string();
        let mut depth = 0;
        const MAX_DEPTH: usize = 10;

        loop {
            if depth >= MAX_DEPTH {
                return Err(Error::RefNotFound(format!(
                    "symbolic ref loop or too deep: {}",
                    name
                )));
            }

            match self.read_ref(&current)? {
                Ref::Direct(oid) => return Ok(oid),
                Ref::Symbolic(target) => {
                    current = target;
                    depth += 1;
                }
            }
        }
    }

    /// List all refs
    pub fn list_refs(&self) -> Result<Vec<NamedRef>> {
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let mut named_refs = Vec::new();

        for (name, value) in &state.refs {
            let reference = if let Some(target) = value.strip_prefix("ref: ") {
                Ref::Symbolic(target.to_string())
            } else if let Some(oid) = ObjectId::from_hex(value) {
                Ref::Direct(oid)
            } else {
                continue;
            };
            named_refs.push(NamedRef::new(name.clone(), reference));
        }

        Ok(named_refs)
    }

    /// List refs matching a prefix (e.g., "refs/heads/")
    pub fn list_refs_with_prefix(&self, prefix: &str) -> Result<Vec<NamedRef>> {
        let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let mut named_refs = Vec::new();

        for (name, value) in &state.refs {
            if !name.starts_with(prefix) {
                continue;
            }
            let reference = if let Some(target) = value.strip_prefix("ref: ") {
                Ref::Symbolic(target.to_string())
            } else if let Some(oid) = ObjectId::from_hex(value) {
                Ref::Direct(oid)
            } else {
                continue;
            };
            named_refs.push(NamedRef::new(name.clone(), reference));
        }

        Ok(named_refs)
    }

    /// Update a ref atomically, checking the old value
    pub fn compare_and_swap_ref(
        &self,
        name: &str,
        expected: Option<&ObjectId>,
        new_value: Option<&ObjectId>,
    ) -> Result<bool> {
        validate_ref_name(name)?;

        let mut state = self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;

        // Check current value
        let current = state.refs.get(name);
        let current_oid = current.and_then(|v| ObjectId::from_hex(v));

        match (expected, current_oid.as_ref()) {
            (None, None) => {}                         // Creating new ref
            (Some(exp), Some(cur)) if exp == cur => {} // Expected matches
            (None, Some(_)) => return Ok(false),       // Expected empty but exists
            (Some(_), None) => return Ok(false),       // Expected value but empty
            (Some(_), Some(_)) => return Ok(false),    // Values don't match
        }

        match new_value {
            Some(oid) => {
                state.refs.insert(name.to_string(), oid.to_hex());
            }
            None => {
                state.refs.remove(name);
            }
        }
        state.root_hash = None;

        Ok(true)
    }

    // === Hashtree operations ===

    /// Build the merkle tree and return root hash (SHA-256)
    /// Also persists all nodes to LMDB
    pub fn build_tree(&mut self) -> Result<[u8; 32]> {
        {
            let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            if let Some(hash) = state.root_hash {
                return Ok(hash);
            }
        }

        let (objects, refs) = {
            let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            (state.objects.clone(), state.refs.clone())
        };
        let store = self.store.clone();

        let config = BuilderConfig::new(store.clone());
        let builder = TreeBuilder::new(config);

        let root_hash = self.runtime.block_on(async {
            let objects_hash = build_objects_dir(&builder, &store, &objects).await?;
            let refs_hash = build_refs_dir(&builder, &store, &refs).await?;

            let root_entries = vec![
                DirEntry::new("objects", objects_hash),
                DirEntry::new("refs", refs_hash),
            ];

            let root = builder
                .put_directory(root_entries, None)
                .await
                .map_err(|e| Error::StorageError(format!("build tree: {}", e)))?;

            Ok::<[u8; 32], Error>(root)
        })?;

        self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?.root_hash = Some(root_hash);
        Ok(root_hash)
    }

    /// Get root hash as hex string
    pub fn get_root_hash(&mut self) -> Result<String> {
        let hash = self.build_tree()?;
        Ok(hex::encode(hash))
    }

    /// Get the underlying store
    pub fn store(&self) -> &Arc<LmdbBlobStore> {
        &self.store
    }

    /// Load from a root hash (fetches tree structure from LMDB store)
    pub fn load_from_root(&mut self, root_hash: &str) -> Result<()> {
        let hash_bytes = hex::decode(root_hash)
            .map_err(|_| Error::StorageError("invalid root hash hex".into()))?;

        if hash_bytes.len() != 32 {
            return Err(Error::StorageError("root hash must be 32 bytes".into()));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&hash_bytes);

        let store = self.store.clone();

        // Load into temporary collections
        let mut objects = HashMap::new();
        let mut refs = HashMap::new();

        self.runtime.block_on(async {
            let reader = TreeReader::new(store);
            load_tree_recursive(&reader, root, &mut objects, &mut refs).await
        })?;

        // Merge into state
        let mut state = self.state.write().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        state.objects.extend(objects);
        state.refs.extend(refs);
        state.root_hash = Some(root);

        Ok(())
    }
}

/// Build objects/ directory in hashtree
async fn build_objects_dir<S: Store>(
    builder: &TreeBuilder<S>,
    store: &Arc<S>,
    objects: &HashMap<String, Vec<u8>>,
) -> Result<[u8; 32]> {
    let mut entries = Vec::new();

    for (sha1, compressed) in objects {
        let hash = builder
            .put_blob(compressed)
            .await
            .map_err(|e| Error::StorageError(format!("put blob: {}", e)))?;
        entries.push(DirEntry::new(sha1.clone(), hash).with_size(compressed.len() as u64));
    }

    if entries.is_empty() {
        let hash = sha256(b"");
        store
            .put(hash, vec![])
            .await
            .map_err(|e| Error::StorageError(format!("put empty: {}", e)))?;
        return Ok(hash);
    }

    builder
        .put_directory(entries, None)
        .await
        .map_err(|e| Error::StorageError(format!("put objects dir: {}", e)))
}

/// Build refs/ directory in hashtree
async fn build_refs_dir<S: Store>(
    builder: &TreeBuilder<S>,
    store: &Arc<S>,
    refs: &HashMap<String, String>,
) -> Result<[u8; 32]> {
    // Group refs by category (heads, tags, etc.)
    let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for (ref_name, value) in refs {
        let parts: Vec<&str> = ref_name.split('/').collect();
        if parts.len() >= 3 && parts[0] == "refs" {
            let category = parts[1].to_string();
            let name = parts[2..].join("/");
            groups
                .entry(category)
                .or_default()
                .push((name, value.clone()));
        } else if ref_name == "HEAD" {
            groups
                .entry("HEAD".to_string())
                .or_default()
                .push(("".to_string(), value.clone()));
        }
    }

    let mut ref_entries = Vec::new();

    for (category, refs_in_category) in groups {
        if category == "HEAD" {
            if let Some((_, value)) = refs_in_category.first() {
                let hash = builder
                    .put_blob(value.as_bytes())
                    .await
                    .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;
                ref_entries.push(DirEntry::new("HEAD", hash).with_size(value.len() as u64));
            }
        } else {
            let mut cat_entries = Vec::new();
            for (name, value) in refs_in_category {
                let hash = builder
                    .put_blob(value.as_bytes())
                    .await
                    .map_err(|e| Error::StorageError(format!("put ref: {}", e)))?;
                cat_entries.push(DirEntry::new(name, hash).with_size(value.len() as u64));
            }
            let cat_hash = builder
                .put_directory(cat_entries, None)
                .await
                .map_err(|e| Error::StorageError(format!("put {} dir: {}", category, e)))?;
            ref_entries.push(DirEntry::new(category, cat_hash));
        }
    }

    if ref_entries.is_empty() {
        let hash = sha256(b"");
        store
            .put(hash, vec![])
            .await
            .map_err(|e| Error::StorageError(format!("put empty refs: {}", e)))?;
        return Ok(hash);
    }

    builder
        .put_directory(ref_entries, None)
        .await
        .map_err(|e| Error::StorageError(format!("put refs dir: {}", e)))
}

/// Recursively load tree from hashtree using TreeReader walk
async fn load_tree_recursive<S: Store>(
    reader: &TreeReader<S>,
    root: [u8; 32],
    objects: &mut HashMap<String, Vec<u8>>,
    refs: &mut HashMap<String, String>,
) -> Result<()> {
    // Walk the entire tree
    let entries = reader
        .walk(&root, "")
        .await
        .map_err(|e| Error::StorageError(format!("walk tree: {}", e)))?;

    for entry in entries {
        // Skip directory entries, only process files
        if entry.is_tree {
            continue;
        }

        // Read the file content
        let data = reader
            .read_file(&entry.hash)
            .await
            .map_err(|e| Error::StorageError(format!("read file: {}", e)))?
            .ok_or_else(|| Error::StorageError("file not found".into()))?;

        // Determine if this is an object or ref based on path
        if entry.path.starts_with("objects/") {
            let sha1 = entry.path.strip_prefix("objects/").unwrap();
            objects.insert(sha1.to_string(), data);
        } else if entry.path.starts_with("refs/") {
            refs.insert(entry.path.clone(), String::from_utf8_lossy(&data).to_string());
        } else if entry.path == "HEAD" {
            refs.insert("HEAD".to_string(), String::from_utf8_lossy(&data).to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_object_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let content = b"hello world\n";
        let oid = storage.write_blob(content).unwrap();

        // Known hash for "hello world\n"
        assert_eq!(oid.to_hex(), "3b18e512dba79e4c8300dd08aeb37f8e728b8dad");

        let obj = storage.read_object(&oid).unwrap();
        assert_eq!(obj.content, content);
    }

    #[test]
    fn test_ref_operations() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let oid = storage.write_blob(b"test").unwrap();

        // Write direct ref
        storage
            .write_ref("refs/heads/main", &Ref::Direct(oid))
            .unwrap();

        // Read it back
        let resolved = storage.resolve_ref("refs/heads/main").unwrap();
        assert_eq!(resolved, oid);

        // Write symbolic ref
        storage
            .write_ref("HEAD", &Ref::Symbolic("refs/heads/main".into()))
            .unwrap();

        // Resolve through symbolic
        let head_resolved = storage.resolve_ref("HEAD").unwrap();
        assert_eq!(head_resolved, oid);

        // List refs
        let refs = storage.list_refs().unwrap();
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_has_object() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let oid = storage.write_blob(b"test").unwrap();
        assert!(storage.has_object(&oid).unwrap());

        let fake_oid = ObjectId::from_hex("0000000000000000000000000000000000000000").unwrap();
        assert!(!storage.has_object(&fake_oid).unwrap());
    }

    #[test]
    fn test_build_tree_and_persist() {
        let dir = tempdir().unwrap();
        let mut storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Add some data
        storage.write_blob(b"hello").unwrap();
        storage
            .write_ref(
                "refs/heads/main",
                &Ref::Direct(
                    ObjectId::from_hex("abc123def456abc123def456abc123def456abc1").unwrap(),
                ),
            )
            .unwrap();

        // Build tree (persists to LMDB)
        let root_hash = storage.build_tree().unwrap();
        assert_eq!(root_hash.len(), 32);

        // Verify data is in LMDB
        let stats = storage.store().stats().unwrap();
        assert!(stats.count > 0, "should have stored hashtree nodes in LMDB");

        // Get hex
        let hex = storage.get_root_hash().unwrap();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_load_from_root() {
        let dir = tempdir().unwrap();

        // Create and populate storage
        let root_hex = {
            let mut storage = GitStorage::open(dir.path().join("git")).unwrap();
            storage.write_blob(b"test content").unwrap();
            storage
                .write_ref(
                    "refs/heads/main",
                    &Ref::Direct(
                        ObjectId::from_hex("abc123def456abc123def456abc123def456abc1").unwrap(),
                    ),
                )
                .unwrap();
            storage.get_root_hash().unwrap()
        };

        // Load from root in new storage instance
        let mut storage2 = GitStorage::open(dir.path().join("git")).unwrap();
        storage2.load_from_root(&root_hex).unwrap();

        // Verify refs loaded
        let refs = storage2.list_refs().unwrap();
        assert_eq!(refs.len(), 1);
    }
}
