//! Hashtree-backed git object and ref storage using LMDB persistence
//!
//! Stores git objects and refs in a hashtree merkle tree with working tree:
//!   root/
//!     .git/
//!       HEAD -> "ref: refs/heads/main"
//!       refs/
//!         heads/main -> <commit-sha1>
//!         tags/v1.0 -> <tag-sha1>
//!       objects/
//!         <sha1> -> zlib-compressed loose object
//!     README.md -> actual file content (from HEAD)
//!     src/main.rs -> actual file content
//!
//! The working tree is extracted from HEAD commit for direct browsing.
//! The root hash (SHA-256) is the content-addressed identifier for the entire repo state.
//! All hashtree nodes are persisted to LMDB via LmdbBlobStore.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hashtree::{sha256, HashTree, HashTreeConfig, DirEntry, Store, Cid};
use hashtree_lmdb::LmdbBlobStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::runtime::Runtime;

use crate::object::{GitObject, ObjectId, ObjectType, parse_tree};
use crate::refs::{validate_ref_name, NamedRef, Ref};
use crate::{Error, Result};

/// Represents a file in the working tree
#[derive(Debug, Clone)]
pub struct WorkingTreeEntry {
    pub path: String,
    pub mode: u32,
    pub content: Vec<u8>,
}

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
    /// Includes .git/ directory and working tree from HEAD
    /// Also persists all nodes to LMDB
    pub fn build_tree(&mut self) -> Result<[u8; 32]> {
        {
            let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            if let Some(hash) = state.root_hash {
                return Ok(hash);
            }
        }

        // Determine HEAD and extract working tree
        let default_branch = self.determine_default_branch();
        let working_tree = if let Some(ref branch) = default_branch {
            if let Ok(commit_oid) = self.resolve_ref(branch) {
                self.extract_working_tree(&commit_oid).ok()
            } else {
                None
            }
        } else {
            None
        };

        let (objects, refs) = {
            let state = self.state.read().map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            (state.objects.clone(), state.refs.clone())
        };
        let store = self.store.clone();

        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        let root_hash = self.runtime.block_on(async {
            // Build .git directory
            let git_dir_hash = build_git_dir(&tree, &store, &objects, &refs, &default_branch).await?;

            // Build working tree entries
            let mut root_entries = vec![
                DirEntry::new(".git", git_dir_hash),
            ];

            // Add working tree files
            if let Some(wt) = working_tree {
                let wt_entries = build_working_tree(&tree, wt).await?;
                root_entries.extend(wt_entries);
            }

            let root_cid = tree
                .put_directory(root_entries, None)
                .await
                .map_err(|e| Error::StorageError(format!("build tree: {}", e)))?;

            Ok::<[u8; 32], Error>(root_cid.hash)
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

    /// Determine the default branch for HEAD
    /// Priority: master > main > alphabetically first branch
    pub fn determine_default_branch(&self) -> Option<String> {
        let state = self.state.read().ok()?;

        let branches: Vec<&String> = state.refs.keys()
            .filter(|k| k.starts_with("refs/heads/"))
            .collect();

        if branches.is_empty() {
            return None;
        }

        // Check for master first
        if branches.iter().any(|b| *b == "refs/heads/master") {
            return Some("refs/heads/master".to_string());
        }

        // Then main
        if branches.iter().any(|b| *b == "refs/heads/main") {
            return Some("refs/heads/main".to_string());
        }

        // Fall back to alphabetically first
        let mut sorted: Vec<_> = branches.into_iter().collect();
        sorted.sort();
        sorted.first().map(|s| (*s).clone())
    }

    /// Extract the working tree from a commit
    /// Returns a list of (path, mode, content) for all files
    pub fn extract_working_tree(&self, commit_oid: &ObjectId) -> Result<Vec<WorkingTreeEntry>> {
        let commit_obj = self.read_object(commit_oid)?;
        if commit_obj.obj_type != ObjectType::Commit {
            return Err(Error::InvalidObjectFormat("expected commit".into()));
        }

        // Parse commit to get tree OID
        let commit_content = String::from_utf8_lossy(&commit_obj.content);
        let tree_line = commit_content.lines()
            .find(|l| l.starts_with("tree "))
            .ok_or_else(|| Error::InvalidObjectFormat("commit missing tree".into()))?;

        let tree_hex = tree_line.strip_prefix("tree ").unwrap().trim();
        let tree_oid = ObjectId::from_hex(tree_hex)
            .ok_or_else(|| Error::InvalidObjectFormat("invalid tree oid".into()))?;

        // Recursively extract files from tree
        let mut entries = Vec::new();
        self.extract_tree_recursive(&tree_oid, "", &mut entries)?;
        Ok(entries)
    }

    /// Recursively extract files from a git tree object
    fn extract_tree_recursive(
        &self,
        tree_oid: &ObjectId,
        prefix: &str,
        entries: &mut Vec<WorkingTreeEntry>,
    ) -> Result<()> {
        let tree_obj = self.read_object(tree_oid)?;
        if tree_obj.obj_type != ObjectType::Tree {
            return Err(Error::InvalidObjectFormat("expected tree".into()));
        }

        let tree_entries = parse_tree(&tree_obj.content)?;

        for entry in tree_entries {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", prefix, entry.name)
            };

            if entry.is_tree() {
                // Recurse into subdirectory
                self.extract_tree_recursive(&entry.oid, &path, entries)?;
            } else {
                // Read blob content
                let blob_obj = self.read_object(&entry.oid)?;
                entries.push(WorkingTreeEntry {
                    path,
                    mode: entry.mode,
                    content: blob_obj.content,
                });
            }
        }

        Ok(())
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
            let tree = HashTree::new(HashTreeConfig::new(store).public());
            load_tree_recursive(&tree, root, &mut objects, &mut refs).await
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
    tree: &HashTree<S>,
    store: &Arc<S>,
    objects: &HashMap<String, Vec<u8>>,
) -> Result<[u8; 32]> {
    let mut entries = Vec::new();

    for (sha1, compressed) in objects {
        let hash = tree
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

    tree
        .put_directory(entries, None)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put objects dir: {}", e)))
}

/// Build refs/ directory in hashtree
async fn build_refs_dir<S: Store>(
    tree: &HashTree<S>,
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
                let hash = tree
                    .put_blob(value.as_bytes())
                    .await
                    .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;
                ref_entries.push(DirEntry::new("HEAD", hash).with_size(value.len() as u64));
            }
        } else {
            let mut cat_entries = Vec::new();
            for (name, value) in refs_in_category {
                let hash = tree
                    .put_blob(value.as_bytes())
                    .await
                    .map_err(|e| Error::StorageError(format!("put ref: {}", e)))?;
                cat_entries.push(DirEntry::new(name, hash).with_size(value.len() as u64));
            }
            let cat_cid = tree
                .put_directory(cat_entries, None)
                .await
                .map_err(|e| Error::StorageError(format!("put {} dir: {}", category, e)))?;
            ref_entries.push(DirEntry::new(category, cat_cid.hash));
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

    tree
        .put_directory(ref_entries, None)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put refs dir: {}", e)))
}

/// Build .git/ directory in hashtree (objects, refs, HEAD)
async fn build_git_dir<S: Store>(
    tree: &HashTree<S>,
    store: &Arc<S>,
    objects: &HashMap<String, Vec<u8>>,
    refs: &HashMap<String, String>,
    default_branch: &Option<String>,
) -> Result<[u8; 32]> {
    let objects_hash = build_objects_dir(tree, store, objects).await?;
    let refs_hash = build_refs_dir(tree, store, refs).await?;

    let mut git_entries = vec![
        DirEntry::new("objects", objects_hash),
        DirEntry::new("refs", refs_hash),
    ];

    // Add HEAD pointing to default branch
    if let Some(branch) = default_branch {
        let head_content = format!("ref: {}", branch);
        let head_hash = tree
            .put_blob(head_content.as_bytes())
            .await
            .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;
        git_entries.push(DirEntry::new("HEAD", head_hash).with_size(head_content.len() as u64));
    }

    tree
        .put_directory(git_entries, None)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put .git dir: {}", e)))
}

/// Build working tree entries from extracted files
/// Returns DirEntry items for the root directory
async fn build_working_tree<S: Store>(
    tree: &HashTree<S>,
    entries: Vec<WorkingTreeEntry>,
) -> Result<Vec<DirEntry>> {
    // Group entries by top-level directory
    let mut dirs: HashMap<String, Vec<WorkingTreeEntry>> = HashMap::new();
    let mut root_files: Vec<WorkingTreeEntry> = Vec::new();

    for entry in entries {
        if let Some(slash_pos) = entry.path.find('/') {
            let top_dir = entry.path[..slash_pos].to_string();
            let rest = entry.path[slash_pos + 1..].to_string();
            dirs.entry(top_dir).or_default().push(WorkingTreeEntry {
                path: rest,
                mode: entry.mode,
                content: entry.content,
            });
        } else {
            root_files.push(entry);
        }
    }

    let mut result = Vec::new();

    // Add root-level files
    for file in root_files {
        let hash = tree
            .put_blob(&file.content)
            .await
            .map_err(|e| Error::StorageError(format!("put file {}: {}", file.path, e)))?;
        result.push(DirEntry::new(file.path, hash).with_size(file.content.len() as u64));
    }

    // Recursively build subdirectories
    for (dir_name, sub_entries) in dirs {
        let sub_dir_entries = build_working_tree_recursive(tree, sub_entries).await?;
        let dir_cid = tree
            .put_directory(sub_dir_entries, None)
            .await
            .map_err(|e| Error::StorageError(format!("put dir {}: {}", dir_name, e)))?;
        result.push(DirEntry::new(dir_name, dir_cid.hash));
    }

    Ok(result)
}

/// Recursively build a subdirectory's entries
async fn build_working_tree_recursive<S: Store>(
    tree: &HashTree<S>,
    entries: Vec<WorkingTreeEntry>,
) -> Result<Vec<DirEntry>> {
    let mut dirs: HashMap<String, Vec<WorkingTreeEntry>> = HashMap::new();
    let mut files: Vec<WorkingTreeEntry> = Vec::new();

    for entry in entries {
        if let Some(slash_pos) = entry.path.find('/') {
            let top_dir = entry.path[..slash_pos].to_string();
            let rest = entry.path[slash_pos + 1..].to_string();
            dirs.entry(top_dir).or_default().push(WorkingTreeEntry {
                path: rest,
                mode: entry.mode,
                content: entry.content,
            });
        } else {
            files.push(entry);
        }
    }

    let mut result = Vec::new();

    // Add files
    for file in files {
        let hash = tree
            .put_blob(&file.content)
            .await
            .map_err(|e| Error::StorageError(format!("put file {}: {}", file.path, e)))?;
        result.push(DirEntry::new(file.path, hash).with_size(file.content.len() as u64));
    }

    // Recurse into subdirectories
    for (dir_name, sub_entries) in dirs {
        let sub_dir_entries = Box::pin(build_working_tree_recursive(tree, sub_entries)).await?;
        let dir_cid = tree
            .put_directory(sub_dir_entries, None)
            .await
            .map_err(|e| Error::StorageError(format!("put dir {}: {}", dir_name, e)))?;
        result.push(DirEntry::new(dir_name, dir_cid.hash));
    }

    Ok(result)
}

/// Recursively load tree from hashtree using HashTree walk
/// Supports both old format (objects/, refs/) and new format (.git/objects/, .git/refs/)
async fn load_tree_recursive<S: Store>(
    tree: &HashTree<S>,
    root: [u8; 32],
    objects: &mut HashMap<String, Vec<u8>>,
    refs: &mut HashMap<String, String>,
) -> Result<()> {
    // Walk the entire tree (public mode - no encryption key)
    let root_cid = Cid::public(root, 0);
    let entries = tree
        .walk(&root_cid, "")
        .await
        .map_err(|e| Error::StorageError(format!("walk tree: {}", e)))?;

    for entry in entries {
        // Skip directory entries, only process files
        if entry.is_tree {
            continue;
        }

        // Read the file content
        let data = tree
            .read_file(&entry.hash)
            .await
            .map_err(|e| Error::StorageError(format!("read file: {}", e)))?
            .ok_or_else(|| Error::StorageError("file not found".into()))?;

        // Determine if this is an object or ref based on path
        // Support both .git/ prefix (new) and no prefix (old format)
        let path = &entry.path;

        if let Some(rest) = path.strip_prefix(".git/objects/") {
            objects.insert(rest.to_string(), data);
        } else if let Some(rest) = path.strip_prefix(".git/refs/") {
            refs.insert(format!("refs/{}", rest), String::from_utf8_lossy(&data).to_string());
        } else if path == ".git/HEAD" {
            refs.insert("HEAD".to_string(), String::from_utf8_lossy(&data).to_string());
        } else if let Some(rest) = path.strip_prefix("objects/") {
            // Old format compatibility
            objects.insert(rest.to_string(), data);
        } else if let Some(rest) = path.strip_prefix("refs/") {
            // Old format compatibility
            refs.insert(format!("refs/{}", rest), String::from_utf8_lossy(&data).to_string());
        } else if path == "HEAD" {
            // Old format compatibility
            refs.insert("HEAD".to_string(), String::from_utf8_lossy(&data).to_string());
        }
        // Skip working tree files (not in .git/)
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

        // Verify refs loaded (now includes HEAD pointing to default branch)
        let refs = storage2.list_refs().unwrap();
        // Should have refs/heads/main and HEAD
        assert!(refs.iter().any(|r| r.name == "refs/heads/main"));
    }

    #[test]
    fn test_determine_default_branch_master_first() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let oid = ObjectId::from_hex("abc123def456abc123def456abc123def456abc1").unwrap();

        // Add both main and master
        storage.write_ref("refs/heads/main", &Ref::Direct(oid)).unwrap();
        storage.write_ref("refs/heads/master", &Ref::Direct(oid)).unwrap();
        storage.write_ref("refs/heads/develop", &Ref::Direct(oid)).unwrap();

        // master should win
        assert_eq!(
            storage.determine_default_branch(),
            Some("refs/heads/master".to_string())
        );
    }

    #[test]
    fn test_determine_default_branch_main_second() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let oid = ObjectId::from_hex("abc123def456abc123def456abc123def456abc1").unwrap();

        // Add main and others, but not master
        storage.write_ref("refs/heads/main", &Ref::Direct(oid)).unwrap();
        storage.write_ref("refs/heads/develop", &Ref::Direct(oid)).unwrap();

        // main should win
        assert_eq!(
            storage.determine_default_branch(),
            Some("refs/heads/main".to_string())
        );
    }

    #[test]
    fn test_determine_default_branch_alphabetical() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let oid = ObjectId::from_hex("abc123def456abc123def456abc123def456abc1").unwrap();

        // No main or master
        storage.write_ref("refs/heads/develop", &Ref::Direct(oid)).unwrap();
        storage.write_ref("refs/heads/feature", &Ref::Direct(oid)).unwrap();

        // Alphabetically first should win
        assert_eq!(
            storage.determine_default_branch(),
            Some("refs/heads/develop".to_string())
        );
    }

    #[test]
    fn test_determine_default_branch_empty() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        // No branches
        assert_eq!(storage.determine_default_branch(), None);
    }

    #[test]
    fn test_working_tree_extraction() {
        use crate::object::serialize_tree;

        let dir = tempdir().unwrap();
        let mut storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create a simple repo structure:
        // README.md
        // src/main.rs

        // 1. Create blobs
        let readme_content = b"# Test Repo\n\nThis is a test.";
        let main_rs_content = b"fn main() {\n    println!(\"Hello\");\n}";

        let readme_oid = storage.write_blob(readme_content).unwrap();
        let main_rs_oid = storage.write_blob(main_rs_content).unwrap();

        // 2. Create src/ tree
        let src_tree_content = serialize_tree(&[
            crate::object::TreeEntry::new(0o100644, "main.rs".to_string(), main_rs_oid),
        ]);
        let src_tree_oid = storage.write_tree(&src_tree_content).unwrap();

        // 3. Create root tree
        let root_tree_content = serialize_tree(&[
            crate::object::TreeEntry::new(0o100644, "README.md".to_string(), readme_oid),
            crate::object::TreeEntry::new(0o40000, "src".to_string(), src_tree_oid),
        ]);
        let root_tree_oid = storage.write_tree(&root_tree_content).unwrap();

        // 4. Create commit
        let commit_content = format!(
            "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial commit\n",
            root_tree_oid.to_hex()
        );
        let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

        // 5. Create ref
        storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();

        // 6. Extract working tree
        let working_tree = storage.extract_working_tree(&commit_oid).unwrap();

        // Verify we got both files
        assert_eq!(working_tree.len(), 2);

        let readme = working_tree.iter().find(|e| e.path == "README.md").unwrap();
        assert_eq!(readme.content, readme_content);
        assert_eq!(readme.mode, 0o100644);

        let main_rs = working_tree.iter().find(|e| e.path == "src/main.rs").unwrap();
        assert_eq!(main_rs.content, main_rs_content);
    }

    #[test]
    fn test_build_tree_with_working_tree() {
        use crate::object::serialize_tree;

        let dir = tempdir().unwrap();
        let mut storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create a repo with files
        let readme_content = b"# Hello World";
        let readme_oid = storage.write_blob(readme_content).unwrap();

        let root_tree_content = serialize_tree(&[
            crate::object::TreeEntry::new(0o100644, "README.md".to_string(), readme_oid),
        ]);
        let root_tree_oid = storage.write_tree(&root_tree_content).unwrap();

        let commit_content = format!(
            "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nTest\n",
            root_tree_oid.to_hex()
        );
        let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

        storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();

        // Build the tree
        let root_hash = storage.build_tree().unwrap();
        assert_eq!(root_hash.len(), 32);

        // Verify we can load it back
        let root_hex = hex::encode(root_hash);

        // Create new storage and load
        let mut storage2 = GitStorage::open(dir.path().join("git")).unwrap();
        storage2.load_from_root(&root_hex).unwrap();

        // Should have the ref
        let refs = storage2.list_refs().unwrap();
        assert!(refs.iter().any(|r| r.name == "refs/heads/main"));

        // Should be able to read the blob
        assert!(storage2.has_object(&readme_oid).unwrap());
    }

    #[test]
    fn test_full_push_simulation() {
        use crate::object::serialize_tree;

        let dir = tempdir().unwrap();
        let mut storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Simulate what git-remote-htree does on push:
        // 1. Receive objects from git
        // 2. Store them
        // 3. Update refs
        // 4. Build tree (which now includes working tree)

        // Create files
        let files = vec![
            ("README.md", b"# My Project\n".as_slice()),
            ("Cargo.toml", b"[package]\nname = \"test\"\n".as_slice()),
            ("src/lib.rs", b"pub fn hello() {}\n".as_slice()),
            ("src/main.rs", b"fn main() { hello(); }\n".as_slice()),
        ];

        // Store blobs
        let mut blob_oids = Vec::new();
        for (_, content) in &files {
            blob_oids.push(storage.write_blob(content).unwrap());
        }

        // Create src/ tree
        let src_tree = serialize_tree(&[
            crate::object::TreeEntry::new(0o100644, "lib.rs".to_string(), blob_oids[2]),
            crate::object::TreeEntry::new(0o100644, "main.rs".to_string(), blob_oids[3]),
        ]);
        let src_tree_oid = storage.write_tree(&src_tree).unwrap();

        // Create root tree
        let root_tree = serialize_tree(&[
            crate::object::TreeEntry::new(0o100644, "Cargo.toml".to_string(), blob_oids[1]),
            crate::object::TreeEntry::new(0o100644, "README.md".to_string(), blob_oids[0]),
            crate::object::TreeEntry::new(0o40000, "src".to_string(), src_tree_oid),
        ]);
        let root_tree_oid = storage.write_tree(&root_tree).unwrap();

        // Create commit
        let commit = format!(
            "tree {}\nauthor Dev <dev@example.com> 1700000000 +0000\ncommitter Dev <dev@example.com> 1700000000 +0000\n\nAdd project files\n",
            root_tree_oid.to_hex()
        );
        let commit_oid = storage.write_commit(commit.as_bytes()).unwrap();

        // Update ref (this is what push does)
        storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();

        // Build the hashtree (this should now include working tree)
        let root_hash = storage.get_root_hash().unwrap();
        println!("Root hash: {}", root_hash);

        // Verify: load and check structure
        let store = storage.store().clone();
        let tree = HashTree::new(HashTreeConfig::new(store).public());

        let root_bytes: [u8; 32] = hex::decode(&root_hash).unwrap().try_into().unwrap();
        let root_cid = Cid::public(root_bytes, 0);

        // Walk the tree and collect paths
        let rt = tokio::runtime::Runtime::new().unwrap();
        let entries = rt.block_on(async {
            tree.walk(&root_cid, "").await.unwrap()
        });

        let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
        println!("Paths in tree: {:?}", paths);

        // Should have .git directory
        assert!(paths.iter().any(|p| p.starts_with(".git/")), "Missing .git/ directory");

        // Should have .git/objects
        assert!(paths.iter().any(|p| p.starts_with(".git/objects/")), "Missing .git/objects/");

        // Should have .git/refs
        assert!(paths.iter().any(|p| p.starts_with(".git/refs/")), "Missing .git/refs/");

        // Should have .git/HEAD
        assert!(paths.iter().any(|p| p == ".git/HEAD"), "Missing .git/HEAD");

        // Should have working tree files at root
        assert!(paths.iter().any(|p| p == "README.md"), "Missing README.md in working tree");
        assert!(paths.iter().any(|p| p == "Cargo.toml"), "Missing Cargo.toml in working tree");
        assert!(paths.iter().any(|p| p == "src/lib.rs"), "Missing src/lib.rs in working tree");
        assert!(paths.iter().any(|p| p == "src/main.rs"), "Missing src/main.rs in working tree");

        println!("All checks passed!");
    }
}
