//! Hashtree-backed git object and ref storage using LMDB persistence
//!
//! Stores git objects and refs in a hashtree merkle tree with working tree:
//!   root/
//!     .git/
//!       HEAD -> "ref: refs/heads/main"
//!       refs/heads/main -> <commit-sha1>
//!       objects/<sha1> -> zlib-compressed loose object
//!     README.md -> actual file content (from HEAD)
//!
//! The root hash (SHA-256) is the content-addressed identifier for the entire repo state.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hashtree_core::{sha256, DirEntry, HashTree, HashTreeConfig, Store};
use hashtree_lmdb::LmdbBlobStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::runtime::{Handle, Runtime};

use super::object::{parse_tree, GitObject, ObjectId, ObjectType};
use super::refs::{validate_ref_name, Ref};
use super::{Error, Result};

/// Represents a file in the working tree
#[derive(Debug, Clone)]
struct WorkingTreeEntry {
    path: String,
    mode: u32,
    content: Vec<u8>,
}

/// Interior mutable state for GitStorage
struct GitStorageState {
    /// Git objects: SHA-1 hex -> zlib-compressed loose object
    objects: HashMap<String, Vec<u8>>,
    /// Refs: name -> value ("ref: <target>" for symbolic, or SHA-1 hex)
    refs: HashMap<String, String>,
    /// Cached root hash (invalidated on mutation)
    root_hash: Option<[u8; 32]>,
}

/// Runtime executor - either owns a runtime or reuses an existing one
enum RuntimeExecutor {
    Owned(Runtime),
    Handle(Handle),
}

impl RuntimeExecutor {
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        match self {
            RuntimeExecutor::Owned(rt) => rt.block_on(f),
            RuntimeExecutor::Handle(handle) => {
                tokio::task::block_in_place(|| handle.block_on(f))
            }
        }
    }
}

/// Git storage backed by hashtree with LMDB persistence
pub struct GitStorage {
    store: Arc<LmdbBlobStore>,
    runtime: RuntimeExecutor,
    state: RwLock<GitStorageState>,
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

    /// Write an object, returning its ID
    fn write_object(&self, obj: &GitObject) -> Result<ObjectId> {
        let oid = obj.id();
        let key = oid.to_hex();

        let loose = obj.to_loose_format();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&loose)?;
        let compressed = encoder.finish()?;

        let mut state = self
            .state
            .write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        state.objects.insert(key, compressed);
        state.root_hash = None;

        Ok(oid)
    }

    /// Write raw object data (type + content already parsed)
    pub fn write_raw_object(&self, obj_type: ObjectType, content: &[u8]) -> Result<ObjectId> {
        let obj = GitObject::new(obj_type, content.to_vec());
        self.write_object(&obj)
    }

    /// Read an object by ID
    fn read_object(&self, oid: &ObjectId) -> Result<GitObject> {
        let key = oid.to_hex();
        let state = self
            .state
            .read()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let compressed = state
            .objects
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

        let mut state = self
            .state
            .write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        state.refs.insert(name.to_string(), value);
        state.root_hash = None;

        Ok(())
    }

    /// Delete a ref
    pub fn delete_ref(&self, name: &str) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
        let deleted = state.refs.remove(name).is_some();
        state.root_hash = None;
        Ok(deleted)
    }

    /// Resolve a ref to its final object ID (follows symbolic refs)
    fn resolve_ref(&self, name: &str) -> Result<ObjectId> {
        let mut current = name.to_string();
        let mut depth = 0;
        const MAX_DEPTH: usize = 10;

        loop {
            if depth >= MAX_DEPTH {
                return Err(Error::RefNotFound(format!(
                    "too many levels of symbolic refs: {}",
                    name
                )));
            }
            depth += 1;

            let state = self
                .state
                .read()
                .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            let value = state
                .refs
                .get(&current)
                .ok_or_else(|| Error::RefNotFound(current.clone()))?
                .clone();
            drop(state);

            if let Some(target) = value.strip_prefix("ref: ") {
                current = target.to_string();
            } else {
                return ObjectId::from_hex(&value)
                    .ok_or_else(|| Error::InvalidObjectFormat("invalid oid in ref".into()));
            }
        }
    }

    /// Build the merkle tree and return root hash (SHA-256)
    fn build_tree(&mut self) -> Result<[u8; 32]> {
        {
            let state = self
                .state
                .read()
                .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            if let Some(hash) = state.root_hash {
                return Ok(hash);
            }
        }

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
            let state = self
                .state
                .read()
                .map_err(|e| Error::StorageError(format!("lock: {}", e)))?;
            (state.objects.clone(), state.refs.clone())
        };
        let store = self.store.clone();

        let tree = HashTree::new(HashTreeConfig::new(store.clone()).public());

        let root_hash = self.runtime.block_on(async {
            let git_dir_hash =
                build_git_dir(&tree, &store, &objects, &refs, &default_branch).await?;

            let mut root_entries = vec![DirEntry::new(".git", git_dir_hash)];

            if let Some(wt) = working_tree {
                let wt_entries = build_working_tree(&tree, wt).await?;
                root_entries.extend(wt_entries);
            }

            let root_cid = tree
                .put_directory(root_entries)
                .await
                .map_err(|e| Error::StorageError(format!("build tree: {}", e)))?;

            Ok::<[u8; 32], Error>(root_cid.hash)
        })?;

        self.state
            .write()
            .map_err(|e| Error::StorageError(format!("lock: {}", e)))?
            .root_hash = Some(root_hash);
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
    fn determine_default_branch(&self) -> Option<String> {
        let state = self.state.read().ok()?;

        let branches: Vec<&String> = state
            .refs
            .keys()
            .filter(|k| k.starts_with("refs/heads/"))
            .collect();

        if branches.is_empty() {
            return None;
        }

        if branches.iter().any(|b| *b == "refs/heads/master") {
            return Some("refs/heads/master".to_string());
        }

        if branches.iter().any(|b| *b == "refs/heads/main") {
            return Some("refs/heads/main".to_string());
        }

        let mut sorted: Vec<_> = branches.into_iter().collect();
        sorted.sort();
        sorted.first().map(|s| (*s).clone())
    }

    /// Extract the working tree from a commit
    fn extract_working_tree(&self, commit_oid: &ObjectId) -> Result<Vec<WorkingTreeEntry>> {
        let commit_obj = self.read_object(commit_oid)?;
        if commit_obj.obj_type != ObjectType::Commit {
            return Err(Error::InvalidObjectFormat("expected commit".into()));
        }

        let commit_content = String::from_utf8_lossy(&commit_obj.content);
        let tree_line = commit_content
            .lines()
            .find(|l| l.starts_with("tree "))
            .ok_or_else(|| Error::InvalidObjectFormat("commit missing tree".into()))?;

        let tree_hex = tree_line.strip_prefix("tree ").unwrap().trim();
        let tree_oid = ObjectId::from_hex(tree_hex)
            .ok_or_else(|| Error::InvalidObjectFormat("invalid tree oid".into()))?;

        let mut entries = Vec::new();
        self.extract_tree_recursive(&tree_oid, "", &mut entries)?;
        Ok(entries)
    }

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
                self.extract_tree_recursive(&entry.oid, &path, entries)?;
            } else {
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
}

// === Helper functions for building hashtree ===

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

    tree.put_directory(entries)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put objects dir: {}", e)))
}

async fn build_refs_dir<S: Store>(
    tree: &HashTree<S>,
    store: &Arc<S>,
    refs: &HashMap<String, String>,
) -> Result<[u8; 32]> {
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
        }
    }

    let mut ref_entries = Vec::new();

    for (category, refs_in_category) in groups {
        let mut cat_entries = Vec::new();
        for (name, value) in refs_in_category {
            let hash = tree
                .put_blob(value.as_bytes())
                .await
                .map_err(|e| Error::StorageError(format!("put ref: {}", e)))?;
            cat_entries.push(DirEntry::new(name, hash).with_size(value.len() as u64));
        }
        let cat_cid = tree
            .put_directory(cat_entries)
            .await
            .map_err(|e| Error::StorageError(format!("put {} dir: {}", category, e)))?;
        ref_entries.push(DirEntry::new(category, cat_cid.hash));
    }

    if ref_entries.is_empty() {
        let hash = sha256(b"");
        store
            .put(hash, vec![])
            .await
            .map_err(|e| Error::StorageError(format!("put empty refs: {}", e)))?;
        return Ok(hash);
    }

    tree.put_directory(ref_entries)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put refs dir: {}", e)))
}

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

    if let Some(branch) = default_branch {
        let head_content = format!("ref: {}", branch);
        let head_hash = tree
            .put_blob(head_content.as_bytes())
            .await
            .map_err(|e| Error::StorageError(format!("put HEAD: {}", e)))?;
        git_entries.push(DirEntry::new("HEAD", head_hash).with_size(head_content.len() as u64));
    }

    tree.put_directory(git_entries)
        .await
        .map(|cid| cid.hash)
        .map_err(|e| Error::StorageError(format!("put .git dir: {}", e)))
}

async fn build_working_tree<S: Store>(
    tree: &HashTree<S>,
    entries: Vec<WorkingTreeEntry>,
) -> Result<Vec<DirEntry>> {
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

    for file in root_files {
        let hash = tree
            .put_blob(&file.content)
            .await
            .map_err(|e| Error::StorageError(format!("put file {}: {}", file.path, e)))?;
        result.push(DirEntry::new(file.path, hash).with_size(file.content.len() as u64));
    }

    for (dir_name, sub_entries) in dirs {
        let sub_dir_entries = build_working_tree_recursive(tree, sub_entries).await?;
        let dir_cid = tree
            .put_directory(sub_dir_entries)
            .await
            .map_err(|e| Error::StorageError(format!("put dir {}: {}", dir_name, e)))?;
        result.push(DirEntry::new(dir_name, dir_cid.hash));
    }

    Ok(result)
}

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

    for file in files {
        let hash = tree
            .put_blob(&file.content)
            .await
            .map_err(|e| Error::StorageError(format!("put file {}: {}", file.path, e)))?;
        result.push(DirEntry::new(file.path, hash).with_size(file.content.len() as u64));
    }

    for (dir_name, sub_entries) in dirs {
        let sub_dir_entries = Box::pin(build_working_tree_recursive(tree, sub_entries)).await?;
        let dir_cid = tree
            .put_directory(sub_dir_entries)
            .await
            .map_err(|e| Error::StorageError(format!("put dir {}: {}", dir_name, e)))?;
        result.push(DirEntry::new(dir_name, dir_cid.hash));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::object::{serialize_tree, TreeEntry};
    use tempfile::tempdir;

    #[test]
    fn test_object_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let content = b"Hello, World!";
        let obj = GitObject::new(ObjectType::Blob, content.to_vec());
        let oid = storage.write_object(&obj).unwrap();

        let read_obj = storage.read_object(&oid).unwrap();
        assert_eq!(read_obj.obj_type, ObjectType::Blob);
        assert_eq!(read_obj.content, content);
    }

    #[test]
    fn test_ref_operations() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let obj = GitObject::new(ObjectType::Blob, b"test".to_vec());
        let oid = storage.write_object(&obj).unwrap();

        storage
            .write_ref("refs/heads/main", &Ref::Direct(oid.clone()))
            .unwrap();

        let resolved = storage.resolve_ref("refs/heads/main").unwrap();
        assert_eq!(resolved.to_hex(), oid.to_hex());

        let deleted = storage.delete_ref("refs/heads/main").unwrap();
        assert!(deleted);
    }

    #[test]
    fn test_build_tree() {
        let dir = tempdir().unwrap();
        let mut storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create a simple blob
        let blob = GitObject::new(ObjectType::Blob, b"# README\n".to_vec());
        let blob_oid = storage.write_object(&blob).unwrap();

        // Create tree with blob
        let tree_content = serialize_tree(&[TreeEntry::new(
            0o100644,
            "README.md".to_string(),
            blob_oid.clone(),
        )]);
        let tree = GitObject::new(ObjectType::Tree, tree_content);
        let tree_oid = storage.write_object(&tree).unwrap();

        // Create commit
        let commit_content = format!(
            "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial commit\n",
            tree_oid.to_hex()
        );
        let commit = GitObject::new(ObjectType::Commit, commit_content.into_bytes());
        let commit_oid = storage.write_object(&commit).unwrap();

        // Create ref
        storage
            .write_ref("refs/heads/main", &Ref::Direct(commit_oid))
            .unwrap();

        // Build tree and get root hash
        let root_hash = storage.get_root_hash().unwrap();
        assert_eq!(root_hash.len(), 64); // SHA-256 hex
    }
}
