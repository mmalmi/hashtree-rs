//! Filesystem-based content-addressed blob storage.
//!
//! Stores blobs in a directory structure similar to git:
//! `{base_path}/{first 2 chars of hash}/{remaining hash chars}`
//!
//! For example, a blob with hash `abcdef123...` would be stored at:
//! `~/.hashtree/blobs/ab/cdef123...`

use async_trait::async_trait;
use hashtree_core::store::{Store, StoreError};
use hashtree_core::types::Hash;
use std::fs;
use std::path::{Path, PathBuf};

/// Filesystem-backed blob store implementing hashtree's Store trait.
///
/// Stores blobs in a 256-way sharded directory structure using
/// the first 2 hex characters of the hash as the directory prefix.
pub struct FsBlobStore {
    base_path: PathBuf,
}

impl FsBlobStore {
    /// Create a new filesystem blob store at the given path.
    ///
    /// Creates the directory if it doesn't exist.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let base_path = path.as_ref().to_path_buf();
        fs::create_dir_all(&base_path)?;
        Ok(Self { base_path })
    }

    /// Get the file path for a given hash.
    ///
    /// Format: `{base_path}/{first 2 hex chars}/{remaining 62 hex chars}`
    fn blob_path(&self, hash: &Hash) -> PathBuf {
        let hex = hex::encode(hash);
        let (prefix, rest) = hex.split_at(2);
        self.base_path.join(prefix).join(rest)
    }

    /// Sync put operation.
    pub fn put_sync(&self, hash: Hash, data: &[u8]) -> Result<bool, StoreError> {
        let path = self.blob_path(&hash);

        // Check if already exists
        if path.exists() {
            return Ok(false);
        }

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write atomically using temp file + rename
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, data)?;
        fs::rename(&temp_path, &path)?;

        Ok(true)
    }

    /// Sync get operation.
    pub fn get_sync(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.blob_path(hash);
        if path.exists() {
            Ok(Some(fs::read(&path)?))
        } else {
            Ok(None)
        }
    }

    /// Check if a hash exists.
    pub fn exists(&self, hash: &Hash) -> bool {
        self.blob_path(hash).exists()
    }

    /// Sync delete operation.
    pub fn delete_sync(&self, hash: &Hash) -> Result<bool, StoreError> {
        let path = self.blob_path(hash);
        if path.exists() {
            fs::remove_file(&path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all hashes in the store.
    pub fn list(&self) -> Result<Vec<Hash>, StoreError> {
        let mut hashes = Vec::new();

        // Iterate over prefix directories (00-ff)
        let entries = match fs::read_dir(&self.base_path) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(hashes),
            Err(e) => return Err(e.into()),
        };

        for prefix_entry in entries {
            let prefix_entry = prefix_entry?;
            let prefix_path = prefix_entry.path();

            if !prefix_path.is_dir() {
                continue;
            }

            let prefix = match prefix_path.file_name().and_then(|n| n.to_str()) {
                Some(p) if p.len() == 2 => p.to_string(),
                _ => continue,
            };

            // Iterate over blobs in this prefix directory
            for blob_entry in fs::read_dir(&prefix_path)? {
                let blob_entry = blob_entry?;
                let rest = match blob_entry.file_name().to_str() {
                    Some(r) if r.len() == 62 => r.to_string(),
                    _ => continue,
                };

                // Reconstruct full hash hex
                let full_hex = format!("{}{}", prefix, rest);
                if let Ok(bytes) = hex::decode(&full_hex) {
                    if bytes.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&bytes);
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }

    /// Get storage statistics.
    pub fn stats(&self) -> Result<FsStats, StoreError> {
        let mut count = 0usize;
        let mut total_bytes = 0u64;

        let entries = match fs::read_dir(&self.base_path) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FsStats { count, total_bytes })
            }
            Err(e) => return Err(e.into()),
        };

        for prefix_entry in entries {
            let prefix_entry = prefix_entry?;
            let prefix_path = prefix_entry.path();

            if !prefix_path.is_dir() {
                continue;
            }

            for blob_entry in fs::read_dir(&prefix_path)? {
                let blob_entry = blob_entry?;
                if blob_entry.path().is_file() {
                    count += 1;
                    total_bytes += blob_entry.metadata()?.len();
                }
            }
        }

        Ok(FsStats { count, total_bytes })
    }
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct FsStats {
    pub count: usize,
    pub total_bytes: u64,
}

#[async_trait]
impl Store for FsBlobStore {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        self.put_sync(hash, &data)
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_sync(hash)
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self.exists(hash))
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.delete_sync(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashtree_core::sha256;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_put_get() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let data = b"hello filesystem";
        let hash = sha256(data);
        store.put(hash, data.to_vec()).await.unwrap();

        assert!(store.has(&hash).await.unwrap());
        assert_eq!(store.get(&hash).await.unwrap(), Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_get_missing() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let hash = [0u8; 32];
        assert!(!store.has(&hash).await.unwrap());
        assert_eq!(store.get(&hash).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_delete() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let data = b"delete me";
        let hash = sha256(data);
        store.put(hash, data.to_vec()).await.unwrap();
        assert!(store.has(&hash).await.unwrap());

        assert!(store.delete(&hash).await.unwrap());
        assert!(!store.has(&hash).await.unwrap());
        assert!(!store.delete(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_deduplication() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let data = b"same content";
        let hash = sha256(data);

        // First put returns true (newly stored)
        assert!(store.put(hash, data.to_vec()).await.unwrap());
        // Second put returns false (already existed)
        assert!(!store.put(hash, data.to_vec()).await.unwrap());

        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let d1 = b"one";
        let d2 = b"two";
        let d3 = b"three";
        let h1 = sha256(d1);
        let h2 = sha256(d2);
        let h3 = sha256(d3);

        store.put(h1, d1.to_vec()).await.unwrap();
        store.put(h2, d2.to_vec()).await.unwrap();
        store.put(h3, d3.to_vec()).await.unwrap();

        let hashes = store.list().unwrap();
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&h1));
        assert!(hashes.contains(&h2));
        assert!(hashes.contains(&h3));
    }

    #[tokio::test]
    async fn test_stats() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let d1 = b"hello";
        let d2 = b"world";
        store.put(sha256(d1), d1.to_vec()).await.unwrap();
        store.put(sha256(d2), d2.to_vec()).await.unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.total_bytes, 10);
    }

    #[tokio::test]
    async fn test_directory_structure() {
        let temp = TempDir::new().unwrap();
        let blobs_path = temp.path().join("blobs");
        let store = FsBlobStore::new(&blobs_path).unwrap();

        let data = b"test data";
        let hash = sha256(data);
        let hex = hex::encode(hash);

        store.put(hash, data.to_vec()).await.unwrap();

        // Verify the file exists at the correct path
        let prefix = &hex[..2];
        let rest = &hex[2..];
        let expected_path = blobs_path.join(prefix).join(rest);

        assert!(expected_path.exists(), "Blob should be at {:?}", expected_path);
        assert_eq!(fs::read(&expected_path).unwrap(), data);
    }

    #[test]
    fn test_blob_path_format() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path()).unwrap();

        // Hash: 0x00112233...
        let mut hash = [0u8; 32];
        hash[0] = 0x00;
        hash[1] = 0x11;
        hash[2] = 0x22;

        let path = store.blob_path(&hash);
        let path_str = path.to_string_lossy();

        // Should have "00" as directory prefix
        assert!(path_str.contains("/00/"), "Path should contain /00/ directory: {}", path_str);
        // File name should be remaining 62 chars
        assert!(path.file_name().unwrap().len() == 62);
    }

    #[tokio::test]
    async fn test_empty_store_stats() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_empty_store_list() {
        let temp = TempDir::new().unwrap();
        let store = FsBlobStore::new(temp.path().join("blobs")).unwrap();

        let hashes = store.list().unwrap();
        assert!(hashes.is_empty());
    }
}
