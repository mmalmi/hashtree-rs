//! Encrypted file operations for HashTree
//!
//! Two modes:
//! - Small files (single chunk): CHK encryption - same content = same ciphertext (dedup works)
//! - Large files (multi-chunk): Random key - tree nodes encrypted, no chunk-level dedup
//!
//! The root decryption key must be stored/shared to access the file.

use std::sync::Arc;

use crate::codec::{decode_tree_node, encode_and_hash, is_tree_node};
use crate::crypto::{decrypt, decrypt_chk, encrypt, encrypt_chk, generate_key, CryptoError, EncryptionKey};
use crate::hash::sha256;
use crate::store::Store;
use crate::types::{Hash, Link, TreeNode};

/// Encrypted tree configuration
pub struct EncryptedTreeConfig<S: Store> {
    pub store: Arc<S>,
    pub chunk_size: usize,
    pub max_links: usize,
}

/// Result of encrypted file storage
pub struct EncryptedPutResult {
    /// Root hash of encrypted tree
    pub hash: Hash,
    /// Original plaintext size
    pub size: u64,
    /// Encryption key used
    pub key: EncryptionKey,
}

/// Error type for encrypted operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptedError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Store error: {0}")]
    Store(String),
    #[error("Codec error: {0}")]
    Codec(#[from] crate::codec::CodecError),
    #[error("Missing chunk: {0}")]
    MissingChunk(String),
}

/// Store a file with encryption
///
/// - Small files (≤ chunk_size): CHK encryption - same content = same ciphertext
/// - Large files: Random key encryption for all chunks and tree nodes
pub async fn put_file_encrypted<S: Store>(
    config: &EncryptedTreeConfig<S>,
    data: &[u8],
    key: Option<EncryptionKey>,
) -> Result<EncryptedPutResult, EncryptedError> {
    let size = data.len() as u64;

    if data.len() <= config.chunk_size {
        // Small file - use CHK for deduplication
        let (encrypted, content_key) = encrypt_chk(data)?;
        let hash = sha256(&encrypted);
        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;
        return Ok(EncryptedPutResult {
            hash,
            size,
            key: content_key, // Content hash is the decryption key
        });
    }

    // Large file - use random key (no chunk-level dedup)
    let enc_key = key.unwrap_or_else(generate_key);

    // Split into chunks
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + config.chunk_size).min(data.len());
        chunks.push(&data[offset..end]);
        offset = end;
    }

    // Encrypt and store chunks with random key
    let mut links = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let encrypted = encrypt(chunk, &enc_key)?;
        let hash = sha256(&encrypted);
        let enc_size = encrypted.len() as u64;
        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;
        links.push(Link {
            hash,
            name: None,
            size: Some(enc_size),
        });
    }

    // Build tree with same key
    let root_hash = build_encrypted_tree(config, links, Some(size), &enc_key).await?;

    Ok(EncryptedPutResult {
        hash: root_hash,
        size,
        key: enc_key,
    })
}

/// Build tree structure with encrypted tree nodes
async fn build_encrypted_tree<S: Store>(
    config: &EncryptedTreeConfig<S>,
    links: Vec<Link>,
    total_size: Option<u64>,
    key: &EncryptionKey,
) -> Result<Hash, EncryptedError> {
    if links.len() == 1 {
        if let Some(ts) = total_size {
            if links[0].size == Some(ts) {
                return Ok(links[0].hash);
            }
        }
    }

    if links.len() <= config.max_links {
        let node = TreeNode {
            links,
            total_size,
            metadata: None,
        };
        let (data, _) = encode_and_hash(&node)?;
        // Encrypt the tree node
        let encrypted = encrypt(&data, key)?;
        let hash = sha256(&encrypted);
        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;
        return Ok(hash);
    }

    // Too many links - create subtrees
    let mut sub_trees = Vec::new();
    for batch in links.chunks(config.max_links) {
        let batch_size: u64 = batch.iter().filter_map(|l| l.size).sum();

        let node = TreeNode {
            links: batch.to_vec(),
            total_size: Some(batch_size),
            metadata: None,
        };
        let (data, _) = encode_and_hash(&node)?;
        // Encrypt the subtree node
        let encrypted = encrypt(&data, key)?;
        let hash = sha256(&encrypted);
        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;

        sub_trees.push(Link {
            hash,
            name: None,
            size: Some(batch_size),
        });
    }

    Box::pin(build_encrypted_tree(config, sub_trees, total_size, key)).await
}

/// Read an encrypted file
///
/// Tries CHK decryption first (for small files), falls back to regular decryption.
pub async fn read_file_encrypted<S: Store>(
    store: &S,
    hash: &Hash,
    key: &EncryptionKey,
) -> Result<Option<Vec<u8>>, EncryptedError> {
    let encrypted_data = match store.get(hash).await {
        Ok(Some(data)) => data,
        Ok(None) => return Ok(None),
        Err(e) => return Err(EncryptedError::Store(e.to_string())),
    };

    // Try CHK decryption first (for small files)
    if let Ok(decrypted) = decrypt_chk(&encrypted_data, key) {
        // Verify it's not a tree node (CHK is only for leaf data)
        if !is_tree_node(&decrypted) {
            return Ok(Some(decrypted));
        }
    }

    // Fall back to regular decryption (for large files with tree structure)
    let decrypted = decrypt(&encrypted_data, key)?;

    // Check if decrypted data is a tree node
    if is_tree_node(&decrypted) {
        let node = decode_tree_node(&decrypted)?;
        let result = assemble_encrypted_chunks(store, &node, key).await?;
        return Ok(Some(result));
    }

    // Single blob
    Ok(Some(decrypted))
}

/// Assemble chunks from an encrypted tree
async fn assemble_encrypted_chunks<S: Store>(
    store: &S,
    node: &TreeNode,
    key: &EncryptionKey,
) -> Result<Vec<u8>, EncryptedError> {
    let mut parts = Vec::new();

    for link in &node.links {
        let encrypted_child = store
            .get(&link.hash)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?
            .ok_or_else(|| EncryptedError::MissingChunk(crate::to_hex(&link.hash)))?;

        // Decrypt the child
        let decrypted = decrypt(&encrypted_child, key)?;

        if is_tree_node(&decrypted) {
            // Intermediate tree node
            let child_node = decode_tree_node(&decrypted)?;
            let child_data = Box::pin(assemble_encrypted_chunks(store, &child_node, key)).await?;
            parts.push(child_data);
        } else {
            // Leaf data chunk
            parts.push(decrypted);
        }
    }

    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for part in parts {
        result.extend_from_slice(&part);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn make_config(chunk_size: usize) -> EncryptedTreeConfig<MemoryStore> {
        EncryptedTreeConfig {
            store: Arc::new(MemoryStore::new()),
            chunk_size,
            max_links: 174,
        }
    }

    #[tokio::test]
    async fn test_small_file_encrypted() {
        let config = make_config(256 * 1024);
        let data = b"Hello, encrypted world!";

        let result = put_file_encrypted(&config, data, None).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &result.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_chunked_file_encrypted() {
        let config = make_config(1024); // Small chunks
        let data = vec![0u8; 5000]; // Multiple chunks

        let result = put_file_encrypted(&config, &data, None).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &result.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_wrong_key_fails() {
        let config = make_config(256 * 1024);
        let data = b"Secret data";

        let result = put_file_encrypted(&config, data, None).await.unwrap();

        let wrong_key = generate_key();
        let decrypt_result =
            read_file_encrypted(config.store.as_ref(), &result.hash, &wrong_key).await;
        assert!(decrypt_result.is_err());
    }

    #[tokio::test]
    async fn test_provided_key() {
        // Use small chunk size to test multi-chunk path (which uses provided key)
        let config = make_config(10);
        let data = b"Data with custom key that is longer than chunk size";
        let key = generate_key();

        let result = put_file_encrypted(&config, data, Some(key)).await.unwrap();
        assert_eq!(result.key, key);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_small_file_chk_dedup() {
        let config = make_config(256 * 1024);
        let data = b"Same content for dedup test";

        // Encrypt same data twice
        let result1 = put_file_encrypted(&config, data, None).await.unwrap();
        let result2 = put_file_encrypted(&config, data, None).await.unwrap();

        // CHK: same content = same hash and same key
        assert_eq!(result1.hash, result2.hash);
        assert_eq!(result1.key, result2.key);
    }

    #[tokio::test]
    async fn test_empty_file() {
        let config = make_config(256 * 1024);
        let data = b"";

        let result = put_file_encrypted(&config, data, None).await.unwrap();
        assert_eq!(result.size, 0);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &result.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_large_file_many_chunks() {
        let config = make_config(1024);
        // Create data that needs multiple tree levels
        let data = vec![42u8; 1024 * 200]; // 200 chunks

        let result = put_file_encrypted(&config, &data, None).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &result.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }
}
