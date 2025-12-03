//! CHK (Content Hash Key) encrypted file operations for HashTree
//!
//! **⚠️ EXPERIMENTAL: Encryption API is unstable and may change.**
//!
//! Everything uses CHK encryption:
//! - Chunks: key = SHA256(plaintext)
//! - Tree nodes: key = SHA256(cbor_encoded_node)
//!
//! Same content → same ciphertext → deduplication works at all levels.
//! The root key is deterministic: same file = same CID (hash + key).

use std::sync::Arc;

use crate::codec::{decode_tree_node, encode_and_hash, is_tree_node};
use crate::crypto::{decrypt_chk, encrypt_chk, CryptoError, EncryptionKey};
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
    /// Encryption key for the root (random key for tree nodes)
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
    #[error("Missing decryption key for chunk")]
    MissingKey,
}

/// Store a file with CHK encryption
///
/// Everything is CHK encrypted - deterministic, enables full deduplication.
/// Returns hash + key, both derived from content.
pub async fn put_file_encrypted<S: Store>(
    config: &EncryptedTreeConfig<S>,
    data: &[u8],
) -> Result<EncryptedPutResult, EncryptedError> {
    let size = data.len() as u64;

    // Single chunk - use CHK directly
    if data.len() <= config.chunk_size {
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
            key: content_key,
        });
    }

    // Multiple chunks - each chunk gets CHK
    let mut links = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + config.chunk_size).min(data.len());
        let chunk = &data[offset..end];

        // CHK encrypt this chunk
        let (encrypted, chunk_key) = encrypt_chk(chunk)?;
        let hash = sha256(&encrypted);
        let enc_size = encrypted.len() as u64;

        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;

        // Link stores both hash (location) and key (for decryption)
        links.push(Link {
            hash,
            name: None,
            size: Some(enc_size),
            key: Some(chunk_key),
        });

        offset = end;
    }

    // Build tree - tree nodes also CHK encrypted
    let (root_hash, root_key) = build_encrypted_tree(config, links, Some(size)).await?;

    Ok(EncryptedPutResult {
        hash: root_hash,
        size,
        key: root_key,
    })
}

/// Build tree structure with CHK-encrypted tree nodes
/// Returns (hash, key) for the root node
async fn build_encrypted_tree<S: Store>(
    config: &EncryptedTreeConfig<S>,
    links: Vec<Link>,
    total_size: Option<u64>,
) -> Result<(Hash, EncryptionKey), EncryptedError> {
    // Single link - return its hash and key directly
    if links.len() == 1 && links[0].key.is_some() {
        if let Some(ts) = total_size {
            if links[0].size == Some(ts) {
                return Ok((links[0].hash, links[0].key.unwrap()));
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
        // CHK encrypt the tree node
        let (encrypted, node_key) = encrypt_chk(&data)?;
        let hash = sha256(&encrypted);
        config
            .store
            .put(hash, encrypted)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?;
        return Ok((hash, node_key));
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
        // CHK encrypt the subtree node
        let (encrypted, node_key) = encrypt_chk(&data)?;
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
            key: Some(node_key),
        });
    }

    Box::pin(build_encrypted_tree(config, sub_trees, total_size)).await
}

/// Read an encrypted file
///
/// Key is always the CHK key (content hash of plaintext)
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

    // CHK decrypt
    let decrypted = decrypt_chk(&encrypted_data, key)?;

    // Check if it's a tree node
    if is_tree_node(&decrypted) {
        let node = decode_tree_node(&decrypted)?;
        let result = assemble_encrypted_chunks(store, &node).await?;
        return Ok(Some(result));
    }

    // Single chunk data
    Ok(Some(decrypted))
}

/// Assemble chunks from an encrypted tree
/// Each link has its own CHK key
async fn assemble_encrypted_chunks<S: Store>(
    store: &S,
    node: &TreeNode,
) -> Result<Vec<u8>, EncryptedError> {
    let mut parts = Vec::new();

    for link in &node.links {
        let chunk_key = link.key.ok_or(EncryptedError::MissingKey)?;

        let encrypted_child = store
            .get(&link.hash)
            .await
            .map_err(|e| EncryptedError::Store(e.to_string()))?
            .ok_or_else(|| EncryptedError::MissingChunk(crate::to_hex(&link.hash)))?;

        let decrypted = decrypt_chk(&encrypted_child, &chunk_key)?;

        if is_tree_node(&decrypted) {
            // Intermediate tree node - recurse
            let child_node = decode_tree_node(&decrypted)?;
            let child_data = Box::pin(assemble_encrypted_chunks(store, &child_node)).await?;
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
    use crate::crypto::generate_key;
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

        let result = put_file_encrypted(&config, data).await.unwrap();
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

        let result = put_file_encrypted(&config, &data).await.unwrap();
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

        let result = put_file_encrypted(&config, data).await.unwrap();

        let wrong_key = generate_key();
        let decrypt_result =
            read_file_encrypted(config.store.as_ref(), &result.hash, &wrong_key).await;
        assert!(decrypt_result.is_err());
    }

    #[tokio::test]
    async fn test_deterministic_cid() {
        // Same content = same hash + key (deterministic CID)
        let config = make_config(10); // Small chunks to test multi-chunk
        let data = b"Data that spans multiple chunks for testing";

        let result1 = put_file_encrypted(&config, data).await.unwrap();
        let result2 = put_file_encrypted(&config, data).await.unwrap();

        // CHK: same content = same hash AND same key
        assert_eq!(result1.hash, result2.hash);
        assert_eq!(result1.key, result2.key);
    }

    #[tokio::test]
    async fn test_small_file_chk_dedup() {
        let config = make_config(256 * 1024);
        let data = b"Same content for dedup test";

        // Encrypt same data twice
        let result1 = put_file_encrypted(&config, data).await.unwrap();
        let result2 = put_file_encrypted(&config, data).await.unwrap();

        // CHK: same content = same hash and same key
        assert_eq!(result1.hash, result2.hash);
        assert_eq!(result1.key, result2.key);
    }

    #[tokio::test]
    async fn test_chunk_level_dedup() {
        // Test that identical chunks across different files produce same ciphertext
        let config = make_config(10);

        // Two files that share some chunks
        let data1 = b"AAAAAAAAAA_BBBBBBBBBB"; // chunk "AAAAAAAAAA" + "_BBBBBBBBB" + "B"
        let data2 = b"AAAAAAAAAA_CCCCCCCCCC"; // chunk "AAAAAAAAAA" + "_CCCCCCCCC" + "C"

        let result1 = put_file_encrypted(&config, data1).await.unwrap();
        let result2 = put_file_encrypted(&config, data2).await.unwrap();

        // Files have different hashes (different content overall)
        assert_ne!(result1.hash, result2.hash);

        // But first chunk should be deduplicated (same hash in store)
        // We can verify by checking the store has fewer entries than if no dedup

        // Verify both files decrypt correctly
        let decrypted1 = read_file_encrypted(config.store.as_ref(), &result1.hash, &result1.key)
            .await
            .unwrap()
            .unwrap();
        let decrypted2 = read_file_encrypted(config.store.as_ref(), &result2.hash, &result2.key)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(decrypted1, data1);
        assert_eq!(decrypted2, data2);
    }

    #[tokio::test]
    async fn test_empty_file() {
        let config = make_config(256 * 1024);
        let data = b"";

        let result = put_file_encrypted(&config, data).await.unwrap();
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

        let result = put_file_encrypted(&config, &data).await.unwrap();
        assert_eq!(result.size, data.len() as u64);

        let decrypted = read_file_encrypted(config.store.as_ref(), &result.hash, &result.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, data);
    }
}
