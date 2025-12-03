//! HashTree - Simple content-addressed merkle tree
//!
//! Core principle: Every node is stored by SHA256(CBOR(node)) -> CBOR(node)
//! This enables pure KV content-addressed storage.

use std::collections::HashMap;

/// 32-byte SHA256 hash used as content address
pub type Hash = [u8; 32];

/// Convert hash to hex string
pub fn to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Convert hex string to hash
pub fn from_hex(hex_str: &str) -> Result<Hash, hex::FromHexError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Compare two hashes for equality
pub fn hash_equals(a: &Hash, b: &Hash) -> bool {
    a == b
}

/// A link to a child node with optional metadata
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    /// SHA256 hash of the child node's CBOR encoding
    pub hash: Hash,
    /// Optional name (for directory entries)
    pub name: Option<String>,
    /// Size of subtree in bytes (for efficient seeks)
    pub size: Option<u64>,
    /// Optional decryption key for encrypted links (CHK: content hash)
    pub key: Option<[u8; 32]>,
}

impl Link {
    pub fn new(hash: Hash) -> Self {
        Self {
            hash,
            name: None,
            size: None,
            key: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_key(mut self, key: [u8; 32]) -> Self {
        self.key = Some(key);
        self
    }
}

/// Tree node - contains links to children
/// Stored as: SHA256(CBOR(TreeNode)) -> CBOR(TreeNode)
///
/// For directories: links have names
/// For chunked files: links are ordered chunks
/// For large directories: links can be other tree nodes (fanout)
#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    /// Links to child nodes
    pub links: Vec<Link>,
    /// Total size of all data in this subtree
    pub total_size: Option<u64>,
    /// Optional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl TreeNode {
    pub fn new(links: Vec<Link>) -> Self {
        Self {
            links,
            total_size: None,
            metadata: None,
        }
    }

    pub fn with_total_size(mut self, size: u64) -> Self {
        self.total_size = Some(size);
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Result of adding content to the tree
#[derive(Debug, Clone, PartialEq)]
pub struct PutResult {
    /// Hash of the stored node
    pub hash: Hash,
    /// Size of the stored data
    pub size: u64,
}

/// Directory entry for building directory trees
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub hash: Hash,
    pub size: Option<u64>,
}

impl DirEntry {
    pub fn new(name: impl Into<String>, hash: Hash) -> Self {
        Self {
            name: name.into(),
            hash,
            size: None,
        }
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex_empty() {
        let hash = [0u8; 32];
        let hex = to_hex(&hash);
        assert_eq!(hex, "0000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_to_hex_bytes() {
        let mut hash = [0u8; 32];
        hash[0] = 0x00;
        hash[1] = 0xff;
        hash[2] = 0x10;
        let hex = to_hex(&hash);
        assert!(hex.starts_with("00ff10"));
    }

    #[test]
    fn test_from_hex() {
        let hex = "00ff100000000000000000000000000000000000000000000000000000000000";
        let hash = from_hex(hex).unwrap();
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[1], 0xff);
        assert_eq!(hash[2], 0x10);
    }

    #[test]
    fn test_roundtrip() {
        let mut original = [0u8; 32];
        original[0] = 0;
        original[1] = 1;
        original[2] = 127;
        original[3] = 128;
        original[4] = 255;

        let hex = to_hex(&original);
        let result = from_hex(&hex).unwrap();
        assert_eq!(result, original);
    }
}
