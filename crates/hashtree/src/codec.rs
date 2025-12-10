//! MessagePack encoding/decoding for tree nodes
//!
//! Blobs are stored raw (not wrapped) for efficiency.
//! Tree nodes are MessagePack-encoded.
//!
//! **Determinism:** Unlike CBOR, MessagePack doesn't have a built-in canonical encoding.
//! We ensure deterministic output by:
//! 1. Using fixed struct field order (Rust declaration order via serde)
//! 2. Converting HashMap metadata to BTreeMap before encoding (sorted keys)
//!
//! Format uses short keys for compact encoding:
//! - t: type (1 = tree)
//! - l: links array
//! - h: hash (in link)
//! - n: name (in link, optional)
//! - s: size (in link or total_size, optional)
//! - m: metadata (optional)

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::hash::sha256;
use crate::types::{Hash, Link, TreeNode};

/// Error type for codec operations
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("Invalid node type: {0}")]
    InvalidNodeType(u8),
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid field type for {0}")]
    InvalidFieldType(&'static str),
    #[error("MessagePack encoding error: {0}")]
    MsgpackEncode(String),
    #[error("MessagePack decoding error: {0}")]
    MsgpackDecode(String),
    #[error("Invalid hash length: expected 32, got {0}")]
    InvalidHashLength(usize),
}

/// Wire format for a link (compact keys)
#[derive(Serialize, Deserialize)]
struct WireLink {
    /// Hash (required) - use serde_bytes for proper MessagePack binary encoding
    #[serde(with = "serde_bytes")]
    h: Vec<u8>,
    /// Name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    /// Size (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<u64>,
    /// Encryption key (optional) - use serde_bytes for proper MessagePack binary encoding
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    k: Option<Vec<u8>>,
}

/// Helper module for optional bytes serialization
mod option_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|bb| bb.into_vec()))
    }
}

/// Wire format for a tree node (compact keys)
#[derive(Serialize, Deserialize)]
struct WireTreeNode {
    /// Type (1 = tree)
    t: u8,
    /// Links
    l: Vec<WireLink>,
    /// Total size (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<u64>,
    /// Metadata (optional) - uses BTreeMap for deterministic key ordering
    #[serde(skip_serializing_if = "Option::is_none")]
    m: Option<BTreeMap<String, serde_json::Value>>,
}

/// Encode a tree node to MessagePack
pub fn encode_tree_node(node: &TreeNode) -> Result<Vec<u8>, CodecError> {
    // Convert HashMap to BTreeMap for deterministic key ordering
    let sorted_metadata = node.metadata.as_ref().map(|m| m.iter().collect::<BTreeMap<_, _>>());

    let wire = WireTreeNode {
        t: 1,
        l: node
            .links
            .iter()
            .map(|link| WireLink {
                h: link.hash.to_vec(),
                n: link.name.clone(),
                s: link.size,
                k: link.key.map(|k| k.to_vec()),
            })
            .collect(),
        s: node.total_size,
        m: sorted_metadata.map(|m| m.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
    };

    rmp_serde::to_vec_named(&wire).map_err(|e| CodecError::MsgpackEncode(e.to_string()))
}

/// Decode MessagePack to a tree node
pub fn decode_tree_node(data: &[u8]) -> Result<TreeNode, CodecError> {
    let wire: WireTreeNode =
        rmp_serde::from_slice(data).map_err(|e| CodecError::MsgpackDecode(e.to_string()))?;

    if wire.t != 1 {
        return Err(CodecError::InvalidNodeType(wire.t));
    }

    let mut links = Vec::with_capacity(wire.l.len());
    for wl in wire.l {
        if wl.h.len() != 32 {
            return Err(CodecError::InvalidHashLength(wl.h.len()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&wl.h);

        let key = match wl.k {
            Some(k) if k.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                Some(key)
            }
            _ => None,
        };

        links.push(Link {
            hash,
            name: wl.n,
            size: wl.s,
            key,
        });
    }

    // Convert BTreeMap back to HashMap for the public API
    let metadata = wire.m.map(|m| m.into_iter().collect::<HashMap<_, _>>());

    Ok(TreeNode {
        links,
        total_size: wire.s,
        metadata,
    })
}

/// Encode a tree node and compute its hash
pub fn encode_and_hash(node: &TreeNode) -> Result<(Vec<u8>, Hash), CodecError> {
    let data = encode_tree_node(node)?;
    let hash = sha256(&data);
    Ok((data, hash))
}

/// Check if data is a MessagePack-encoded tree node (vs raw blob)
/// Tree nodes decode successfully with t=1
pub fn is_tree_node(data: &[u8]) -> bool {
    decode_tree_node(data).is_ok()
}

/// Check if data is a directory tree node (has named links)
/// vs a chunked file tree node (links have no names)
pub fn is_directory_node(data: &[u8]) -> bool {
    match decode_tree_node(data) {
        Ok(node) => {
            // Empty directory is still a directory
            if node.links.is_empty() {
                return true;
            }
            // Directory has named links, chunked file doesn't
            node.links[0].name.is_some()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::to_hex;

    #[test]
    fn test_encode_decode_empty_tree() {
        let node = TreeNode::new(vec![]);

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert_eq!(decoded.links.len(), 0);
    }

    #[test]
    fn test_encode_decode_tree_with_links() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        let node = TreeNode::new(vec![
            Link {
                hash: hash1,
                name: Some("file1.txt".to_string()),
                size: Some(100),
                key: None,
            },
            Link {
                hash: hash2,
                name: Some("dir".to_string()),
                size: Some(500),
                key: None,
            },
        ]);

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert_eq!(decoded.links.len(), 2);
        assert_eq!(decoded.links[0].name, Some("file1.txt".to_string()));
        assert_eq!(decoded.links[0].size, Some(100));
        assert_eq!(to_hex(&decoded.links[0].hash), to_hex(&hash1));
        assert_eq!(decoded.links[1].name, Some("dir".to_string()));
    }

    #[test]
    fn test_preserve_total_size() {
        let node = TreeNode::new(vec![]).with_total_size(12345);

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert_eq!(decoded.total_size, Some(12345));
    }

    #[test]
    fn test_preserve_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), serde_json::json!(1));
        metadata.insert("author".to_string(), serde_json::json!("test"));

        let node = TreeNode::new(vec![]).with_metadata(metadata.clone());

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert!(decoded.metadata.is_some());
        let m = decoded.metadata.unwrap();
        assert_eq!(m.get("version"), Some(&serde_json::json!(1)));
        assert_eq!(m.get("author"), Some(&serde_json::json!("test")));
    }

    #[test]
    fn test_links_without_optional_fields() {
        let hash = [42u8; 32];

        let node = TreeNode::new(vec![Link::new(hash)]);

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert_eq!(decoded.links[0].name, None);
        assert_eq!(decoded.links[0].size, None);
        assert_eq!(to_hex(&decoded.links[0].hash), to_hex(&hash));
    }

    #[test]
    fn test_encode_and_hash() {
        let node = TreeNode::new(vec![]);

        let (data, hash) = encode_and_hash(&node).unwrap();
        let expected_hash = sha256(&data);

        assert_eq!(to_hex(&hash), to_hex(&expected_hash));
    }

    #[test]
    fn test_encode_and_hash_consistent() {
        let node = TreeNode::new(vec![Link {
            hash: [1u8; 32],
            name: Some("test".to_string()),
            size: None,
            key: None,
        }]);

        let (_, hash1) = encode_and_hash(&node).unwrap();
        let (_, hash2) = encode_and_hash(&node).unwrap();

        assert_eq!(to_hex(&hash1), to_hex(&hash2));
    }

    #[test]
    fn test_is_tree_node() {
        let node = TreeNode::new(vec![]);
        let encoded = encode_tree_node(&node).unwrap();

        assert!(is_tree_node(&encoded));
    }

    #[test]
    fn test_is_tree_node_raw_blob() {
        let blob = vec![1u8, 2, 3, 4, 5];
        assert!(!is_tree_node(&blob));
    }

    #[test]
    fn test_is_tree_node_invalid_msgpack() {
        let invalid = vec![255u8, 255, 255];
        assert!(!is_tree_node(&invalid));
    }

    #[test]
    fn test_is_directory_node() {
        let node = TreeNode::new(vec![Link {
            hash: [1u8; 32],
            name: Some("file.txt".to_string()),
            size: None,
            key: None,
        }]);
        let encoded = encode_tree_node(&node).unwrap();

        assert!(is_directory_node(&encoded));
    }

    #[test]
    fn test_is_directory_node_empty() {
        let node = TreeNode::new(vec![]);
        let encoded = encode_tree_node(&node).unwrap();

        assert!(is_directory_node(&encoded));
    }

    #[test]
    fn test_is_not_directory_node() {
        let node = TreeNode::new(vec![Link::new([1u8; 32])]);
        let encoded = encode_tree_node(&node).unwrap();

        assert!(!is_directory_node(&encoded));
    }

    #[test]
    fn test_encrypted_link_roundtrip() {
        let hash = [1u8; 32];
        let key = [2u8; 32];

        let node = TreeNode::new(vec![Link {
            hash,
            name: Some("encrypted.dat".to_string()),
            size: Some(1024),
            key: Some(key),
        }]);

        let encoded = encode_tree_node(&node).unwrap();
        let decoded = decode_tree_node(&encoded).unwrap();

        assert_eq!(decoded.links[0].key, Some(key));
    }

    #[test]
    fn test_encoding_determinism() {
        // Test that encoding is deterministic across multiple calls
        // This is critical for content-addressed storage where hash must be stable
        let hash = [42u8; 32];

        let node = TreeNode::new(vec![
            Link {
                hash,
                name: Some("file.txt".to_string()),
                size: Some(100),
                key: None,
            },
        ]);

        // Encode multiple times and verify identical output
        let encoded1 = encode_tree_node(&node).unwrap();
        let encoded2 = encode_tree_node(&node).unwrap();
        let encoded3 = encode_tree_node(&node).unwrap();

        assert_eq!(encoded1, encoded2, "Encoding should be deterministic");
        assert_eq!(encoded2, encoded3, "Encoding should be deterministic");
    }

    #[test]
    fn test_metadata_determinism() {
        // Test that metadata encoding is deterministic regardless of HashMap insertion order
        // We use BTreeMap internally to ensure sorted keys
        let hash = [1u8; 32];

        // Create metadata with keys in different orders
        let mut metadata1 = HashMap::new();
        metadata1.insert("zebra".to_string(), serde_json::json!("last"));
        metadata1.insert("alpha".to_string(), serde_json::json!("first"));
        metadata1.insert("middle".to_string(), serde_json::json!("mid"));

        let mut metadata2 = HashMap::new();
        metadata2.insert("alpha".to_string(), serde_json::json!("first"));
        metadata2.insert("middle".to_string(), serde_json::json!("mid"));
        metadata2.insert("zebra".to_string(), serde_json::json!("last"));

        let node1 = TreeNode::new(vec![Link::new(hash)]).with_metadata(metadata1);
        let node2 = TreeNode::new(vec![Link::new(hash)]).with_metadata(metadata2);

        let encoded1 = encode_tree_node(&node1).unwrap();
        let encoded2 = encode_tree_node(&node2).unwrap();

        // Both should produce identical bytes (keys sorted alphabetically)
        assert_eq!(
            encoded1, encoded2,
            "Metadata encoding should be deterministic regardless of insertion order"
        );

        // Verify the hash is also identical
        let hash1 = crate::hash::sha256(&encoded1);
        let hash2 = crate::hash::sha256(&encoded2);
        assert_eq!(hash1, hash2, "Hashes should match for identical content");
    }
}
