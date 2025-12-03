//! CBOR encoding/decoding for tree nodes
//!
//! Blobs are stored raw (not CBOR-wrapped) for efficiency.
//! Tree nodes are CBOR-encoded.
//!
//! CBOR format uses short keys for compact encoding:
//! - t: type (1 = tree)
//! - l: links array
//! - h: hash (in link)
//! - n: name (in link, optional)
//! - s: size (in link or total_size, optional)
//! - m: metadata (optional)

use ciborium::value::Value;
use std::collections::HashMap;
use std::io::Cursor;

use crate::hash::sha256;
use crate::types::{Hash, Link, TreeNode};

/// Error type for codec operations
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("Invalid node type: {0}")]
    InvalidNodeType(i128),
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid field type for {0}")]
    InvalidFieldType(&'static str),
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),
    #[error("Invalid hash length: expected 32, got {0}")]
    InvalidHashLength(usize),
}

/// Encode a tree node to CBOR
pub fn encode_tree_node(node: &TreeNode) -> Result<Vec<u8>, CodecError> {
    let mut map: Vec<(Value, Value)> = Vec::new();

    // t = 1 for tree
    map.push((Value::Text("t".to_string()), Value::Integer(1.into())));

    // l = links array
    let links: Vec<Value> = node
        .links
        .iter()
        .map(|link| {
            let mut link_map: Vec<(Value, Value)> = Vec::new();

            // h = hash
            link_map.push((
                Value::Text("h".to_string()),
                Value::Bytes(link.hash.to_vec()),
            ));

            // n = name (optional)
            if let Some(ref name) = link.name {
                link_map.push((Value::Text("n".to_string()), Value::Text(name.clone())));
            }

            // s = size (optional)
            if let Some(size) = link.size {
                link_map.push((Value::Text("s".to_string()), Value::Integer(size.into())));
            }

            // k = key (optional, for encrypted links)
            if let Some(ref key) = link.key {
                link_map.push((
                    Value::Text("k".to_string()),
                    Value::Bytes(key.to_vec()),
                ));
            }

            Value::Map(link_map)
        })
        .collect();

    map.push((Value::Text("l".to_string()), Value::Array(links)));

    // s = totalSize (optional)
    if let Some(total_size) = node.total_size {
        map.push((
            Value::Text("s".to_string()),
            Value::Integer(total_size.into()),
        ));
    }

    // m = metadata (optional)
    if let Some(ref metadata) = node.metadata {
        let meta_map: Vec<(Value, Value)> = metadata
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
            .collect();
        map.push((Value::Text("m".to_string()), Value::Map(meta_map)));
    }

    let value = Value::Map(map);
    let mut buffer = Vec::new();
    ciborium::into_writer(&value, &mut buffer)
        .map_err(|e| CodecError::CborEncode(e.to_string()))?;

    Ok(buffer)
}

/// Convert JSON value to CBOR value
fn json_to_cbor(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                Value::Integer(u.into())
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_cbor).collect())
        }
        serde_json::Value::Object(obj) => {
            let map: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
                .collect();
            Value::Map(map)
        }
    }
}

/// Convert CBOR value to JSON value
fn cbor_to_json(cbor: &Value) -> serde_json::Value {
    match cbor {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            let n = i128::try_from(*i).unwrap_or(0);
            if n >= 0 {
                serde_json::json!(n as u64)
            } else {
                serde_json::json!(n as i64)
            }
        }
        Value::Float(f) => serde_json::json!(*f),
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_to_json).collect())
        }
        Value::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| {
                    if let Value::Text(key) = k {
                        Some((key.clone(), cbor_to_json(v)))
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        Value::Tag(_, inner) => cbor_to_json(inner),
        _ => serde_json::Value::Null,
    }
}

/// Decode CBOR to a tree node
pub fn decode_tree_node(data: &[u8]) -> Result<TreeNode, CodecError> {
    let value: Value = ciborium::from_reader(Cursor::new(data))
        .map_err(|e| CodecError::CborDecode(e.to_string()))?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(CodecError::InvalidFieldType("root")),
    };

    // Helper to find value by key
    let find_value = |key: &str| -> Option<&Value> {
        map.iter()
            .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
            .map(|(_, v)| v)
    };

    // Check type = 1
    let node_type = find_value("t")
        .ok_or(CodecError::MissingField("t"))?;
    let type_val = match node_type {
        Value::Integer(i) => i128::try_from(*i).unwrap_or(0),
        _ => return Err(CodecError::InvalidFieldType("t")),
    };
    if type_val != 1 {
        return Err(CodecError::InvalidNodeType(type_val));
    }

    // Parse links
    let links_val = find_value("l")
        .ok_or(CodecError::MissingField("l"))?;
    let links_arr = match links_val {
        Value::Array(arr) => arr,
        _ => return Err(CodecError::InvalidFieldType("l")),
    };

    let mut links = Vec::new();
    for link_val in links_arr {
        let link_map = match link_val {
            Value::Map(m) => m,
            _ => return Err(CodecError::InvalidFieldType("link")),
        };

        let find_link_value = |key: &str| -> Option<&Value> {
            link_map
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
                .map(|(_, v)| v)
        };

        // Parse hash
        let hash_val = find_link_value("h")
            .ok_or(CodecError::MissingField("h"))?;
        let hash_bytes = match hash_val {
            Value::Bytes(b) => b,
            _ => return Err(CodecError::InvalidFieldType("h")),
        };
        if hash_bytes.len() != 32 {
            return Err(CodecError::InvalidHashLength(hash_bytes.len()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_bytes);

        // Parse optional name
        let name = find_link_value("n").and_then(|v| {
            if let Value::Text(s) = v {
                Some(s.clone())
            } else {
                None
            }
        });

        // Parse optional size
        let size = find_link_value("s").and_then(|v| {
            if let Value::Integer(i) = v {
                u64::try_from(i128::try_from(*i).unwrap_or(0)).ok()
            } else {
                None
            }
        });

        // Parse optional key (for encrypted links)
        let key = find_link_value("k").and_then(|v| {
            if let Value::Bytes(b) = v {
                if b.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(b);
                    Some(key)
                } else {
                    None
                }
            } else {
                None
            }
        });

        links.push(Link {
            hash,
            name,
            size,
            key,
        });
    }

    // Parse optional totalSize
    let total_size = find_value("s").and_then(|v| {
        if let Value::Integer(i) = v {
            u64::try_from(i128::try_from(*i).unwrap_or(0)).ok()
        } else {
            None
        }
    });

    // Parse optional metadata
    let metadata = find_value("m").and_then(|v| {
        if let Value::Map(m) = v {
            let map: HashMap<String, serde_json::Value> = m
                .iter()
                .filter_map(|(k, val)| {
                    if let Value::Text(key) = k {
                        Some((key.clone(), cbor_to_json(val)))
                    } else {
                        None
                    }
                })
                .collect();
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        } else {
            None
        }
    });

    Ok(TreeNode {
        links,
        total_size,
        metadata,
    })
}

/// Encode a tree node and compute its hash
pub fn encode_and_hash(node: &TreeNode) -> Result<(Vec<u8>, Hash), CodecError> {
    let data = encode_tree_node(node)?;
    let hash = sha256(&data);
    Ok((data, hash))
}

/// Check if data is a CBOR-encoded tree node (vs raw blob)
/// Tree nodes start with CBOR map with t=1
pub fn is_tree_node(data: &[u8]) -> bool {
    match decode_tree_node(data) {
        Ok(_) => true,
        Err(_) => false,
    }
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
    fn test_is_tree_node_invalid_cbor() {
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
}
