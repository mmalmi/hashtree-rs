//! HashTree - Simple content-addressed merkle tree storage
//!
//! Rust-first library for building merkle trees with content-hash addressing:
//! SHA256(content) -> content
//!
//! # Overview
//!
//! HashTree provides a simple, efficient way to build and traverse content-addressed
//! merkle trees. It uses SHA256 for hashing and CBOR for tree node encoding.
//!
//! # Core Concepts
//!
//! - **Blobs**: Raw data stored directly by their hash (SHA256(data) -> data)
//! - **Tree Nodes**: CBOR-encoded nodes with links to children (SHA256(CBOR(node)) -> CBOR(node))
//! - **Links**: References to child nodes with optional name and size metadata
//!
//! # Example
//!
//! ```rust
//! use hashtree::{TreeBuilder, TreeReader, MemoryStore, BuilderConfig};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a memory store
//!     let store = Arc::new(MemoryStore::new());
//!
//!     // Build a tree
//!     let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));
//!     let result = builder.put_file(b"Hello, World!").await?;
//!
//!     // Read it back
//!     let reader = TreeReader::new(store);
//!     let data = reader.read_file(&result.hash).await?;
//!     assert_eq!(data, Some(b"Hello, World!".to_vec()));
//!
//!     Ok(())
//! }
//! ```

pub mod builder;
pub mod codec;
pub mod hash;
pub mod hashtree;
pub mod reader;
pub mod store;
pub mod types;

#[cfg(feature = "encryption")]
pub mod crypto;
#[cfg(feature = "encryption")]
pub mod encrypted;

// Re-exports for convenience
pub use builder::{BuilderConfig, BuilderError, MerkleAlgorithm, PutFileResult, StreamBuilder, StreamStats, TreeBuilder};
pub use builder::{BEP52_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_LINKS};
pub use codec::{
    decode_tree_node, encode_and_hash, encode_tree_node, is_directory_node, is_tree_node,
    CodecError,
};
pub use hash::{sha256, verify};
pub use hashtree::{HashTree, HashTreeConfig, HashTreeError, PutFileResult as HashTreePutFileResult, verify_tree as hashtree_verify_tree};
pub use reader::{verify_tree, ReaderError, TreeEntry, TreeReader, VerifyResult, WalkEntry};
pub use store::{MemoryStore, Store, StoreError};
pub use types::{from_hex, hash_equals, to_hex, DirEntry, Hash, Link, PutResult, TreeNode};

#[cfg(feature = "encryption")]
pub use crypto::{
    content_hash, could_be_encrypted, decrypt, decrypt_chk, encrypt, encrypt_chk, encrypted_size,
    encrypted_size_chk, generate_key, key_from_hex, key_to_hex, plaintext_size, CryptoError,
    EncryptionKey,
};
#[cfg(feature = "encryption")]
pub use encrypted::{
    put_file_encrypted, read_file_encrypted, EncryptedError, EncryptedPutResult,
    EncryptedTreeConfig,
};
