//! BEP52 (BitTorrent v2) compatible merkle tree implementation
//!
//! Key differences from default hashtree:
//! - 16 KiB block size (vs 256KB default)
//! - Binary tree (2 children per node, not variable fanout)
//! - Zero-padding for incomplete trees (pads to power of 2)
//! - SHA256 hash algorithm
//! - Piece layers: intermediate hash layers at piece boundaries
//!
//! # Example
//!
//! ```rust,no_run
//! use hashtree_bep52::{Bep52TreeBuilder, Bep52Config, MemoryStore};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = Arc::new(MemoryStore::new());
//!     let config = Bep52Config::new().with_store(store);
//!     let builder = Bep52TreeBuilder::new(config);
//!     let result = builder.build_from_data(b"Hello, World!").await.unwrap();
//!
//!     println!("Root: {:?}", result.root);
//!     println!("Blocks: {}", result.block_count);
//! }
//! ```
//!
//! @see <https://www.bittorrent.org/beps/bep_0052.html>

/// 32-byte SHA256 hash
pub type Hash = [u8; 32];

/// BEP52 block size: 16 KiB
pub const BEP52_BLOCK_SIZE: usize = 16 * 1024;

/// Zero hash (32 bytes of zeros) used for padding
pub const ZERO_HASH: Hash = [0u8; 32];

mod merkle;
mod builder;
mod store;

// Re-export main API
pub use builder::{Bep52Config, Bep52Result, Bep52StreamBuilder, Bep52TreeBuilder, BuilderError, StreamStats};
pub use store::{MemoryStore, Store, StoreError};

// Re-export low-level merkle functions
pub use merkle::{
    merkle_build_tree,
    merkle_first_leaf,
    merkle_get_first_child,
    merkle_get_parent,
    merkle_get_proof,
    merkle_get_sibling,
    merkle_hash_pair,
    merkle_num_leafs,
    merkle_num_nodes,
    merkle_pad_hash,
    merkle_root,
    merkle_verify_proof,
};
