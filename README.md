# hashtree-rs

Content-addressed merkle tree storage library for Rust.

## Design Philosophy

**Simple over clever.** SHA256 for hashing, CBOR for encoding. No multicodec, multibase, or CID versioning. One way to do things.

**Core does one thing.** Merkle trees over any key-value store. That's it. The library doesn't know about networks, peers, or protocols.

**Composition over integration.** Want WebRTC sync? Nostr discovery? Those are separate layers that *use* hashtree, not part of it.

## Features

- SHA256 hashing
- CBOR encoding for tree nodes
- File chunking with configurable size
- Directory support with nested trees
- Streaming append for large files
- Tree verification
- BEP52 (BitTorrent v2) compatible binary merkle algorithm (experimental)

## Usage

```rust
use hashtree::{TreeBuilder, TreeReader, MemoryStore, BuilderConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::new());

    // Build a tree
    let builder = TreeBuilder::new(BuilderConfig::new(store.clone()));
    let result = builder.put_file(b"Hello, World!").await?;

    // Read it back
    let reader = TreeReader::new(store);
    let data = reader.read_file(&result.hash).await?;

    Ok(())
}
```

### BEP52 Binary Merkle Algorithm

For BitTorrent v2 compatibility exploration:

```rust
use hashtree::{TreeBuilder, BuilderConfig, MerkleAlgorithm, BEP52_CHUNK_SIZE};

let config = BuilderConfig::new(store)
    .with_chunk_size(BEP52_CHUNK_SIZE)      // 16KB
    .with_merkle_algorithm(MerkleAlgorithm::Binary);

let builder = TreeBuilder::new(config);
let result = builder.put_file(&data).await?;

// result.leaf_hashes contains chunk hashes for verification
```

Note: Binary mode computes root hashes only (no intermediate nodes stored). Use CBOR mode (default) for full tree traversal with TreeReader.

## Crates

- `hashtree` - Core merkle tree library
- `hashtree-bep52` - BEP52 specific implementation (experimental)

## Development

```bash
# Run tests
cargo test -p hashtree

# Run benchmarks
cargo bench -p hashtree
```

## License

MIT
