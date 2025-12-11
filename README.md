# hashtree-rs

Content-addressed merkle tree storage for Rust.

## Design

- **SHA256** hashing
- **MessagePack** encoding for tree nodes (deterministic)
- **Simple**: No multicodec, multibase, or CID versioning
- **CHK encryption** by default (Content Hash Key)
- **Dumb storage**: Works with any key-value store (hash → bytes). Unlike BitTorrent, no active merkle proof computation needed—just store and retrieve blobs by hash.
- **16KB chunks** by default: Fits WebRTC data channel limits and matches BitTorrent v2 piece size.

## Usage

```rust
use hashtree::{HashTree, HashTreeConfig, MemoryStore};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::new());
    let tree = HashTree::new(HashTreeConfig::new(store));

    // Store content (encrypted by default)
    let cid = tree.put(b"Hello, World!").await?;
    // cid contains hash + encryption key

    // Read it back
    let data = tree.get(&cid).await?;

    // Public (unencrypted) content
    let tree = HashTree::new(HashTreeConfig::new(store).public());
    let cid = tree.put(b"Public content").await?;

    Ok(())
}
```

## Tree Nodes

Every stored item is either raw bytes or a tree node. Tree nodes are MessagePack-encoded with a `type` field:

- `Blob` (0) - Raw data chunk (not a tree node, just bytes)
- `File` (1) - Chunked file: links are unnamed, ordered by byte offset
- `Dir` (2) - Directory: links have names, may point to files or subdirs

Wire format: `{t: LinkType, l: [{h: hash, s: size, n?: name, t: linkType, ...}]}`

## Crates

The `Store` trait is just `get(hash) → bytes` and `put(hash, bytes)`. The core is transport-agnostic—works with any backend that can store/fetch by hash.

- `hashtree` - Core merkle tree library
- `hashtree-lmdb` - LMDB storage backend
- `hashtree-resolver` - Nostr-based tree resolution
- `hashtree-git` - Git object compatibility layer
- `hashtree-cli` - Command-line interface
- `hashtree-sim` - P2P network simulation (Freenet-style HTL forwarding)
- `git-remote-htree` - Git remote helper (`htree://` protocol)

## Git Remote Helper

Push/pull git repos via hashtree:

```bash
# Install
cargo install --path crates/git-remote-htree

# Configure keys in ~/.hashtree/keys
# Format: <nsec or hex> [petname]
nsec1abc123... work

# Use
git remote add origin htree://work/myproject
git push origin main
git clone htree://npub1.../repo-name
```

## Development

```bash
cargo test -p hashtree    # Run tests
cargo bench -p hashtree   # Run benchmarks
```

## License

MIT
