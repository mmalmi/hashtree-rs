# hashtree-rs

Content-addressed filesystem on Nostr.

Basically [Blossom](https://github.com/hzrd149/blossom) with chunking and directory structure. Merkle roots can be published on Nostr to get mutable `npub/path` addresses.

## Design

- **SHA256** hashing
- **MessagePack** encoding for tree nodes (deterministic)
- **CHK encryption** by default (Content Hash Key) — ~2-3x overhead vs plain (still 500+ MiB/s)
- **Dumb storage**: Works with any key-value store (hash → bytes). Unlike BitTorrent, no active merkle proof computation needed—just store and retrieve blobs by hash.
- **2MB chunks** by default (optimized for blossom uploads)

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

## CLI

```bash
# Add content
htree add myfile.txt                    # Add file (encrypted)
htree add mydir/ --public               # Add directory (unencrypted)
htree add myfile.txt --publish mydata   # Add and publish to Nostr

# Push to Blossom servers
htree push <hash>                       # Push to configured servers
htree push <hash> -s https://blossom.example.com  # Push to specific server

# Get/cat content
htree get <hash>                        # Download to file
htree cat <hash>                        # Print to stdout

# Pins
htree pins                              # List pinned content
htree pin <hash>                        # Pin content
htree unpin <hash>                      # Unpin content

# Nostr identity
htree user                              # Show npub
htree publish mydata <hash>             # Publish hash to npub.../mydata
htree follow npub1...                   # Follow user
htree following                         # List followed users
```

## Development

```bash
cargo test -p hashtree    # Run tests
cargo bench -p hashtree   # Run benchmarks
```

## License

MIT
