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
- CHK (Content Hash Key) encryption (enabled by default)
- BEP52 (BitTorrent v2) compatible binary merkle algorithm (experimental)

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
    // Share cid.to_string() ("hash:key") to allow decryption

    // Read it back
    let data = tree.get(&cid).await?;

    Ok(())
}
```

### Public (Unencrypted) Content

For content that should be publicly readable without a key:

```rust
let tree = HashTree::new(HashTreeConfig::new(store).public());
let cid = tree.put(b"Public content").await?;

// cid.key is None, cid.to_string() is just the hash
```

### Directory Operations

```rust
use hashtree::DirEntry;

// Create files
let file1 = tree.put(b"content1").await?;
let file2 = tree.put(b"content2").await?;

// Create directory
let dir = tree.put_directory(vec![
    DirEntry::new("a.txt", file1.hash).with_size(file1.size),
    DirEntry::new("b.txt", file2.hash).with_size(file2.size),
], None).await?;

// List, resolve paths, walk trees
let entries = tree.list_directory(&dir).await?;
let resolved = tree.resolve_path(&dir, "a.txt").await?;
```

## Git Remote Helper

Push and pull git repos via hashtree using the `htree://` protocol.

### Installation

```bash
# Build and install to ~/.cargo/bin (must be in PATH)
cargo install --path crates/git-remote-htree

# Or install system-wide
cargo build --release -p git-remote-htree
sudo cp target/release/git-remote-htree /usr/local/bin/
```

Git automatically finds remote helpers named `git-remote-<protocol>` in PATH.

### Usage

```bash
# Add a remote (pubkey is 64 hex chars)
git remote add origin htree://<pubkey>/<repo-name>

# Push
git push origin main

# Clone (once repo exists)
git clone htree://<pubkey>/<repo-name>

# Pull
git pull origin main
```

### Configuration

The helper looks for your nostr private key in these locations:
- `~/.config/nostr/secret`
- `~/.nostr/secret`
- `~/.config/git-remote-htree/secret`

The key should be a hex-encoded 32-byte secret key (64 characters).

## Crates

- `hashtree` - Core merkle tree library
- `hashtree-bep52` - BEP52 specific implementation (experimental)
- `hashtree-lmdb` - LMDB storage backend
- `hashtree-resolver` - Nostr-based ref resolution
- `hashtree-webrtc` - P2P sync via WebRTC
- `hashtree-git` - Git object compatibility layer
- `hashtree-cli` - Command-line interface
- `hashtree-relay` - Nostr relay for hashtree events
- `git-remote-htree` - Git remote helper (htree:// protocol)

## Development

```bash
# Run tests
cargo test -p hashtree

# Run benchmarks
cargo bench -p hashtree
```

## License

MIT
