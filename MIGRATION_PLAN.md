# Migration Plan: nosta → hashtree-rs

## Overview

Migrate all nosta crates into the hashtree-rs monorepo with consistent naming and a single `htree` binary.

## Target Structure

```
hashtree-rs/
├── crates/
│   ├── hashtree/              # (existing) Core merkle tree library
│   ├── hashtree-bep52/        # (existing) BitTorrent v2 compat
│   ├── hashtree-resolver/     # (existing) Name resolution
│   ├── hashtree-webrtc/       # (existing) WebRTC transport
│   ├── hashtree-cli/          # (NEW) CLI + daemon, binary: htree
│   ├── hashtree-git/          # (from nosta-git) Git protocol
│   ├── hashtree-relay/        # (from nosta-relay) Nostr relay
│   ├── hashtree-lmdb/         # (from lmdb-blob-store) LMDB storage
│   └── git-remote-nostr/      # (keep name - git convention)
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
└── README.md
```

## Naming Changes

| Old (nosta) | New (hashtree-rs) | Notes |
|-------------|-------------------|-------|
| `nosta` (binary) | `htree` | Single CLI binary |
| `nosta` (lib) | `hashtree-cli` | Main crate with daemon + CLI |
| `lmdb-blob-store` | `hashtree-lmdb` | LMDB storage backend |
| `nosta-git` | `hashtree-git` | Git smart HTTP protocol |
| `nosta-relay` | `hashtree-relay` | Nostr relay integration |
| `git-remote-nostr` | `git-remote-nostr` | Keep as-is (git convention) |

## Migration Steps

### Phase 1: Prepare hashtree-rs workspace

1. **Update workspace Cargo.toml** - Add new dependencies needed by nosta:
   - axum, tower, tower-http (HTTP server)
   - heed (LMDB)
   - nostr, nostr-sdk (Nostr protocol)
   - clap (CLI)
   - Additional deps from nosta

### Phase 2: Migrate crates (in dependency order)

Order matters - migrate dependencies first:

1. **hashtree-lmdb** (no internal deps)
   - Copy `nosta/crates/lmdb-blob-store/` → `hashtree-rs/crates/hashtree-lmdb/`
   - Update Cargo.toml: rename package, use workspace deps
   - Update imports: `hashtree = { workspace = true }`

2. **hashtree-relay** (no internal deps besides hashtree)
   - Copy `nosta/crates/nosta-relay/` → `hashtree-rs/crates/hashtree-relay/`
   - Update Cargo.toml: rename package, use workspace deps

3. **hashtree-git** (depends on hashtree-lmdb)
   - Copy `nosta/crates/nosta-git/` → `hashtree-rs/crates/hashtree-git/`
   - Update Cargo.toml: rename package, use workspace deps
   - Update internal deps: `hashtree-lmdb = { path = "../hashtree-lmdb" }`

4. **git-remote-nostr** (depends on hashtree-git, hashtree-lmdb)
   - Copy `nosta/crates/git-remote-nostr/` → `hashtree-rs/crates/git-remote-nostr/`
   - Update Cargo.toml: use workspace deps
   - Update internal deps to new names

5. **hashtree-cli** (depends on all above)
   - Copy `nosta/src/` → `hashtree-rs/crates/hashtree-cli/src/`
   - Create new Cargo.toml with:
     ```toml
     [[bin]]
     name = "htree"
     path = "src/main.rs"
     ```
   - Update all internal deps to new names

### Phase 3: Update internal references

1. **Source code updates:**
   - `use lmdb_blob_store::` → `use hashtree_lmdb::`
   - `use nosta_git::` → `use hashtree_git::`
   - `use nosta_relay::` → `use hashtree_relay::`

2. **Config/paths updates:**
   - `~/.nosta/` → `~/.hashtree/` (or keep for backwards compat?)
   - `./nosta-data/` → `./hashtree-data/`
   - Config file references

3. **CLI updates:**
   - Update help text, command names
   - Update default paths

### Phase 4: Update root files

1. **Merge Cargo.lock** - Combine dependencies
2. **Update Dockerfile** - Change binary name to `htree`
3. **Merge README.md** - Combine documentation
4. **Update .gitignore** if needed

### Phase 5: Tests and verification

1. Run `cargo build --workspace`
2. Run `cargo test --workspace`
3. Test CLI commands manually:
   - `htree start`
   - `htree upload <file>`
   - `htree pins`
4. Test git integration
5. Test Docker build

### Phase 6: Cleanup

1. Remove nosta directory (after confirming everything works)
2. Update any external references (if published)

## Breaking Changes

- Binary name: `nosta` → `htree`
- Default data directory: `./nosta-data/` → `./hashtree-data/`
- Config location: `~/.nosta/` → `~/.hashtree/`

## Open Questions

1. **Backwards compatibility for config?**
   - Option A: Just change paths (breaking)
   - Option B: Check both locations, migrate automatically
   - Recommendation: Option A (clean break, this is pre-1.0)

2. **Keep nosta-webrtc separate from hashtree-webrtc?**
   - nosta has its own webrtc module in main crate
   - hashtree-webrtc exists in hashtree-rs
   - Need to reconcile/merge these

3. **Git dependencies (nostrdb, enostr)?**
   - These are external git deps, will need to stay as git deps
   - Add to workspace dependencies

## Estimated File Count

- Source files to move: ~35
- Cargo.toml files to update: 5
- Total lines of code: ~13,000

## Commands to Execute

```bash
# Phase 1: Create directories
mkdir -p crates/hashtree-lmdb/src
mkdir -p crates/hashtree-git/src
mkdir -p crates/hashtree-relay/src
mkdir -p crates/hashtree-cli/src
mkdir -p crates/git-remote-nostr/src

# Phase 2: Copy files (will do incrementally)
# ... detailed commands during execution

# Phase 5: Verify
cargo build --workspace
cargo test --workspace
./target/debug/htree --help
```
