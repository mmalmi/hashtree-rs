# Efficient Push: Tree Diff Implementation Plan

## Status: IMPLEMENTED

The diff-based push optimization has been implemented. See the sections below for details.

## Problem Statement

Currently, `push_to_file_servers` uploads every blob in the tree, relying on server-side 409 responses or HEAD checks. This wastes:
- Network round-trips for existence checks
- Bandwidth for HEAD request/response overhead
- CPU time waiting on network I/O

## Solution: Local Tree Diff

When pushing to an existing nostr ref, calculate the diff locally and upload only new/changed blobs.

## Design Principles

1. **Memory Efficient**: Stream both trees, don't load full hash sets into memory for large trees
2. **CPU Efficient**: Hash comparison only (content-addressed = no content comparison needed)
3. **Fast**: Early exit when subtrees match (hash equality = identical subtree)
4. **Parallel**: Concurrent fetching during diff calculation

## Architecture

### 1. Add `tree_diff` to hashtree-core

New module: `crates/hashtree-core/src/diff.rs`

```rust
/// Result of tree diff operation
pub struct TreeDiff {
    /// Hashes that exist in new tree but not in old tree (need upload)
    pub added: Vec<Hash>,
    /// Hashes that exist in old tree but not in new tree (orphaned)
    pub removed: Vec<Hash>,
    /// Statistics
    pub stats: DiffStats,
}

pub struct DiffStats {
    pub old_tree_nodes: usize,
    pub new_tree_nodes: usize,
    pub unchanged_subtrees: usize,  // Subtrees skipped due to hash match
}

/// Compute diff between two trees
/// Returns hashes present in `new_tree` but not in `old_tree`
pub async fn tree_diff<S: Store>(
    store: &HashTree<S>,
    old_root: &Cid,
    new_root: &Cid,
) -> Result<TreeDiff, HashTreeError>
```

**Algorithm: Parallel Set Difference with Subtree Pruning**

```
1. Build old_hashes set by walking old tree (streaming, parallel fetch)
2. Walk new tree:
   - For each node hash, check if in old_hashes
   - If hash matches: SKIP entire subtree (identical)
   - If hash differs: add to `added`, recurse into children
3. Return added set
```

**Memory Optimization for Large Trees:**

For trees with millions of nodes, use a bloom filter for initial check:
```rust
/// For very large trees, use bloom filter + verification
pub async fn tree_diff_large<S: Store>(
    store: &HashTree<S>,
    old_root: &Cid,
    new_root: &Cid,
    expected_old_size: Option<usize>,
) -> Result<TreeDiff, HashTreeError>
```

### 2. Modify Push Flow in git-remote-htree

**Current flow:**
```
1. build_tree() -> new_root_hash
2. push_to_file_servers(new_root_hash) -> uploads ALL blobs
3. publish_repo() -> nostr
```

**New flow:**
```
1. Fetch existing ref from nostr (already happens in load_existing_remote_state)
   - Returns (old_root_hash, encryption_key)
2. build_tree() -> new_root_hash
3. IF old_root_hash exists:
   a. Ensure old tree is in local store (download if needed)
   b. tree_diff(old_root, new_root) -> added_hashes
   c. push_hashes_to_file_servers(added_hashes)
   d. Track which blossom servers have old tree
   e. For servers without old tree: push full tree
   ELSE:
   push_to_file_servers(new_root_hash) // existing behavior
4. publish_repo() -> nostr
```

### 3. Handle Blossom Server Coverage

Problem: Not all blossom servers may have the old tree.

Solution:
```rust
/// Check which servers have the old root
async fn check_server_coverage(
    blossom: &BlossomClient,
    old_root_hash: &str,
) -> Vec<(String, bool)>  // (server_url, has_old_tree)

/// For servers missing old tree, upload full tree
/// For servers with old tree, upload only diff
fn push_with_coverage(
    &self,
    new_root_hash: &str,
    old_root_hash: Option<&str>,
    diff_hashes: Option<&HashSet<Hash>>,
    server_coverage: &[(String, bool)],
)
```

### 4. Download/Stream Old Tree

If we don't have the old tree locally, we need to fetch it:

```rust
/// Ensure old tree is available in local store
/// Downloads from blossom if not present
async fn ensure_tree_available<S: Store>(
    store: &HashTree<S>,
    blossom: &BlossomClient,
    root: &Cid,
) -> Result<(), HashTreeError>
```

**Optimization**: Use streaming walk - don't download blob content, only tree structure:
- Tree nodes: download and cache (needed for traversal)
- Blobs: record hash only (metadata from parent link is sufficient)

## Implementation Plan (TDD)

### Phase 1: hashtree-core diff module

**Tests first:**
```rust
// crates/hashtree-core/src/diff.rs

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_diff_identical_trees() {
        // Same root = empty diff
    }

    #[tokio::test]
    async fn test_diff_single_file_change() {
        // Change one file, verify only that file's blobs in diff
    }

    #[tokio::test]
    async fn test_diff_subtree_unchanged() {
        // Verify unchanged subtrees are skipped (not traversed)
    }

    #[tokio::test]
    async fn test_diff_new_directory() {
        // Add new directory, all its contents in diff
    }

    #[tokio::test]
    async fn test_diff_deleted_directory() {
        // Remove directory, verify removed set contains its hashes
    }

    #[tokio::test]
    async fn test_diff_empty_to_populated() {
        // First push (no old tree) = all hashes in diff
    }

    #[tokio::test]
    async fn test_diff_large_tree_performance() {
        // Benchmark with 10k+ nodes
    }
}
```

**Implementation:**
1. `collect_hashes()` - streaming hash collection with parallel fetch
2. `tree_diff()` - main diff function
3. `tree_diff_streaming()` - memory-efficient version for huge trees

### Phase 2: git-remote-htree integration

**Tests:**
```rust
// crates/git-remote-htree/src/helper.rs tests

#[test]
fn test_push_first_time_uploads_all() {
    // No existing ref = upload everything
}

#[test]
fn test_push_no_changes_uploads_nothing() {
    // Same tree = upload nothing (except root for verification)
}

#[test]
fn test_push_small_change_uploads_minimal() {
    // Change one file = only upload changed blobs + parent tree nodes
}

#[test]
fn test_push_handles_missing_old_tree() {
    // Old ref exists but tree not in local store = download first
}

#[test]
fn test_push_partial_server_coverage() {
    // Some servers have old tree, some don't = hybrid strategy
}
```

**Implementation:**
1. Add `ensure_tree_available()` helper
2. Modify `process_push()` to use diff when old root exists
3. Add `push_diff_to_file_servers()` - upload only specific hashes
4. Add `check_server_coverage()` for hybrid upload strategy

### Phase 3: Optimizations

1. **Bloom filter for huge trees**: When old tree has >100k nodes, use bloom filter
2. **Parallel diff**: Fetch nodes from both trees concurrently
3. **Incremental hash collection**: Stream hashes to upload channel as discovered

## API Changes

### hashtree-core public API additions

```rust
// New module: crates/hashtree-core/src/diff.rs

pub struct TreeDiff {
    pub added: Vec<Hash>,
    pub removed: Vec<Hash>,
    pub stats: DiffStats,
}

pub struct DiffStats {
    pub old_tree_nodes: usize,
    pub new_tree_nodes: usize,
    pub unchanged_subtrees: usize,
}

impl<S: Store> HashTree<S> {
    /// Compute diff between two trees
    pub async fn diff(&self, old: &Cid, new: &Cid) -> Result<TreeDiff, HashTreeError>;

    /// Collect all hashes in a tree (streaming)
    pub async fn collect_hashes(&self, root: &Cid) -> Result<HashSet<Hash>, HashTreeError>;

    /// Collect hashes with streaming callback (memory efficient)
    pub async fn collect_hashes_streaming<F>(&self, root: &Cid, callback: F) -> Result<usize, HashTreeError>
    where F: FnMut(Hash) -> bool;  // return false to stop
}
```

### git-remote-htree changes

```rust
// Modified push flow in helper.rs

impl RemoteHelper {
    /// Push with optional diff-based optimization
    async fn push_optimized(
        &self,
        new_root: &str,
        old_root: Option<&str>,
        encryption_key: Option<&[u8; 32]>,
    ) -> Result<usize, Error>;
}
```

## File Changes Summary

| File | Change |
|------|--------|
| `crates/hashtree-core/src/lib.rs` | Add `pub mod diff;` |
| `crates/hashtree-core/src/diff.rs` | **NEW** - Tree diff implementation |
| `crates/hashtree-core/src/hashtree.rs` | Add `diff()`, `collect_hashes()` methods |
| `crates/git-remote-htree/src/helper.rs` | Modify `push_to_file_servers()`, add diff integration |
| `crates/git-remote-htree/src/nostr_client.rs` | Minor: expose old root hash from fetch |

## Performance Expectations

| Scenario | Current | With Diff |
|----------|---------|-----------|
| Push identical tree | N HEAD checks | 1 hash compare |
| Change 1 file in 1000 | 1000 HEAD checks | ~10 uploads |
| Add new directory | All blobs uploaded | Only new blobs |
| First push | All uploaded | All uploaded (no change) |

## Risk Mitigation

1. **Fallback**: If diff fails, fall back to full upload
2. **Verification**: After push, verify root hash exists on all servers
3. **Timeout**: Set reasonable timeout for old tree download
4. **Memory limit**: For trees >1M nodes, use streaming/bloom approach

## Testing Strategy

1. **Unit tests**: Each function in diff.rs
2. **Integration tests**: Full push flow with mock blossom
3. **Performance tests**: Benchmark with varying tree sizes
4. **Edge cases**: Empty trees, single file, deeply nested, wide directories

---

## Implementation Summary (Completed)

### Files Changed

1. **`crates/hashtree-core/src/diff.rs`** (NEW)
   - `TreeDiff` struct with `added` hashes and `DiffStats`
   - `collect_hashes()` - parallel hash collection from tree
   - `collect_hashes_with_progress()` - with progress counter
   - `tree_diff()` - main diff function
   - `tree_diff_with_old_hashes()` - diff using pre-computed hash set
   - `tree_diff_streaming()` - memory-efficient streaming version
   - 10 unit tests covering all edge cases

2. **`crates/hashtree-core/src/lib.rs`**
   - Added `pub mod diff;`
   - Re-exported diff module functions

3. **`crates/git-remote-htree/src/helper.rs`**
   - Renamed `push_to_file_servers()` to `push_to_file_servers_with_diff()`
   - Added parameters for old root hash and encryption key
   - Uses `collect_hashes()` to get old tree's hash set
   - Skips entire subtrees when hash exists in old tree
   - Shows improved progress: "X new, Y unchanged, Z exist on server"

### How It Works

1. When pushing, the system checks if an old root hash is cached from nostr
2. If old root exists and differs from new root:
   - Collects all hashes from old tree (parallel, 32 concurrent)
   - During new tree walk, skips any hash found in old tree's hash set
   - Only uploads hashes that are truly new
3. If old root doesn't exist or equals new root:
   - Falls back to original behavior (upload all) or skips entirely

### User-Visible Changes

When pushing to an existing repo, users will see:
```
  Computing diff from previous tree... 1234 hashes in old tree
  Uploading: 45 (10 new, 1180 unchanged, 35 exist on server)
```

For identical repos:
```
  No changes detected (same root hash)
```

### Testing

4. **`crates/git-remote-htree/tests/git_roundtrip.rs`**
   - Added local in-memory nostr relay (`TestRelay`) for testing without network
   - Added local blossom server (`TestServer`) using temp directories
   - `test_git_push_and_clone_local` - full roundtrip with local servers
   - `test_diff_based_push` - verifies diff optimization reduces uploads

5. **`crates/git-remote-htree/src/nostr_client.rs`**
   - Added `shutdown_timeout()` for graceful runtime cleanup
   - Prevents "runtime shutting down" panics from nostr-sdk timers

### Not Implemented (Future Work)

- **Server coverage detection**: Upload full tree to servers that don't have old root
- **Bloom filter**: For very large trees (>100k nodes) to reduce memory
- **Deterministic tree building**: Index file timestamps cause minor hash variations
