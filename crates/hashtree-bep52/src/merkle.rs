//! BEP52 merkle tree utility functions
//!
//! These match libtorrent's merkle tree implementation for compatibility.

use sha2::{Digest, Sha256};
use crate::{Hash, ZERO_HASH};

/// Compute the number of leaves needed (rounds up to power of 2)
#[inline]
pub fn merkle_num_leafs(blocks: usize) -> usize {
    if blocks == 0 {
        return 0;
    }
    let mut n = 1;
    while n < blocks {
        n <<= 1;
    }
    n
}

/// Get parent index in flat tree representation
/// Tree layout: [0=root, 1=left, 2=right, 3=left-left, 4=left-right, ...]
#[inline]
pub fn merkle_get_parent(idx: usize) -> usize {
    (idx - 1) / 2
}

/// Get sibling index
#[inline]
pub fn merkle_get_sibling(idx: usize) -> usize {
    // Even indices have sibling to left, odd to right
    if idx & 1 == 1 {
        idx + 1
    } else {
        idx - 1
    }
}

/// Get first child index
#[inline]
pub fn merkle_get_first_child(idx: usize) -> usize {
    idx * 2 + 1
}

/// Get index of first leaf given number of leaves
#[inline]
pub fn merkle_first_leaf(num_leafs: usize) -> usize {
    num_leafs - 1
}

/// Get total number of nodes in tree given number of leaves
#[inline]
pub fn merkle_num_nodes(num_leafs: usize) -> usize {
    num_leafs * 2 - 1
}

/// Compute hash of two concatenated hashes (parent = H(left || right))
pub fn merkle_hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the pad hash for a given depth
/// pad(0) = zero hash
/// pad(n) = H(pad(n-1) || pad(n-1))
pub fn merkle_pad_hash(depth: usize) -> Hash {
    let mut pad = ZERO_HASH;
    for _ in 0..depth {
        pad = merkle_hash_pair(&pad, &pad);
    }
    pad
}

/// Compute merkle root from leaf hashes with zero-padding
///
/// Uses scratch space approach like libtorrent's merkle_root_scratch
pub fn merkle_root(leaves: &[Hash], num_leafs: Option<usize>) -> Hash {
    if leaves.is_empty() {
        return ZERO_HASH;
    }

    if leaves.len() == 1 && (num_leafs.is_none() || num_leafs == Some(1)) {
        return leaves[0];
    }

    let target_leafs = num_leafs.unwrap_or_else(|| merkle_num_leafs(leaves.len()));

    // Build tree bottom-up using scratch space
    let mut current: Vec<Hash> = leaves.to_vec();
    let mut pad_hash = ZERO_HASH;
    let mut level_size = target_leafs;

    while level_size > 1 {
        let mut next_level: Vec<Hash> = Vec::with_capacity((current.len() + 1) / 2);

        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                // Both children present
                next_level.push(merkle_hash_pair(&current[i], &current[i + 1]));
            } else {
                // Odd leaf - pair with pad
                next_level.push(merkle_hash_pair(&current[i], &pad_hash));
            }
            i += 2;
        }

        // Compute next level's pad hash (H(pad || pad))
        pad_hash = merkle_hash_pair(&pad_hash, &pad_hash);

        current = next_level;
        level_size /= 2;
    }

    current[0]
}

/// Build full merkle tree from leaves, returning all nodes
///
/// Returns flat array of tree nodes [root, layer1..., leaves]
pub fn merkle_build_tree(leaves: &[Hash]) -> Vec<Hash> {
    if leaves.is_empty() {
        return vec![ZERO_HASH];
    }

    let num_leafs = merkle_num_leafs(leaves.len());
    let num_nodes = merkle_num_nodes(num_leafs);
    let mut tree: Vec<Hash> = vec![ZERO_HASH; num_nodes];

    // Fill leaves (with zero-padding)
    let first_leaf = merkle_first_leaf(num_leafs);
    for (i, leaf) in leaves.iter().enumerate() {
        tree[first_leaf + i] = *leaf;
    }
    // Remaining leaves are already zero-padded

    // Build parents bottom-up
    let mut level_start = first_leaf;
    let mut level_size = num_leafs;

    while level_size > 1 {
        let mut parent = merkle_get_parent(level_start);
        let mut i = level_start;
        while i < level_start + level_size {
            tree[parent] = merkle_hash_pair(&tree[i], &tree[i + 1]);
            parent += 1;
            i += 2;
        }
        level_start = merkle_get_parent(level_start);
        level_size /= 2;
    }

    tree
}

/// Generate uncle hashes (proof) for a leaf
pub fn merkle_get_proof(tree: &[Hash], leaf_index: usize, num_leafs: usize) -> Vec<Hash> {
    let mut proofs: Vec<Hash> = Vec::new();
    let mut idx = merkle_first_leaf(num_leafs) + leaf_index;

    while idx > 0 {
        let sibling_idx = merkle_get_sibling(idx);
        proofs.push(tree[sibling_idx]);
        idx = merkle_get_parent(idx);
    }

    proofs
}

/// Verify a merkle proof
pub fn merkle_verify_proof(
    leaf: &Hash,
    leaf_index: usize,
    proof: &[Hash],
    root: &Hash,
    num_leafs: usize,
) -> bool {
    let mut hash = *leaf;
    let mut idx = merkle_first_leaf(num_leafs) + leaf_index;

    for uncle in proof {
        // In flat tree: children of parent P are at 2P+1 (left) and 2P+2 (right)
        // So odd indices are LEFT children, even indices are RIGHT children
        hash = if idx & 1 == 1 {
            // Odd index - we're on the left, uncle is on right
            merkle_hash_pair(&hash, uncle)
        } else {
            // Even index - we're on the right, uncle is on left
            merkle_hash_pair(uncle, &hash)
        };
        idx = merkle_get_parent(idx);
    }

    hash == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_from_fill(val: u8) -> Hash {
        [val; 32]
    }

    #[test]
    fn test_merkle_num_leafs() {
        assert_eq!(merkle_num_leafs(0), 0);
        assert_eq!(merkle_num_leafs(1), 1);
        assert_eq!(merkle_num_leafs(2), 2);
        assert_eq!(merkle_num_leafs(3), 4);
        assert_eq!(merkle_num_leafs(4), 4);
        assert_eq!(merkle_num_leafs(5), 8);
        assert_eq!(merkle_num_leafs(8), 8);
        assert_eq!(merkle_num_leafs(9), 16);
    }

    #[test]
    fn test_merkle_get_parent() {
        // Tree structure:
        //             0
        //      1              2
        //   3      4       5       6
        //  7 8    9 10   11 12   13 14
        assert_eq!(merkle_get_parent(1), 0);
        assert_eq!(merkle_get_parent(2), 0);
        assert_eq!(merkle_get_parent(3), 1);
        assert_eq!(merkle_get_parent(4), 1);
        assert_eq!(merkle_get_parent(5), 2);
        assert_eq!(merkle_get_parent(6), 2);
        assert_eq!(merkle_get_parent(7), 3);
        assert_eq!(merkle_get_parent(14), 6);
    }

    #[test]
    fn test_merkle_get_sibling() {
        assert_eq!(merkle_get_sibling(1), 2);
        assert_eq!(merkle_get_sibling(2), 1);
        assert_eq!(merkle_get_sibling(3), 4);
        assert_eq!(merkle_get_sibling(4), 3);
        assert_eq!(merkle_get_sibling(7), 8);
        assert_eq!(merkle_get_sibling(8), 7);
    }

    #[test]
    fn test_merkle_first_leaf() {
        assert_eq!(merkle_first_leaf(1), 0);
        assert_eq!(merkle_first_leaf(2), 1);
        assert_eq!(merkle_first_leaf(4), 3);
        assert_eq!(merkle_first_leaf(8), 7);
    }

    #[test]
    fn test_merkle_num_nodes() {
        assert_eq!(merkle_num_nodes(1), 1);
        assert_eq!(merkle_num_nodes(2), 3);
        assert_eq!(merkle_num_nodes(4), 7);
        assert_eq!(merkle_num_nodes(8), 15);
    }

    #[test]
    fn test_merkle_hash_pair() {
        let a = hash_from_fill(1);
        let b = hash_from_fill(2);

        let ab = merkle_hash_pair(&a, &b);
        let ba = merkle_hash_pair(&b, &a);

        // Order matters
        assert_ne!(ab, ba);
    }

    #[test]
    fn test_merkle_root_single() {
        let leaf = hash_from_fill(42);
        let root = merkle_root(&[leaf], None);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two() {
        let a = hash_from_fill(1);
        let b = hash_from_fill(2);

        let root = merkle_root(&[a, b], Some(2));
        let expected = merkle_hash_pair(&a, &b);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three() {
        let a = hash_from_fill(1);
        let b = hash_from_fill(2);
        let c = hash_from_fill(3);

        // Tree: ((a,b), (c,0))
        let root = merkle_root(&[a, b, c], Some(4));

        let ab = merkle_hash_pair(&a, &b);
        let c0 = merkle_hash_pair(&c, &ZERO_HASH);
        let expected = merkle_hash_pair(&ab, &c0);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_build_tree() {
        let leaves = [
            hash_from_fill(1),
            hash_from_fill(2),
            hash_from_fill(3),
            hash_from_fill(4),
        ];

        let tree = merkle_build_tree(&leaves);

        // Tree should have 7 nodes (2*4 - 1)
        assert_eq!(tree.len(), 7);

        // Leaves should be at indices 3-6
        assert_eq!(tree[3], leaves[0]);
        assert_eq!(tree[4], leaves[1]);
        assert_eq!(tree[5], leaves[2]);
        assert_eq!(tree[6], leaves[3]);

        // Parents should be computed
        let expected12 = merkle_hash_pair(&leaves[0], &leaves[1]);
        let expected34 = merkle_hash_pair(&leaves[2], &leaves[3]);
        assert_eq!(tree[1], expected12);
        assert_eq!(tree[2], expected34);

        // Root
        let expected_root = merkle_hash_pair(&expected12, &expected34);
        assert_eq!(tree[0], expected_root);
    }

    #[test]
    fn test_merkle_proof_verify() {
        let leaves = [
            hash_from_fill(1),
            hash_from_fill(2),
            hash_from_fill(3),
            hash_from_fill(4),
        ];

        let tree = merkle_build_tree(&leaves);
        let root = tree[0];

        // Verify proof for each leaf
        for i in 0..4 {
            let proof = merkle_get_proof(&tree, i, 4);
            let valid = merkle_verify_proof(&leaves[i], i, &proof, &root, 4);
            assert!(valid, "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let leaves = [
            hash_from_fill(1),
            hash_from_fill(2),
            hash_from_fill(3),
            hash_from_fill(4),
        ];

        let tree = merkle_build_tree(&leaves);
        let root = tree[0];
        let proof = merkle_get_proof(&tree, 0, 4);

        // Wrong leaf should fail
        let wrong_leaf = hash_from_fill(99);
        let valid = merkle_verify_proof(&wrong_leaf, 0, &proof, &root, 4);
        assert!(!valid);
    }
}
