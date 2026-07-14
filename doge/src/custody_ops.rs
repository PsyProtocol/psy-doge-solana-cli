//! Tracked custody UTXO computation helpers for the bridge withdrawal operator.
//!
//! This module provides pure functions for computing combined TXO indices,
//! sparse Merkle tree leaf updates, and spent-root computation. It does NOT
//! manage its own SQLite connection — UTXO lifecycle is handled by
//! `doge_bridge_client::operator_store::OperatorStore`.

use psy_bridge_core::crypto::hash::sha256::SHA256_ZERO_HASHES;
use psy_bridge_core::crypto::hash::sha256_impl::hash_impl_sha256_two_to_one_bytes;
use psy_bridge_core::txo_constants::{
    get_txo_combined_index, get_txo_merkle_index_and_leaf_bit_index_from_combined_index,
};
use psy_bridge_core::txo_constants::TXO_MERKLE_INDEX_TOTAL_BITS;
use std::collections::HashMap;

/// Compute a combined TXO index from a Dogecoin transaction's on-chain position.
pub fn compute_combined_index(block_height: u32, tx_index_in_block: u16, vout: u16) -> u64 {
    get_txo_combined_index(block_height, tx_index_in_block, vout)
}

/// Derive the (merkle_index, bit_index) from a combined index.
pub fn decode_combined_index(combined_index: u64) -> (u64, u8) {
    get_txo_merkle_index_and_leaf_bit_index_from_combined_index(combined_index)
}

/// Rebuild the full Merkle leaf state from a list of spent custody UTXO combined indices.
///
/// Each spent output sets a bit in the 32-byte leaf bit vector at its merkle_index.
/// Multiple spent outputs at the same merkle_index OR their bits together.
pub fn rebuild_merkle_leaves(spent_combined_indices: &[u64]) -> HashMap<u64, [u8; 32]> {
    let mut leaves: HashMap<u64, [u8; 32]> = HashMap::new();
    for ci in spent_combined_indices {
        let (merkle_idx, bit_idx) = decode_combined_index(*ci);
        let leaf = leaves.entry(merkle_idx).or_insert([0u8; 32]);
        let byte_idx = (bit_idx >> 3) as usize;
        leaf[byte_idx] |= 1 << (bit_idx & 7);
    }
    leaves
}

/// Set bits in a 32-byte leaf bit vector for multiple combined indices, starting
/// from existing leaf state.
pub fn compute_updated_leaf_values(
    combined_indices: &[u64],
    existing_leaves: &HashMap<u64, [u8; 32]>,
) -> HashMap<u64, [u8; 32]> {
    let mut result: HashMap<u64, [u8; 32]> = HashMap::new();
    for ci in combined_indices {
        let (merkle_idx, bit_idx) = decode_combined_index(*ci);
        let leaf = result
            .entry(merkle_idx)
            .or_insert_with(|| existing_leaves.get(&merkle_idx).copied().unwrap_or([0u8; 32]));
        let byte_idx = (bit_idx >> 3) as usize;
        leaf[byte_idx] |= 1 << (bit_idx & 7);
    }
    result
}

/// Compute the root of a 45-level sparse SHA256 Merkle tree from its non-zero leaf values.
///
/// Implements the sparse tree root algorithm: each non-zero leaf walks its path to the
/// root. At each level where the sibling subtree has a known value, the two children are
/// merged via SHA256(left || right). Where the sibling subtree is all-zero,
/// `SHA256_ZERO_HASHES[level]` substitutes.
///
/// # Returns
///
/// The 32-byte root hash, or `SHA256_ZERO_HASHES[45]` if every leaf is zero.
pub fn compute_sparse_merkle_root(leaves: &HashMap<u64, [u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return SHA256_ZERO_HASHES[TXO_MERKLE_INDEX_TOTAL_BITS];
    }

    let height = TXO_MERKLE_INDEX_TOTAL_BITS;
    let mut nodes: HashMap<(usize, u64), [u8; 32]> = HashMap::new();

    // Insert leaf values at level 0.
    for (&idx, val) in leaves {
        nodes.insert((0, idx), *val);
    }

    // Process each leaf, walking up the tree and merging at shared ancestors.
    for (&leaf_idx, leaf_val) in leaves {
        let mut current = *leaf_val;
        for level in 0..height {
            let node_idx = leaf_idx >> level;
            let sibling_node_idx = node_idx ^ 1;
            let parent_node_idx = node_idx >> 1;

            let is_left = (node_idx & 1) == 0;
            let combined = if let Some(sibling_val) = nodes.remove(&(level, sibling_node_idx)) {
                if is_left {
                    hash_impl_sha256_two_to_one_bytes(&current, &sibling_val)
                } else {
                    hash_impl_sha256_two_to_one_bytes(&sibling_val, &current)
                }
            } else {
                if is_left {
                    hash_impl_sha256_two_to_one_bytes(&current, &SHA256_ZERO_HASHES[level])
                } else {
                    hash_impl_sha256_two_to_one_bytes(&SHA256_ZERO_HASHES[level], &current)
                }
            };

            nodes.insert((level + 1, parent_node_idx), combined);
            current = combined;
        }
    }

    nodes
        .remove(&(height, 0))
        .unwrap_or(SHA256_ZERO_HASHES[height])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_update_sets_correct_bits() {
        let ci = compute_combined_index(100, 0, 0);
        let (merkle_idx, bit_idx) = decode_combined_index(ci);
        let existing = HashMap::new();
        let updates = compute_updated_leaf_values(&[ci], &existing);
        let leaf = updates.get(&merkle_idx).unwrap();
        assert_ne!(leaf, &[0u8; 32]);
        // The bit at byte_idx should be set
        let byte_idx = (bit_idx >> 3) as usize;
        assert!(leaf[byte_idx] & (1 << (bit_idx & 7)) != 0);
    }

    #[test]
    fn multiple_bits_in_same_leaf() {
        let ci1 = compute_combined_index(100, 0, 0);
        let ci2 = compute_combined_index(100, 0, 1);
        let (merkle_idx, _) = decode_combined_index(ci1);
        let existing = HashMap::new();
        let updates = compute_updated_leaf_values(&[ci1, ci2], &existing);
        let leaf = updates.get(&merkle_idx).unwrap();
        // At least two bytes different from zero
        assert!(leaf.iter().filter(|&&b| b != 0).count() >= 1);
        // At least two bits set across all bytes
        let total_bits: u32 = leaf.iter().map(|&b| b.count_ones()).sum();
        assert!(total_bits >= 2);
    }

    #[test]
    fn sparse_merkle_root_is_deterministic() {
        let ci1 = compute_combined_index(100, 0, 0);
        let ci2 = compute_combined_index(200, 0, 0);
        let existing = HashMap::new();
        let updates1 = compute_updated_leaf_values(&[ci1, ci2], &existing);
        let root1 = compute_sparse_merkle_root(&updates1);

        let updates2 = compute_updated_leaf_values(&[ci1, ci2], &existing);
        let root2 = compute_sparse_merkle_root(&updates2);
        assert_eq!(root1, root2);
    }

    #[test]
    fn empty_merkle_root_is_zero_hash() {
        let leaves = HashMap::new();
        assert_eq!(
            compute_sparse_merkle_root(&leaves),
            SHA256_ZERO_HASHES[TXO_MERKLE_INDEX_TOTAL_BITS]
        );
    }

    #[test]
    fn rebuild_from_spent_indices_matches_leaf_updates() {
        let ci1 = compute_combined_index(50, 0, 0);
        let ci2 = compute_combined_index(50, 0, 1);
        let spent = vec![ci1, ci2];
        let leaves = rebuild_merkle_leaves(&spent);
        let updates = compute_updated_leaf_values(&spent, &HashMap::new());
        assert_eq!(leaves, updates);
    }

    #[test]
    fn compute_sparse_root_from_rebuilt_leaves() {
        let ci1 = compute_combined_index(10, 0, 0);
        let ci2 = compute_combined_index(20, 1, 5);
        let spent = vec![ci1, ci2];
        let leaves = rebuild_merkle_leaves(&spent);
        let root = compute_sparse_merkle_root(&leaves);
        assert_ne!(root, SHA256_ZERO_HASHES[TXO_MERKLE_INDEX_TOTAL_BITS]);
    }
}
