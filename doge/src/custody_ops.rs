//! Tracked custody UTXO computation helpers for the bridge withdrawal operator.
//!
//! This module provides pure functions for computing combined TXO indices,
//! sparse Merkle tree leaf updates, and spent-root computation. It does NOT
//! manage its own SQLite connection — UTXO lifecycle is handled by
//! `doge_bridge_client::operator_store::OperatorStore`.

use anyhow::{bail, Result};
use psy_bridge_core::crypto::hash::sha256::SHA256_ZERO_HASHES;
use psy_bridge_core::crypto::hash::sha256_impl::{
    hash_impl_btc_hash256_two_to_one_bytes, hash_impl_sha256_two_to_one_bytes,
};
use psy_bridge_core::txo_constants::TXO_MERKLE_INDEX_TOTAL_BITS;
use psy_bridge_core::txo_constants::{
    get_txo_block_number_tx_number_output_index_from_combined_index, get_txo_combined_index,
    get_txo_merkle_index_and_leaf_bit_index_from_combined_index,
};
use std::collections::{HashMap, HashSet};

/// Compute a combined TXO index from a Dogecoin transaction's on-chain position.
pub fn compute_combined_index(block_height: u32, tx_index_in_block: u16, vout: u16) -> u64 {
    get_txo_combined_index(block_height, tx_index_in_block, vout)
}

/// Derive the (merkle_index, bit_index) from a combined index.
pub fn decode_combined_index(combined_index: u64) -> (u64, u8) {
    get_txo_merkle_index_and_leaf_bit_index_from_combined_index(combined_index)
}

/// Recover the Dogecoin position encoded in a combined TXO index.
pub fn decode_combined_position(combined_index: u64) -> (u32, u16, u16) {
    get_txo_block_number_tx_number_output_index_from_combined_index(combined_index)
}

/// One sequential 45-level spent-TXO membership/update proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentTxoProof {
    pub old_leaf: [u8; 32],
    pub bit_index: u8,
    pub merkle_index: u64,
    pub siblings: [[u8; 32]; TXO_MERKLE_INDEX_TOTAL_BITS],
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

/// A 32-level membership proof for the requested-withdrawal append tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedMerkleProof {
    pub index: u64,
    pub siblings: [[u8; 32]; 32],
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
        let leaf = result.entry(merkle_idx).or_insert_with(|| {
            existing_leaves
                .get(&merkle_idx)
                .copied()
                .unwrap_or([0u8; 32])
        });
        let byte_idx = (bit_idx >> 3) as usize;
        leaf[byte_idx] |= 1 << (bit_idx & 7);
    }
    result
}

/// Build spent-TXO witnesses in input order. Each proof starts at the root
/// produced by the preceding proof, which is required when one withdrawal has
/// multiple custody inputs (including multiple bits in the same leaf).
pub fn build_sequential_spent_txo_proofs(
    existing_leaves: &HashMap<u64, [u8; 32]>,
    combined_indices: &[u64],
) -> Result<(Vec<SpentTxoProof>, HashMap<u64, [u8; 32]>)> {
    let mut leaves = existing_leaves.clone();
    let mut proofs = Vec::with_capacity(combined_indices.len());

    for &combined_index in combined_indices {
        let (merkle_index, bit_index) = decode_combined_index(combined_index);
        let old_leaf = leaves.get(&merkle_index).copied().unwrap_or([0u8; 32]);
        let byte_index = usize::from(bit_index >> 3);
        let bit_mask = 1u8 << (bit_index & 7);
        if old_leaf[byte_index] & bit_mask != 0 {
            bail!("custody TXO combined index {combined_index} is already spent");
        }

        let levels = build_sparse_levels(&leaves, TXO_MERKLE_INDEX_TOTAL_BITS);
        let siblings = std::array::from_fn(|level| {
            levels[level]
                .get(&((merkle_index >> level) ^ 1))
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[level])
        });
        let old_root = merkle_root_from_proof(old_leaf, merkle_index, &siblings);
        let expected_old_root = levels[TXO_MERKLE_INDEX_TOTAL_BITS]
            .get(&0)
            .copied()
            .unwrap_or(SHA256_ZERO_HASHES[TXO_MERKLE_INDEX_TOTAL_BITS]);
        if old_root != expected_old_root {
            bail!("constructed spent-TXO proof does not match the current root");
        }

        let mut new_leaf = old_leaf;
        new_leaf[byte_index] |= bit_mask;
        let new_root = merkle_root_from_proof(new_leaf, merkle_index, &siblings);
        leaves.insert(merkle_index, new_leaf);
        if compute_sparse_merkle_root(&leaves) != new_root {
            bail!("sequential spent-TXO update produced an inconsistent root");
        }
        proofs.push(SpentTxoProof {
            old_leaf,
            bit_index,
            merkle_index,
            siblings,
            old_root,
            new_root,
        });
    }

    Ok((proofs, leaves))
}

/// Build 32-level membership proofs for selected leaves of the withdrawal
/// append tree and return the reconstructed root.
pub fn build_fixed_merkle_proofs(
    leaves: &[[u8; 32]],
    indices: &[u64],
) -> Result<([u8; 32], Vec<FixedMerkleProof>)> {
    if leaves.len() > u32::MAX as usize {
        bail!("requested-withdrawal tree exceeds its 32-level capacity");
    }
    let leaf_map = leaves
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, value)| *value != [0u8; 32])
        .map(|(index, value)| (index as u64, value))
        .collect::<HashMap<_, _>>();
    let levels = build_sparse_levels(&leaf_map, 32);
    let root = levels[32]
        .get(&0)
        .copied()
        .unwrap_or(SHA256_ZERO_HASHES[32]);
    let mut proofs = Vec::with_capacity(indices.len());
    for &index in indices {
        if index >= leaves.len() as u64 {
            bail!("withdrawal request proof index {index} is outside the reconstructed tree");
        }
        let siblings = std::array::from_fn(|level| {
            levels[level]
                .get(&((index >> level) ^ 1))
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[level])
        });
        if merkle_root_from_proof(leaves[index as usize], index, &siblings) != root {
            bail!("constructed withdrawal request proof does not match the tree root");
        }
        proofs.push(FixedMerkleProof { index, siblings });
    }
    Ok((root, proofs))
}

/// Construct the Bitcoin/Dogecoin transaction Merkle branch for `target_index`.
/// Hashes and the returned root use internal byte order.
pub fn build_transaction_merkle_branch(
    txids: &[[u8; 32]],
    target_index: usize,
) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    if txids.is_empty() {
        bail!("cannot build a transaction Merkle branch for an empty block");
    }
    if target_index >= txids.len() {
        bail!("transaction index {target_index} is outside block transaction list");
    }

    let mut level = txids.to_vec();
    let mut index = target_index;
    let mut branch = Vec::new();
    while level.len() > 1 {
        let sibling_index = if index ^ 1 < level.len() {
            index ^ 1
        } else {
            index
        };
        branch.push(level[sibling_index]);

        let mut parents = Vec::with_capacity((level.len() + 1) / 2);
        for pair_start in (0..level.len()).step_by(2) {
            let left = level[pair_start];
            let right = level.get(pair_start + 1).copied().unwrap_or(left);
            parents.push(hash_impl_btc_hash256_two_to_one_bytes(&left, &right));
        }
        level = parents;
        index >>= 1;
    }
    Ok((level[0], branch))
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
    build_sparse_levels(leaves, TXO_MERKLE_INDEX_TOTAL_BITS)[TXO_MERKLE_INDEX_TOTAL_BITS]
        .get(&0)
        .copied()
        .unwrap_or(SHA256_ZERO_HASHES[TXO_MERKLE_INDEX_TOTAL_BITS])
}

fn build_sparse_levels(
    leaves: &HashMap<u64, [u8; 32]>,
    height: usize,
) -> Vec<HashMap<u64, [u8; 32]>> {
    let mut levels: Vec<HashMap<u64, [u8; 32]>> = Vec::with_capacity(height + 1);
    levels.push(
        leaves
            .iter()
            .filter(|(_, value)| **value != SHA256_ZERO_HASHES[0])
            .map(|(&index, &value)| (index, value))
            .collect(),
    );
    for level in 0..height {
        let current = &levels[level];
        let parent_indices = current
            .keys()
            .map(|index| index >> 1)
            .collect::<HashSet<_>>();
        let mut parents = HashMap::with_capacity(parent_indices.len());
        for parent_index in parent_indices {
            let left = current
                .get(&(parent_index << 1))
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[level]);
            let right = current
                .get(&((parent_index << 1) | 1))
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[level]);
            let parent = hash_impl_sha256_two_to_one_bytes(&left, &right);
            if parent != SHA256_ZERO_HASHES[level + 1] {
                parents.insert(parent_index, parent);
            }
        }
        levels.push(parents);
    }
    levels
}

fn merkle_root_from_proof(mut value: [u8; 32], mut index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    for sibling in siblings {
        value = if index & 1 == 0 {
            hash_impl_sha256_two_to_one_bytes(&value, sibling)
        } else {
            hash_impl_sha256_two_to_one_bytes(sibling, &value)
        };
        index >>= 1;
    }
    value
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

    #[test]
    fn sequential_multi_input_proofs_chain_roots() {
        let first = compute_combined_index(100, 3, 2);
        let second = compute_combined_index(100, 3, 3);
        let third = compute_combined_index(101, 4, 1);
        let (proofs, leaves) =
            build_sequential_spent_txo_proofs(&HashMap::new(), &[first, second, third]).unwrap();
        assert_eq!(proofs.len(), 3);
        assert_eq!(proofs[0].new_root, proofs[1].old_root);
        assert_eq!(proofs[1].new_root, proofs[2].old_root);
        assert_eq!(proofs[2].new_root, compute_sparse_merkle_root(&leaves));
        assert_eq!(proofs[1].old_leaf, {
            let mut leaf = [0u8; 32];
            let (_, bit) = decode_combined_index(first);
            leaf[usize::from(bit >> 3)] |= 1 << (bit & 7);
            leaf
        });
    }

    #[test]
    fn fixed_request_membership_proof_matches_root() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let (root, proofs) = build_fixed_merkle_proofs(&leaves, &[1]).unwrap();
        assert_eq!(proofs[0].index, 1);
        assert_eq!(
            merkle_root_from_proof(leaves[1], 1, &proofs[0].siblings),
            root
        );
    }

    #[test]
    fn transaction_merkle_branch_duplicates_odd_tail() {
        let txids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (root, branch) = build_transaction_merkle_branch(&txids, 2).unwrap();
        assert_eq!(branch[0], txids[2]);
        let lower = hash_impl_btc_hash256_two_to_one_bytes(&txids[2], &txids[2]);
        let left = hash_impl_btc_hash256_two_to_one_bytes(&txids[0], &txids[1]);
        assert_eq!(root, hash_impl_btc_hash256_two_to_one_bytes(&left, &lower));
    }
}
