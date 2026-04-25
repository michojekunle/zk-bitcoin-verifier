/// Verifies a Merkle inclusion proof.
///
/// Given a `leaf` hash, a sibling `proof` path, and the expected `root`, this function
/// recomputes the root by hashing up the tree and checks it matches.
///
/// # Arguments
/// * `leaf`  - The double-SHA256 hash of the leaf data.
/// * `proof` - Ordered list of sibling hashes from leaf to root.
/// * `root`  - The expected Merkle root.
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
///
/// TODO: Hash each pair with sha256d, respecting Bitcoin's left/right ordering convention.
pub fn merkle_verify(leaf: u256, proof: Array<u256>, root: u256) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}

/// Computes the Merkle root of a list of leaves.
///
/// Follows Bitcoin's pairwise double-SHA256 construction; odd-length levels
/// duplicate the last element before hashing.
///
/// # Arguments
/// * `leaves` - The ordered list of leaf hashes (double-SHA256 of serialised txids).
///
/// # Returns
/// The Merkle root as a `u256`. Returns `0` for an empty list.
///
/// TODO: Implement the iterative pairing loop using sha256d.
pub fn merkle_root(leaves: Array<u256>) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}
