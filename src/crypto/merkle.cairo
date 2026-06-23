use zk_bitcoin_verifier::crypto::sha256::sha256d_pair;

/// Verifies a Merkle inclusion proof.
///
/// Given a `leaf` hash, an ordered list of sibling hashes (`proof`), and the
/// expected `root`, recomputes the root by hashing up the tree and checks that
/// it matches.
///
/// Convention: at each level the current node is hashed on the **left** and
/// the sibling on the **right** — `sha256d(current ‖ sibling)`.
///
/// # Arguments
/// * `leaf`  - The double-SHA256 hash of the leaf data.
/// * `proof` - Sibling hashes from leaf level up to (but not including) root.
/// * `root`  - The expected Merkle root.
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
pub fn merkle_verify(leaf: u256, proof: Array<u256>, root: u256) -> bool {
    if proof.len() == 0 {
        return leaf == root;
    }
    let proof_span = proof.span();
    let mut current: u256 = leaf;
    let mut i: u32 = 0;
    while i < proof_span.len() {
        current = sha256d_pair(current, *proof_span.at(i));
        i += 1;
    }
    current == root
}

/// Computes the Merkle root of an ordered list of leaf hashes.
///
/// Follows Bitcoin's pairwise double-SHA256 construction; if a level has an
/// odd number of nodes the last node is duplicated before hashing.
///
/// # Arguments
/// * `leaves` - Ordered leaf hashes.
///
/// # Returns
/// The Merkle root as a `u256`, or `0` for an empty list.
pub fn merkle_root(leaves: Array<u256>) -> u256 {
    let n = leaves.len();
    if n == 0 {
        return 0_u256;
    }
    if n == 1 {
        return *leaves.at(0);
    }

    // Iteratively reduce levels until one element remains.
    let mut current: Array<u256> = leaves;
    loop {
        let len = current.len();
        if len == 1 {
            break;
        }
        let mut next: Array<u256> = array![];
        let mut i: u32 = 0;
        while i < len {
            let left = *current.at(i);
            let right = if i + 1 < len {
                *current.at(i + 1)
            } else {
                left // duplicate last element for odd-length levels
            };
            next.append(sha256d_pair(left, right));
            i += 2;
        }
        current = next;
    };
    *current.at(0)
}
