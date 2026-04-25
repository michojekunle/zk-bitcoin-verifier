/// An unspent transaction output (UTXO).
#[derive(Drop, Copy)]
pub struct UTXO {
    /// The transaction ID that created this output.
    pub txid: u256,
    /// The index of this output within the creating transaction.
    pub vout: u32,
    /// Value in satoshis locked in this output.
    pub value: u64,
    /// Compressed representation of the locking scriptPubKey.
    /// Stored as a `felt252` for efficient Cairo field arithmetic.
    pub script_pubkey: felt252,
}

/// Computes a unique identifier for a transaction outpoint (txid, vout pair).
///
/// Used to index into the UTXO set and detect double-spend attempts.
///
/// # Arguments
/// * `txid` - The transaction ID.
/// * `vout` - The output index.
///
/// # Returns
/// A `u256` hash uniquely identifying this outpoint.
///
/// TODO: Serialise txid and vout, then apply sha256d.
pub fn compute_outpoint_hash(txid: u256, vout: u32) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}

/// Verifies that `pubkey` is the owner of `utxo` by checking the scriptPubKey.
///
/// Supports P2PKH and P2WPKH scripts where ownership is determined by a public
/// key hash matching `HASH160(pubkey)`.
///
/// # Arguments
/// * `utxo`   - The output to check.
/// * `pubkey` - The claimed owner's public key as a `felt252`.
///
/// # Returns
/// `true` if `pubkey` is entitled to spend `utxo`, `false` otherwise.
///
/// TODO: Hash pubkey, extract expected hash from script_pubkey, compare.
pub fn verify_utxo_ownership(utxo: UTXO, pubkey: felt252) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}
