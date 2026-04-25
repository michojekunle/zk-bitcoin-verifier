/// Validates a Pay-to-Public-Key-Hash (P2PKH) locking script.
///
/// A valid P2PKH scriptPubKey has the form:
///   OP_DUP OP_HASH160 <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
///
/// # Arguments
/// * `script`      - The raw scriptPubKey bytes.
/// * `pubkey_hash` - The expected HASH160 of the spending public key (right-aligned in u256).
///
/// # Returns
/// `true` if the script matches the P2PKH template and the pubkey hash matches.
///
/// TODO: Decode opcodes, extract embedded hash, compare to pubkey_hash.
pub fn validate_p2pkh_script(script: Array<u8>, pubkey_hash: u256) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}

/// Validates a Pay-to-Script-Hash (P2SH) locking script.
///
/// A valid P2SH scriptPubKey has the form:
///   OP_HASH160 <20-byte script hash> OP_EQUAL
///
/// # Arguments
/// * `script`             - The raw scriptPubKey bytes.
/// * `redeem_script_hash` - The expected HASH160 of the redeem script (right-aligned in u256).
///
/// # Returns
/// `true` if the script matches the P2SH template and the script hash matches.
///
/// TODO: Decode opcodes, extract embedded hash, compare to redeem_script_hash.
pub fn validate_p2sh_script(script: Array<u8>, redeem_script_hash: u256) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}

/// Validates a Pay-to-Witness-Public-Key-Hash (P2WPKH) locking script.
///
/// A valid P2WPKH scriptPubKey has the form:
///   OP_0 <20-byte pubkey hash>
///
/// # Arguments
/// * `script`      - The raw scriptPubKey bytes (22 bytes total for P2WPKH).
/// * `pubkey_hash` - The expected witness program (right-aligned in u256).
///
/// # Returns
/// `true` if the script is a well-formed P2WPKH output and the hash matches.
///
/// TODO: Check length (22 bytes), verify OP_0 prefix, compare embedded hash.
pub fn validate_p2wpkh_script(script: Array<u8>, pubkey_hash: u256) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}
