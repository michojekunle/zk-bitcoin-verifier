/// Computes the SHA-256 hash of the given byte array.
///
/// # Arguments
/// * `input` - Raw bytes to hash.
///
/// # Returns
/// A `u256` representing the 256-bit digest.
///
/// TODO: Implement using the SHA-256 compression function over 512-bit blocks.
pub fn sha256(input: Array<u8>) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}

/// Computes SHA-256(SHA-256(input)), the double-hash used throughout Bitcoin.
///
/// # Arguments
/// * `input` - Raw bytes to hash.
///
/// # Returns
/// A `u256` representing the double-SHA-256 digest.
///
/// TODO: Chain two calls to `sha256` once the single-round implementation is done.
pub fn sha256d(input: Array<u8>) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}
