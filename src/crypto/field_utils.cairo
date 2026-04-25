/// Converts a `u32` value to a `felt252` field element.
///
/// This is lossless because felt252 can represent all u32 values.
pub fn u32_to_felt252(val: u32) -> felt252 {
    val.into()
}

/// Interprets a big-endian byte array as a `u256`.
///
/// # Arguments
/// * `bytes` - Up to 32 bytes, big-endian.
///
/// # Returns
/// The corresponding `u256` value. Returns `0` for an empty array.
///
/// TODO: Accumulate each byte into the result with the correct bit shift.
pub fn bytes_to_u256(bytes: Array<u8>) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}

/// Reverses the byte order of a 256-bit value.
///
/// Bitcoin internally stores hashes and other 32-byte fields in little-endian
/// byte order when serialised on the wire, while Cairo operates big-endian.
/// This helper converts between the two representations.
///
/// # Arguments
/// * `val` - The `u256` to byte-reverse.
///
/// # Returns
/// A new `u256` whose byte representation is the mirror of `val`'s.
///
/// TODO: Implement 32-byte swap using bitmask decomposition or a loop.
pub fn reverse_bytes32(val: u256) -> u256 {
    // STUB: returns the input unchanged until implementation is complete.
    val
}
