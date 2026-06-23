/// Converts a `u32` value to a `felt252` field element.
///
/// This is lossless because felt252 can represent all u32 values.
pub fn u32_to_felt252(val: u32) -> felt252 {
    val.into()
}

/// Interprets a big-endian byte array (up to 32 bytes) as a `u256`.
pub fn bytes_to_u256(bytes: Array<u8>) -> u256 {
    let s = bytes.span();
    let len = s.len();
    let mut high: u128 = 0_u128;
    let mut low: u128 = 0_u128;
    let mut i: u32 = 0;
    while i < len {
        let byte: u128 = (*s.at(i)).into();
        if i < 16 {
            high = high * 256_u128 + byte;
        } else {
            low = low * 256_u128 + byte;
        }
        i += 1;
    }
    u256 { high, low }
}

// ---------------------------------------------------------------------------
// Byte-reversal helpers  (needed for Bitcoin's little-endian wire encoding)
// ---------------------------------------------------------------------------

/// Reverses the 8 bytes of a `u64`.
pub fn reverse_bytes8(val: u64) -> u64 {
    let b0: u64 = val & 0xff_u64;
    let b1: u64 = (val / 0x100_u64) & 0xff_u64;
    let b2: u64 = (val / 0x10000_u64) & 0xff_u64;
    let b3: u64 = (val / 0x1000000_u64) & 0xff_u64;
    let b4: u64 = (val / 0x100000000_u64) & 0xff_u64;
    let b5: u64 = (val / 0x10000000000_u64) & 0xff_u64;
    let b6: u64 = (val / 0x1000000000000_u64) & 0xff_u64;
    let b7: u64 = (val / 0x100000000000000_u64) & 0xff_u64;
    b0 * 0x100000000000000_u64
        + b1 * 0x1000000000000_u64
        + b2 * 0x10000000000_u64
        + b3 * 0x100000000_u64
        + b4 * 0x1000000_u64
        + b5 * 0x10000_u64
        + b6 * 0x100_u64
        + b7
}

/// Reverses the 16 bytes of a `u128`.
pub fn reverse_bytes16(val: u128) -> u128 {
    let hi: u64 = (val / 0x10000000000000000_u128).try_into().unwrap();
    let lo: u64 = (val % 0x10000000000000000_u128).try_into().unwrap();
    reverse_bytes8(lo).into() * 0x10000000000000000_u128 + reverse_bytes8(hi).into()
}

/// Reverses the byte order of a 32-byte `u256`.
///
/// Bitcoin serialises hashes and other 32-byte fields in little-endian order
/// on the wire, while this library's `u256` representation is big-endian.
/// Use this function to convert between the two.
pub fn reverse_bytes32(val: u256) -> u256 {
    u256 { high: reverse_bytes16(val.low), low: reverse_bytes16(val.high) }
}
