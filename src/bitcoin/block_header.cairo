use zk_bitcoin_verifier::crypto::field_utils::reverse_bytes32;
use zk_bitcoin_verifier::crypto::sha256::sha256d;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// An 80-byte Bitcoin block header.
#[derive(Drop, Copy)]
pub struct BlockHeader {
    /// Block version number (signals soft-fork readiness).
    pub version: u32,
    /// Double-SHA256 of the previous block's header (display / big-endian form).
    pub prev_block_hash: u256,
    /// Merkle root of all transactions in this block (display / big-endian form).
    pub merkle_root: u256,
    /// Unix timestamp of when the miner started hashing this header.
    pub timestamp: u32,
    /// Compact representation of the current network difficulty target.
    pub bits: u32,
    /// The nonce miners iterate to satisfy the proof-of-work requirement.
    pub nonce: u32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Deserialises an 80-byte little-endian byte array into a BlockHeader.
///
/// Fields are stored in their display (big-endian / reversed) form so that
/// prev_block_hash and merkle_root match block-explorer output.
pub fn parse_block_header(raw_bytes: Array<u8>) -> BlockHeader {
    let s = raw_bytes.span();
    BlockHeader {
        version: read_u32_le(s, 0),
        prev_block_hash: read_u256_le(s, 4),
        merkle_root: read_u256_le(s, 36),
        timestamp: read_u32_le(s, 68),
        bits: read_u32_le(s, 72),
        nonce: read_u32_le(s, 76),
    }
}

/// Decodes the compact bits field into a 256-bit difficulty target.
///
/// Format: high byte = exponent e, lower 3 bytes = mantissa m.
/// target = m * 256^(e - 3)
pub fn bits_to_target(bits: u32) -> u256 {
    if bits == 0 {
        return 0_u256;
    }
    let exponent: u32 = bits / 0x1000000_u32;
    let mantissa: u256 = (bits & 0x00ffffff_u32).into();
    if mantissa == 0_u256 {
        return 0_u256;
    }
    if exponent < 3 {
        mantissa / pow256(3 - exponent)
    } else {
        mantissa * pow256(exponent - 3)
    }
}

/// Checks that double-SHA256(serialised header) is at or below the target
/// encoded in header.bits.
pub fn verify_block_hash(header: BlockHeader) -> bool {
    let raw = serialize_header(header);
    let hash_raw: u256 = sha256d(raw);
    // Bitcoin PoW comparison interprets the hash bytes as a little-endian
    // integer, which equals the byte-reversed big-endian u256.
    let hash_le: u256 = reverse_bytes32(hash_raw);
    let target: u256 = bits_to_target(header.bits);
    hash_le <= target
}

/// Verifies that the bits field encodes a plausible difficulty target.
///
/// Rejects zero targets, negative mantissa, and exponents beyond 34.
pub fn verify_block_difficulty(header: BlockHeader) -> bool {
    let bits = header.bits;
    if bits == 0 {
        return false;
    }
    let exponent: u32 = bits / 0x1000000_u32;
    let mantissa: u32 = bits & 0x00ffffff_u32;
    if mantissa == 0 {
        return false;
    }
    if (mantissa & 0x800000_u32) != 0 {
        return false; // negative target
    }
    exponent <= 34_u32
}

/// Performs all validity checks on a block header.
pub fn verify_block_header(header: BlockHeader) -> bool {
    verify_block_difficulty(header) && verify_block_hash(header)
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

fn serialize_header(header: BlockHeader) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    append_u32_le(ref bytes, header.version);
    append_u256_le(ref bytes, header.prev_block_hash);
    append_u256_le(ref bytes, header.merkle_root);
    append_u32_le(ref bytes, header.timestamp);
    append_u32_le(ref bytes, header.bits);
    append_u32_le(ref bytes, header.nonce);
    bytes
}

fn append_u32_le(ref arr: Array<u8>, val: u32) {
    arr.append((val & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x100_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x10000_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x1000000_u32) & 0xff_u32).try_into().unwrap());
}

fn append_u256_le(ref arr: Array<u8>, val: u256) {
    // Display (BE) to wire (LE): reverse all bytes.
    let reversed = reverse_bytes32(val);
    append_u128_be(ref arr, reversed.high);
    append_u128_be(ref arr, reversed.low);
}

fn append_u128_be(ref arr: Array<u8>, val: u128) {
    let hi: u64 = (val / 0x10000000000000000_u128).try_into().unwrap();
    let lo: u64 = (val % 0x10000000000000000_u128).try_into().unwrap();
    append_u64_be(ref arr, hi);
    append_u64_be(ref arr, lo);
}

fn append_u64_be(ref arr: Array<u8>, val: u64) {
    arr.append(((val / 0x100000000000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x1000000000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x10000000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x100000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x1000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x10000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x100_u64) & 0xff_u64).try_into().unwrap());
    arr.append((val & 0xff_u64).try_into().unwrap());
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn read_u32_le(bytes: Span<u8>, offset: u32) -> u32 {
    (*bytes.at(offset)).into()
        + (*bytes.at(offset + 1)).into() * 0x100_u32
        + (*bytes.at(offset + 2)).into() * 0x10000_u32
        + (*bytes.at(offset + 3)).into() * 0x1000000_u32
}

fn read_u256_le(bytes: Span<u8>, offset: u32) -> u256 {
    // Read 32 LE wire bytes, reverse to get display (BE) u256.
    let mut wire: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 32 {
        wire.append(*bytes.at(offset + i));
        i += 1;
    }
    let reversed = reverse_u8_array(wire);
    bytes_be_to_u256(reversed.span())
}

fn reverse_u8_array(arr: Array<u8>) -> Array<u8> {
    let len = arr.len();
    let mut out: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < len {
        out.append(*arr.at(len - 1 - i));
        i += 1;
    }
    out
}

fn bytes_be_to_u256(bytes: Span<u8>) -> u256 {
    let mut high: u128 = 0_u128;
    let mut low: u128 = 0_u128;
    let mut i: u32 = 0;
    while i < 16 {
        high = high * 256_u128 + (*bytes.at(i)).into();
        i += 1;
    }
    let mut i: u32 = 16;
    while i < 32 {
        low = low * 256_u128 + (*bytes.at(i)).into();
        i += 1;
    }
    u256 { high, low }
}

// ---------------------------------------------------------------------------
// bits_to_target: power-of-256 lookup (256^n for n in 0..29)
// ---------------------------------------------------------------------------

fn pow256(n: u32) -> u256 {
    match n {
        0 => 0x1_u256,
        1 => 0x100_u256,
        2 => 0x10000_u256,
        3 => 0x1000000_u256,
        4 => 0x100000000_u256,
        5 => 0x10000000000_u256,
        6 => 0x1000000000000_u256,
        7 => 0x100000000000000_u256,
        8 => 0x10000000000000000_u256,
        9 => 0x1000000000000000000_u256,
        10 => 0x100000000000000000000_u256,
        11 => 0x10000000000000000000000_u256,
        12 => 0x1000000000000000000000000_u256,
        13 => 0x100000000000000000000000000_u256,
        14 => 0x10000000000000000000000000000_u256,
        15 => 0x1000000000000000000000000000000_u256,
        16 => 0x100000000000000000000000000000000_u256,
        17 => 0x10000000000000000000000000000000000_u256,
        18 => 0x1000000000000000000000000000000000000_u256,
        19 => 0x100000000000000000000000000000000000000_u256,
        20 => 0x10000000000000000000000000000000000000000_u256,
        21 => 0x1000000000000000000000000000000000000000000_u256,
        22 => 0x100000000000000000000000000000000000000000000_u256,
        23 => 0x10000000000000000000000000000000000000000000000_u256,
        24 => 0x1000000000000000000000000000000000000000000000000_u256,
        25 => 0x100000000000000000000000000000000000000000000000000_u256,
        26 => 0x10000000000000000000000000000000000000000000000000000_u256,
        27 => 0x1000000000000000000000000000000000000000000000000000000_u256,
        28 => 0x100000000000000000000000000000000000000000000000000000000_u256,
        29 => 0x10000000000000000000000000000000000000000000000000000000000_u256,
        _ => 0x1_u256,
    }
}
