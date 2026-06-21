//! SHA-256 and double-SHA-256 (SHA-256d) hash functions.
//!
//! Pure-Cairo NIST FIPS 180-4 implementation — no StarkNet syscalls, no
//! external crates.  Works with the `cairo-test` runner.
//!
//! # Design
//!
//! * Public API accepts `Array<u8>` and returns `u256` (big-endian digest).
//! * All arithmetic is 32-bit modular using a u64 intermediary for overflow.
//! * Rotations and shifts are implemented with pow2 lookup tables (Cairo 2.17
//!   does not support `>>` / `<<` as infix operators).
//! * The K round-constant table is a 64-arm match (fully inlined by the
//!   compiler).

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Computes the SHA-256 hash of an arbitrary byte array.
///
/// # Arguments
/// * `input` - Raw bytes (arbitrary length).
///
/// # Returns
/// 256-bit digest as `u256`, big-endian byte order.
///
/// # Example
/// ```cairo
/// let h = sha256(array![0x61_u8, 0x62_u8, 0x63_u8]); // SHA-256("abc")
/// ```
pub fn sha256(input: Array<u8>) -> u256 {
    let msg_len: u32 = input.len();
    let padded = pad_message(input, msg_len);
    let num_blocks: u32 = padded.len() / 64;
    let padded_span = padded.span();

    let mut state: [u32; 8] = INITIAL_STATE;
    let mut block: u32 = 0;
    while block < num_blocks {
        state = compress(state, padded_span, block * 64);
        block += 1;
    }
    words_to_u256(state)
}

/// Computes SHA-256(SHA-256(input)) — the double-hash used throughout Bitcoin.
///
/// Used for: block header IDs, transaction IDs, Merkle tree node hashing.
///
/// # Arguments
/// * `input` - Raw bytes (arbitrary length).
///
/// # Returns
/// 256-bit double-digest as `u256`, big-endian byte order.
pub fn sha256d(input: Array<u8>) -> u256 {
    // First pass.
    let inner: u256 = sha256(input);
    // Second pass: hash the 32-byte inner digest (always one 64-byte block).
    sha256(u256_to_bytes(inner))
}

// ---------------------------------------------------------------------------
// SHA-256 initial hash values  (FIPS 180-4 §5.3.3)
// Fractional parts of the square roots of the first 8 primes.
// ---------------------------------------------------------------------------

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32, 0x510e527f_u32, 0x9b05688c_u32,
    0x1f83d9ab_u32, 0x5be0cd19_u32,
];

// ---------------------------------------------------------------------------
// Message padding  (FIPS 180-4 §5.1.1)
// ---------------------------------------------------------------------------

/// Pads a message to a multiple of 512 bits (64 bytes) per FIPS 180-4:
/// 1. Append a `0x80` byte.
/// 2. Append zero bytes until length ≡ 56 (mod 64).
/// 3. Append the original bit-length as a 64-bit big-endian integer.
fn pad_message(input: Array<u8>, msg_len: u32) -> Array<u8> {
    let mut padded: Array<u8> = input;
    padded.append(0x80_u8);

    // How many zero bytes until we reach length ≡ 56 (mod 64)?
    let after_marker: u32 = padded.len();
    let remainder: u32 = after_marker % 64;
    let zeros: u32 = if remainder <= 56 {
        56 - remainder
    } else {
        120 - remainder // 56 + 64 - remainder
    };

    let mut i: u32 = 0;
    while i < zeros {
        padded.append(0_u8);
        i += 1;
    }

    // Append 64-bit big-endian bit-length.
    // For messages up to 2^29 bytes the high 32 bits are zero.
    let bit_len: u64 = msg_len.into() * 8_u64;
    let hi: u32 = (bit_len / 0x100000000_u64).try_into().unwrap();
    let lo: u32 = (bit_len % 0x100000000_u64).try_into().unwrap();
    append_u32_be(ref padded, hi);
    append_u32_be(ref padded, lo);

    padded
}

// ---------------------------------------------------------------------------
// Compression function  (FIPS 180-4 §6.2.2)
// ---------------------------------------------------------------------------

/// Processes one 512-bit (64-byte) block starting at `offset` in `bytes`,
/// mixing it into the running hash `state`.
fn compress(state: [u32; 8], bytes: Span<u8>, offset: u32) -> [u32; 8] {
    // ── Message schedule W[0..63]
    // ─────────────────────────────────────────
    let mut w: Array<u32> = array![];
    let mut i: u32 = 0;
    // W[0..15] come directly from the block (big-endian u32 words).
    while i < 16 {
        w.append(read_u32_be(bytes, offset + i * 4));
        i += 1;
    }
    // W[16..63] are computed from earlier schedule words.
    let mut i: u32 = 16;
    while i < 64 {
        let w2 = *w.at(i - 2);
        let w7 = *w.at(i - 7);
        let w15 = *w.at(i - 15);
        let w16 = *w.at(i - 16);
        let s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ shr32(w15, 3);
        let s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ shr32(w2, 10);
        w.append(add32(add32(add32(s1, w7), s0), w16));
        i += 1;
    }

    // ── Working variables initialised from current state
    // ──────────────────
    let [h0, h1, h2, h3, h4, h5, h6, h7] = state;
    let mut a: u32 = h0;
    let mut b: u32 = h1;
    let mut c: u32 = h2;
    let mut d: u32 = h3;
    let mut e: u32 = h4;
    let mut f: u32 = h5;
    let mut g: u32 = h6;
    let mut hv: u32 = h7; // 'h' is a reserved-ish name; use 'hv'

    // ── 64 rounds
    // ─────────────────────────────────────────────────────────
    let mut i: u32 = 0;
    while i < 64 {
        let sigma1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        let ch = (e & f) ^ ((0xffffffff_u32 ^ e) & g);
        let t1 = add32(add32(add32(add32(hv, sigma1), ch), k_val(i)), *w.at(i));
        let sigma0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = add32(sigma0, maj);

        hv = g;
        g = f;
        f = e;
        e = add32(d, t1);
        d = c;
        c = b;
        b = a;
        a = add32(t1, t2);
        i += 1;
    };

    // ── Add compressed chunk to current hash value
    // ────────────────────────
    [
        add32(h0, a), add32(h1, b), add32(h2, c), add32(h3, d), add32(h4, e), add32(h5, f),
        add32(h6, g), add32(h7, hv),
    ]
}

// ---------------------------------------------------------------------------
// Arithmetic helpers
// ---------------------------------------------------------------------------

/// Adds two u32 values modulo 2^32 without panicking on overflow.
#[inline(always)]
fn add32(a: u32, b: u32) -> u32 {
    let s: u64 = a.into() + b.into();
    (s & 0xffffffff_u64).try_into().unwrap()
}

/// Right-shifts a 32-bit word by `n` positions (logical shift).
#[inline(always)]
fn shr32(x: u32, n: u32) -> u32 {
    x / pow2_u32(n)
}

/// Right-rotates a 32-bit word by `n` positions.
#[inline(always)]
fn rotr32(x: u32, n: u32) -> u32 {
    let right: u32 = x / pow2_u32(n);
    // Left part: multiply as u64, mask to 32 bits, cast back.
    let x64: u64 = x.into();
    let left: u32 = ((x64 * pow2_u64(32 - n)) & 0xffffffff_u64).try_into().unwrap();
    right | left
}

// ---------------------------------------------------------------------------
// Power-of-two lookup tables  (Cairo 2.17 has no shift operators)
// ---------------------------------------------------------------------------

/// Returns 2^n for n in 0..31.
fn pow2_u32(n: u32) -> u32 {
    match n {
        0 => 0x00000001_u32,
        1 => 0x00000002_u32,
        2 => 0x00000004_u32,
        3 => 0x00000008_u32,
        4 => 0x00000010_u32,
        5 => 0x00000020_u32,
        6 => 0x00000040_u32,
        7 => 0x00000080_u32,
        8 => 0x00000100_u32,
        9 => 0x00000200_u32,
        10 => 0x00000400_u32,
        11 => 0x00000800_u32,
        12 => 0x00001000_u32,
        13 => 0x00002000_u32,
        14 => 0x00004000_u32,
        15 => 0x00008000_u32,
        16 => 0x00010000_u32,
        17 => 0x00020000_u32,
        18 => 0x00040000_u32,
        19 => 0x00080000_u32,
        20 => 0x00100000_u32,
        21 => 0x00200000_u32,
        22 => 0x00400000_u32,
        23 => 0x00800000_u32,
        24 => 0x01000000_u32,
        25 => 0x02000000_u32,
        26 => 0x04000000_u32,
        27 => 0x08000000_u32,
        28 => 0x10000000_u32,
        29 => 0x20000000_u32,
        30 => 0x40000000_u32,
        31 => 0x80000000_u32,
        _ => 0x00000001_u32,
    }
}

/// Returns 2^n for n in 0..32 (u64, needed for left-shift in rotr32).
fn pow2_u64(n: u32) -> u64 {
    match n {
        0 => 0x0000000000000001_u64,
        1 => 0x0000000000000002_u64,
        2 => 0x0000000000000004_u64,
        3 => 0x0000000000000008_u64,
        4 => 0x0000000000000010_u64,
        5 => 0x0000000000000020_u64,
        6 => 0x0000000000000040_u64,
        7 => 0x0000000000000080_u64,
        8 => 0x0000000000000100_u64,
        9 => 0x0000000000000200_u64,
        10 => 0x0000000000000400_u64,
        11 => 0x0000000000000800_u64,
        12 => 0x0000000000001000_u64,
        13 => 0x0000000000002000_u64,
        14 => 0x0000000000004000_u64,
        15 => 0x0000000000008000_u64,
        16 => 0x0000000000010000_u64,
        17 => 0x0000000000020000_u64,
        18 => 0x0000000000040000_u64,
        19 => 0x0000000000080000_u64,
        20 => 0x0000000000100000_u64,
        21 => 0x0000000000200000_u64,
        22 => 0x0000000000400000_u64,
        23 => 0x0000000000800000_u64,
        24 => 0x0000000001000000_u64,
        25 => 0x0000000002000000_u64,
        26 => 0x0000000004000000_u64,
        27 => 0x0000000008000000_u64,
        28 => 0x0000000010000000_u64,
        29 => 0x0000000020000000_u64,
        30 => 0x0000000040000000_u64,
        31 => 0x0000000080000000_u64,
        32 => 0x0000000100000000_u64,
        _ => 0x0000000000000001_u64,
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Reads a big-endian `u32` from four consecutive bytes at `offset`.
#[inline(always)]
fn read_u32_be(bytes: Span<u8>, offset: u32) -> u32 {
    (*bytes.at(offset)).into() * 0x1000000_u32
        + (*bytes.at(offset + 1)).into() * 0x10000_u32
        + (*bytes.at(offset + 2)).into() * 0x100_u32
        + (*bytes.at(offset + 3)).into()
}

/// Appends a `u32` as four big-endian bytes.
#[inline(always)]
fn append_u32_be(ref arr: Array<u8>, val: u32) {
    arr.append(((val / 0x1000000_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x10000_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x100_u32) & 0xff_u32).try_into().unwrap());
    arr.append((val & 0xff_u32).try_into().unwrap());
}

/// Hashes the concatenation of two 32-byte values with SHA-256d.
/// Used by the Merkle tree implementation.
pub fn sha256d_pair(left: u256, right: u256) -> u256 {
    let mut bytes: Array<u8> = u256_to_bytes(left);
    let right_bytes = u256_to_bytes(right);
    let mut i: u32 = 0;
    while i < right_bytes.len() {
        bytes.append(*right_bytes.at(i));
        i += 1;
    }
    sha256d(bytes)
}

/// Converts a `u256` to its 32-byte big-endian representation.
pub fn u256_to_bytes(val: u256) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    // High 128 bits → 16 bytes.
    append_u128_be(ref bytes, val.high);
    // Low 128 bits → 16 bytes.
    append_u128_be(ref bytes, val.low);
    bytes
}

/// Appends a `u128` as 16 big-endian bytes, splitting via two u64 halves.
fn append_u128_be(ref arr: Array<u8>, val: u128) {
    let hi: u64 = (val / 0x10000000000000000_u128).try_into().unwrap();
    let lo: u64 = (val % 0x10000000000000000_u128).try_into().unwrap();
    append_u64_be(ref arr, hi);
    append_u64_be(ref arr, lo);
}

/// Appends a `u64` as 8 big-endian bytes.
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

/// Packs 8 × u32 SHA-256 output words into a big-endian `u256`.
///
/// Layout:  `high = w0‖w1‖w2‖w3`  (bits 255..128)
///          `low  = w4‖w5‖w6‖w7`  (bits 127..0)
fn words_to_u256(words: [u32; 8]) -> u256 {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = words;
    let high: u128 = w0.into() * 0x1000000000000000000000000_u128
        + w1.into() * 0x10000000000000000_u128
        + w2.into() * 0x100000000_u128
        + w3.into();
    let low: u128 = w4.into() * 0x1000000000000000000000000_u128
        + w5.into() * 0x10000000000000000_u128
        + w6.into() * 0x100000000_u128
        + w7.into();
    u256 { high, low }
}

// ---------------------------------------------------------------------------
// SHA-256 round constants  (FIPS 180-4 §4.2.2)
// Fractional parts of the cube roots of the first 64 primes.
// ---------------------------------------------------------------------------

fn k_val(i: u32) -> u32 {
    match i {
        0 => 0x428a2f98_u32,
        1 => 0x71374491_u32,
        2 => 0xb5c0fbcf_u32,
        3 => 0xe9b5dba5_u32,
        4 => 0x3956c25b_u32,
        5 => 0x59f111f1_u32,
        6 => 0x923f82a4_u32,
        7 => 0xab1c5ed5_u32,
        8 => 0xd807aa98_u32,
        9 => 0x12835b01_u32,
        10 => 0x243185be_u32,
        11 => 0x550c7dc3_u32,
        12 => 0x72be5d74_u32,
        13 => 0x80deb1fe_u32,
        14 => 0x9bdc06a7_u32,
        15 => 0xc19bf174_u32,
        16 => 0xe49b69c1_u32,
        17 => 0xefbe4786_u32,
        18 => 0x0fc19dc6_u32,
        19 => 0x240ca1cc_u32,
        20 => 0x2de92c6f_u32,
        21 => 0x4a7484aa_u32,
        22 => 0x5cb0a9dc_u32,
        23 => 0x76f988da_u32,
        24 => 0x983e5152_u32,
        25 => 0xa831c66d_u32,
        26 => 0xb00327c8_u32,
        27 => 0xbf597fc7_u32,
        28 => 0xc6e00bf3_u32,
        29 => 0xd5a79147_u32,
        30 => 0x06ca6351_u32,
        31 => 0x14292967_u32,
        32 => 0x27b70a85_u32,
        33 => 0x2e1b2138_u32,
        34 => 0x4d2c6dfc_u32,
        35 => 0x53380d13_u32,
        36 => 0x650a7354_u32,
        37 => 0x766a0abb_u32,
        38 => 0x81c2c92e_u32,
        39 => 0x92722c85_u32,
        40 => 0xa2bfe8a1_u32,
        41 => 0xa81a664b_u32,
        42 => 0xc24b8b70_u32,
        43 => 0xc76c51a3_u32,
        44 => 0xd192e819_u32,
        45 => 0xd6990624_u32,
        46 => 0xf40e3585_u32,
        47 => 0x106aa070_u32,
        48 => 0x19a4c116_u32,
        49 => 0x1e376c08_u32,
        50 => 0x2748774c_u32,
        51 => 0x34b0bcb5_u32,
        52 => 0x391c0cb3_u32,
        53 => 0x4ed8aa4a_u32,
        54 => 0x5b9cca4f_u32,
        55 => 0x682e6ff3_u32,
        56 => 0x748f82ee_u32,
        57 => 0x78a5636f_u32,
        58 => 0x84c87814_u32,
        59 => 0x8cc70208_u32,
        60 => 0x90befffa_u32,
        61 => 0xa4506ceb_u32,
        62 => 0xbef9a3f7_u32,
        63 => 0xc67178f2_u32,
        _ => 0_u32,
    }
}
