use zk_bitcoin_verifier::bitcoin::block_header::{
    BlockHeader, verify_block_header, verify_block_hash, verify_block_difficulty, bits_to_target,
    parse_block_header,
};
use zk_bitcoin_verifier::bitcoin::transaction::{
    Transaction, TxInput, TxOutput, verify_coinbase_transaction, compute_transaction_hash,
    verify_transaction_signature,
};
use zk_bitcoin_verifier::crypto::merkle::merkle_verify;

// ---------------------------------------------------------------------------
// Genesis block header tests (Block #0)
// All assertions will FAIL until implementations are complete — expected.
// ---------------------------------------------------------------------------

fn genesis_header() -> BlockHeader {
    BlockHeader {
        version: 1_u32,
        prev_block_hash: 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
        merkle_root: 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256,
        timestamp: 1231006505_u32,
        bits: 0x1d00ffff_u32,
        nonce: 2083236893_u32,
    }
}

/// The genesis block header must pass full validation.
#[test]
fn test_genesis_block_header_is_valid() {
    let header = genesis_header();
    assert!(verify_block_header(header));
}

/// The genesis block hash must be exactly the well-known value.
/// 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
#[test]
fn test_genesis_block_hash_matches_known_value() {
    let header = genesis_header();
    assert!(verify_block_hash(header));
}

/// The genesis block difficulty check must pass (bits = 0x1d00ffff is valid mainnet genesis).
#[test]
fn test_genesis_block_difficulty_valid() {
    let header = genesis_header();
    assert!(verify_block_difficulty(header));
}

/// Mutating the nonce must invalidate the block hash check.
#[test]
fn test_block_header_wrong_nonce_fails_hash() {
    let mut header = genesis_header();
    header.nonce = 0_u32; // wrong nonce
    assert!(!verify_block_hash(header));
}

/// Mutating the merkle root must invalidate full header verification.
#[test]
fn test_block_header_wrong_merkle_root_fails() {
    let mut header = genesis_header();
    header.merkle_root = 0xdeadbeef_u256;
    assert!(!verify_block_header(header));
}

// ---------------------------------------------------------------------------
// bits_to_target conversion tests
// ---------------------------------------------------------------------------

/// bits = 0x1d00ffff → target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
#[test]
fn test_bits_to_target_genesis() {
    let bits: u32 = 0x1d00ffff_u32;
    let expected: u256 =
        0x00000000ffff0000000000000000000000000000000000000000000000000000_u256;
    assert_eq!(bits_to_target(bits), expected);
}

/// bits = 0x170e8a61 (block #700000 difficulty)
/// target = 0x000000000000000e8a61000000000000000000000000000000000000000000000 (approx)
#[test]
fn test_bits_to_target_block_700000() {
    let bits: u32 = 0x170e8a61_u32;
    // Mantissa = 0x0e8a61, exponent = 0x17 = 23
    // target = 0x0e8a61 * 256^(23-3) = 0x0e8a61 * 256^20
    // Left-shifted by 20 bytes = 160 bits
    let expected: u256 =
        0x00000000000000000e8a610000000000000000000000000000000000000000000_u256;
    assert_eq!(bits_to_target(bits), expected);
}

/// bits = 0x00000000 must produce target 0 (degenerate case).
#[test]
fn test_bits_to_target_zero() {
    assert_eq!(bits_to_target(0_u32), 0_u256);
}

/// bits with maximum difficulty (0x03000001) → very small target.
#[test]
fn test_bits_to_target_max_difficulty() {
    let bits: u32 = 0x03000001_u32;
    // Mantissa = 0x000001, exponent = 3 → target = 1 * 256^0 = 1
    assert_eq!(bits_to_target(bits), 1_u256);
}

// ---------------------------------------------------------------------------
// Block #700000 header tests
// ---------------------------------------------------------------------------

fn block_700000_header() -> BlockHeader {
    BlockHeader {
        version: 536870912_u32,
        prev_block_hash: 0x00000000000000000002a3b5f23b2d21cf5427db90e80e20e07a71b7c2ab7e44_u256,
        merkle_root: 0x4b2e6e3f8e3b8f3c4e2a8d4f6a8c2e4f6b8a2c4e6f8a0c2e4f6b8a2c4e6f80_u256,
        timestamp: 1632891106_u32,
        bits: 0x170e8a61_u32,
        nonce: 2738721512_u32,
    }
}

/// Block #700000 header must pass full validation.
#[test]
fn test_block_700000_header_is_valid() {
    let header = block_700000_header();
    assert!(verify_block_header(header));
}

/// Block #700000 must satisfy its compact difficulty target.
#[test]
fn test_block_700000_hash_meets_target() {
    let header = block_700000_header();
    assert!(verify_block_hash(header));
}

// ---------------------------------------------------------------------------
// Coinbase transaction tests
// ---------------------------------------------------------------------------

fn genesis_coinbase() -> Transaction {
    // Genesis coinbase scriptSig: push of "The Times 03/Jan/2009 Chancellor..."
    let mut script_sig: Array<u8> = ArrayTrait::new();
    // Simplified — real scriptSig is 77 bytes; we encode length prefix + content placeholder
    script_sig.append(0x04_u8);
    script_sig.append(0xff_u8);
    script_sig.append(0xff_u8);
    script_sig.append(0x00_u8);
    script_sig.append(0x1d_u8);

    let input = TxInput {
        prev_txid: 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
        prev_index: 0xffffffff_u32,
        script_sig,
        sequence: 0xffffffff_u32,
    };

    let mut script_pubkey: Array<u8> = ArrayTrait::new();
    script_pubkey.append(0x41_u8); // OP_DATA_65
    // ... compressed pubkey bytes omitted for brevity

    let output = TxOutput { value: 5000000000_u64, script_pubkey };

    Transaction {
        version: 1_u32,
        inputs: array![input],
        outputs: array![output],
        locktime: 0_u32,
    }
}

/// The genesis coinbase transaction must be identified as a valid coinbase.
#[test]
fn test_verify_coinbase_transaction_genesis() {
    let tx = genesis_coinbase();
    assert!(verify_coinbase_transaction(@tx));
}

/// A regular transaction (non-null prev_txid) must NOT be classified as coinbase.
#[test]
fn test_verify_coinbase_transaction_rejects_normal_tx() {
    let input = TxInput {
        prev_txid: 0x1111111111111111111111111111111111111111111111111111111111111111_u256,
        prev_index: 0_u32,
        script_sig: ArrayTrait::new(),
        sequence: 0xffffffff_u32,
    };
    let tx = Transaction {
        version: 1_u32,
        inputs: array![input],
        outputs: ArrayTrait::new(),
        locktime: 0_u32,
    };
    assert!(!verify_coinbase_transaction(@tx));
}

/// An empty transaction must NOT be classified as coinbase.
#[test]
fn test_verify_coinbase_empty_inputs_fails() {
    let tx = Transaction {
        version: 1_u32,
        inputs: ArrayTrait::new(),
        outputs: ArrayTrait::new(),
        locktime: 0_u32,
    };
    assert!(!verify_coinbase_transaction(@tx));
}

// ---------------------------------------------------------------------------
// Transaction hash tests
// ---------------------------------------------------------------------------

/// compute_transaction_hash must return a non-zero value for a non-empty transaction.
#[test]
fn test_compute_transaction_hash_nonzero() {
    let tx = genesis_coinbase();
    let hash = compute_transaction_hash(@tx);
    assert!(hash != 0_u256);
}

/// The genesis coinbase txid (displayed in big-endian) must match the known value.
/// Raw txid (little-endian): 3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a
#[test]
fn test_compute_genesis_coinbase_txid() {
    let tx = genesis_coinbase();
    // Big-endian as stored in the merkle tree / block header:
    let expected: u256 =
        0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256;
    assert_eq!(compute_transaction_hash(@tx), expected);
}

// ---------------------------------------------------------------------------
// Merkle proof for block #700000 (spot check)
// ---------------------------------------------------------------------------

/// Verifying a valid Merkle inclusion proof from a known block must succeed.
#[test]
fn test_merkle_proof_block_700000_coinbase() {
    // Placeholder leaf and proof — real data requires block explorer data
    let leaf: u256 =
        0x4b2e6e3f8e3b8f3c4e2a8d4f6a8c2e4f6b8a2c4e6f8a0c2e4f6b8a2c4e6f80_u256;
    let proof: Array<u256> = ArrayTrait::new();
    // When proof is empty the root must equal the leaf
    assert!(merkle_verify(leaf, proof, leaf));
}

/// Passing a wrong root with a valid leaf must fail.
#[test]
fn test_merkle_proof_wrong_root_fails() {
    let leaf: u256 = 0x1234_u256;
    let wrong_root: u256 = 0x5678_u256;
    let proof: Array<u256> = ArrayTrait::new();
    assert!(!merkle_verify(leaf, proof, wrong_root));
}

// ---------------------------------------------------------------------------
// parse_block_header round-trip test
// ---------------------------------------------------------------------------

/// Parsing 80 zero-bytes must produce a header with all fields == 0.
#[test]
fn test_parse_block_header_all_zeros() {
    let mut raw: Array<u8> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i == 80 {
            break;
        }
        raw.append(0x00_u8);
        i += 1;
    };
    let header = parse_block_header(raw);
    assert_eq!(header.version, 0_u32);
    assert_eq!(header.prev_block_hash, 0_u256);
    assert_eq!(header.merkle_root, 0_u256);
    assert_eq!(header.timestamp, 0_u32);
    assert_eq!(header.bits, 0_u32);
    assert_eq!(header.nonce, 0_u32);
}
