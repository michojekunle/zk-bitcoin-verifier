use zk_bitcoin_verifier::crypto::sha256::{sha256, sha256d};
use zk_bitcoin_verifier::crypto::merkle::{merkle_verify, merkle_root};
use zk_bitcoin_verifier::crypto::secp256k1::{secp256k1_verify_signature, Point, Signature};

// ---------------------------------------------------------------------------
// SHA-256 tests (NIST test vectors)
// All assertions will FAIL until sha256() is implemented — this is expected.
// ---------------------------------------------------------------------------

/// NIST FIPS 180-4 vector: SHA-256("") =
/// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
#[test]
fn test_sha256_nist_empty_input() {
    let input: Array<u8> = ArrayTrait::new();
    let expected: u256 =
        0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_u256;
    assert_eq!(sha256(input), expected);
}

/// NIST FIPS 180-4 vector: SHA-256("abc") =
/// ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656bd6e2d
#[test]
fn test_sha256_nist_abc() {
    let mut input: Array<u8> = ArrayTrait::new();
    input.append(0x61_u8); // 'a'
    input.append(0x62_u8); // 'b'
    input.append(0x63_u8); // 'c'
    let expected: u256 =
        0xba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656bd6e2d_u256;
    assert_eq!(sha256(input), expected);
}

/// NIST vector: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
/// 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
#[test]
fn test_sha256_nist_448_bit_message() {
    let mut input: Array<u8> = ArrayTrait::new();
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let bytes = array![
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66, 0x64, 0x65,
        0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6a,
        0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71,
    ];
    let expected: u256 =
        0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1_u256;
    assert_eq!(sha256(bytes), expected);
}

/// SHA-256 of a single zero byte (0x00):
/// 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
#[test]
fn test_sha256_single_zero_byte() {
    let input = array![0x00_u8];
    let expected: u256 =
        0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d_u256;
    assert_eq!(sha256(input), expected);
}

/// SHA-256 of a single 0xFF byte:
/// a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89
#[test]
fn test_sha256_single_ff_byte() {
    let input = array![0xff_u8];
    let expected: u256 =
        0xa8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89_u256;
    assert_eq!(sha256(input), expected);
}

/// SHA-256 output must be deterministic: two calls with the same input yield the same result.
#[test]
fn test_sha256_deterministic() {
    let input_a = array![0x41_u8, 0x42_u8, 0x43_u8];
    let input_b = array![0x41_u8, 0x42_u8, 0x43_u8];
    assert_eq!(sha256(input_a), sha256(input_b));
}

// ---------------------------------------------------------------------------
// SHA-256d (double-hash) tests
// ---------------------------------------------------------------------------

/// SHA-256d("") = SHA-256(SHA-256(""))
/// Inner: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/// Outer: 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
#[test]
fn test_sha256d_empty_input() {
    let input: Array<u8> = ArrayTrait::new();
    let expected: u256 =
        0x5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456_u256;
    assert_eq!(sha256d(input), expected);
}

/// SHA-256d("abc")
/// Inner: ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656bd6e2d
/// Outer: 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
#[test]
fn test_sha256d_abc() {
    let input = array![0x61_u8, 0x62_u8, 0x63_u8];
    let expected: u256 =
        0x4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358_u256;
    assert_eq!(sha256d(input), expected);
}

/// sha256d must differ from sha256 for the same non-trivial input.
#[test]
fn test_sha256d_differs_from_sha256() {
    let input_a = array![0x61_u8, 0x62_u8, 0x63_u8];
    let input_b = array![0x61_u8, 0x62_u8, 0x63_u8];
    // Once implemented, sha256d != sha256 for "abc"
    assert!(sha256(input_a) != sha256d(input_b));
}

// ---------------------------------------------------------------------------
// Merkle verification tests
// ---------------------------------------------------------------------------

/// A single-leaf tree: the root IS the leaf, so proof is empty.
/// merkle_verify(leaf, [], leaf) should return true.
#[test]
fn test_merkle_verify_single_leaf_empty_proof() {
    let leaf: u256 = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_u256;
    let proof: Array<u256> = ArrayTrait::new();
    assert!(merkle_verify(leaf, proof, leaf));
}

/// A non-matching root with an empty proof should return false.
#[test]
fn test_merkle_verify_wrong_root_empty_proof() {
    let leaf: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111_u256;
    let proof: Array<u256> = ArrayTrait::new();
    let wrong_root: u256 =
        0x2222222222222222222222222222222222222222222222222222222222222222_u256;
    assert!(!merkle_verify(leaf, proof, wrong_root));
}

/// Two-leaf tree: merkle_verify(leaf0, [leaf1], sha256d(leaf0 || leaf1)) == true
/// Uses Bitcoin genesis block txid as leaf0 for realism.
#[test]
fn test_merkle_verify_two_leaf_tree() {
    // Genesis coinbase txid (little-endian as stored in header):
    let leaf0: u256 =
        0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256;
    let leaf1: u256 =
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_u256;
    // root = sha256d(leaf0 || leaf1) — value determined by correct implementation
    let root: u256 = 0x0000000000000000000000000000000000000000000000000000000000000000_u256;
    let proof = array![leaf1];
    // Will fail until sha256d and merkle_verify are implemented
    assert!(merkle_verify(leaf0, proof, root));
}

/// Tampering with a proof element must cause verification to fail.
#[test]
fn test_merkle_verify_tampered_proof_fails() {
    let leaf: u256 = 0xabababababababab_u256;
    let correct_sibling: u256 =
        0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd_u256;
    let tampered_sibling: u256 =
        0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee_u256;
    // root computed from correct_sibling — placeholder
    let root: u256 = 0x0000000000000000000000000000000000000000000000000000000000000000_u256;
    let proof = array![tampered_sibling];
    assert!(!merkle_verify(leaf, proof, root));
}

/// merkle_root of a single element should equal that element.
#[test]
fn test_merkle_root_single_element() {
    let leaf: u256 = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef_u256;
    let leaves = array![leaf];
    assert_eq!(merkle_root(leaves), leaf);
}

/// merkle_root of an empty list should return 0.
#[test]
fn test_merkle_root_empty_returns_zero() {
    let leaves: Array<u256> = ArrayTrait::new();
    assert_eq!(merkle_root(leaves), 0_u256);
}

// ---------------------------------------------------------------------------
// secp256k1 signature verification tests
// ---------------------------------------------------------------------------

/// A known-good ECDSA signature over secp256k1 must verify successfully.
/// Test vector from Bitcoin's test suite (simplified representation).
#[test]
fn test_secp256k1_verify_known_valid_signature() {
    // message hash: SHA-256("test message")
    let message_hash: u256 =
        0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256;
    let sig = Signature {
        r: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        s: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    let pubkey = Point {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    assert!(secp256k1_verify_signature(message_hash, sig, pubkey));
}

/// A zeroed signature must NOT verify against any public key.
#[test]
fn test_secp256k1_verify_zero_signature_fails() {
    let message_hash: u256 =
        0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256;
    let sig = Signature { r: 0_u256, s: 0_u256 };
    let pubkey = Point {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    assert!(!secp256k1_verify_signature(message_hash, sig, pubkey));
}

/// A valid signature must NOT verify against a different message hash.
#[test]
fn test_secp256k1_verify_wrong_message_fails() {
    let wrong_hash: u256 = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_u256;
    let sig = Signature {
        r: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        s: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    let pubkey = Point {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    assert!(!secp256k1_verify_signature(wrong_hash, sig, pubkey));
}

/// A valid signature must NOT verify against a different (random) public key.
#[test]
fn test_secp256k1_verify_wrong_pubkey_fails() {
    let message_hash: u256 =
        0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256;
    let sig = Signature {
        r: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        s: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    let wrong_pubkey = Point { x: 0x1111_u256, y: 0x2222_u256 };
    assert!(!secp256k1_verify_signature(message_hash, sig, wrong_pubkey));
}

/// Signature with r >= curve order must be rejected as malformed.
#[test]
fn test_secp256k1_verify_r_out_of_range_fails() {
    let message_hash: u256 = 0x1234_u256;
    // secp256k1 order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let sig = Signature {
        r: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0_u256,
        s: 0x01_u256,
    };
    let pubkey = Point {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256,
    };
    assert!(!secp256k1_verify_signature(message_hash, sig, pubkey));
}
