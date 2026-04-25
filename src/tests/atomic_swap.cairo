use zk_bitcoin_verifier::atomic_swap::swap_state::{AtomicSwap, SwapState};
use zk_bitcoin_verifier::atomic_swap::swap_verifier::{
    verify_btc_lock, verify_eth_lock, verify_secret_reveal, verify_swap_settlement,
    verify_atomic_swap,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_swap(state: SwapState) -> AtomicSwap {
    AtomicSwap {
        initiator: 0x1234567890abcdef_felt252,
        btc_amount: 100000000_u64, // 1 BTC in satoshis
        eth_amount: 2000000000000000000_u256, // 2 ETH in wei
        secret_hash: 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_u256,
        btc_refund_block: 800000_u32,
        eth_refund_time: 1700000000_u64,
        state,
    }
}

// ---------------------------------------------------------------------------
// SwapState equality tests
// ---------------------------------------------------------------------------

/// Two `Initiated` states must compare equal.
#[test]
fn test_swap_state_initiated_eq() {
    let s1 = SwapState::Initiated;
    let s2 = SwapState::Initiated;
    assert!(s1 == s2);
}

/// `Initiated` and `BtcLocked` must NOT be equal.
#[test]
fn test_swap_state_initiated_ne_btc_locked() {
    let s1 = SwapState::Initiated;
    let s2 = SwapState::BtcLocked;
    assert!(s1 != s2);
}

/// `Settled` and `Refunded` are distinct terminal states.
#[test]
fn test_swap_state_settled_ne_refunded() {
    assert!(SwapState::Settled != SwapState::Refunded);
}

// ---------------------------------------------------------------------------
// verify_btc_lock tests
// ---------------------------------------------------------------------------

/// When current_block < refund_block the BTC HTLC is still live: should return true.
#[test]
fn test_verify_btc_lock_before_expiry() {
    let secret_hash: u256 =
        0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_u256;
    // current_block is 100 blocks before refund
    assert!(verify_btc_lock(secret_hash, 800000_u32, 799900_u32));
}

/// When current_block >= refund_block the HTLC has expired: should return false.
#[test]
fn test_verify_btc_lock_at_expiry_fails() {
    let secret_hash: u256 = 0x1234_u256;
    assert!(!verify_btc_lock(secret_hash, 800000_u32, 800000_u32));
}

/// When current_block > refund_block the HTLC is expired: should return false.
#[test]
fn test_verify_btc_lock_after_expiry_fails() {
    let secret_hash: u256 = 0x1234_u256;
    assert!(!verify_btc_lock(secret_hash, 800000_u32, 800001_u32));
}

// ---------------------------------------------------------------------------
// verify_eth_lock tests
// ---------------------------------------------------------------------------

/// A correctly funded ETH HTLC with the right hash must return true.
#[test]
fn test_verify_eth_lock_valid() {
    let eth_amount: u256 = 2000000000000000000_u256;
    let secret_hash: u256 =
        0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_u256;
    assert!(verify_eth_lock(eth_amount, secret_hash));
}

/// A zero ETH amount must fail lock verification.
#[test]
fn test_verify_eth_lock_zero_amount_fails() {
    let secret_hash: u256 = 0xdeadbeef_u256;
    assert!(!verify_eth_lock(0_u256, secret_hash));
}

// ---------------------------------------------------------------------------
// verify_secret_reveal tests
// ---------------------------------------------------------------------------

/// sha256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
/// Revealing "test" against that hash should succeed.
#[test]
fn test_verify_secret_reveal_correct_preimage() {
    // "test" in bytes: 0x74 0x65 0x73 0x74
    let secret = array![0x74_u8, 0x65_u8, 0x73_u8, 0x74_u8];
    let secret_hash: u256 =
        0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_u256;
    assert!(verify_secret_reveal(secret, secret_hash));
}

/// Revealing a wrong preimage must fail.
#[test]
fn test_verify_secret_reveal_wrong_preimage_fails() {
    let wrong_secret = array![0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8];
    let secret_hash: u256 =
        0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_u256;
    assert!(!verify_secret_reveal(wrong_secret, secret_hash));
}

/// Revealing an empty preimage against a non-zero hash must fail.
#[test]
fn test_verify_secret_reveal_empty_preimage_fails() {
    let secret: Array<u8> = ArrayTrait::new();
    let secret_hash: u256 = 0xdeadbeef_u256;
    assert!(!verify_secret_reveal(secret, secret_hash));
}

// ---------------------------------------------------------------------------
// verify_swap_settlement tests
// ---------------------------------------------------------------------------

/// A swap in EthLocked state with the correct preimage should settle successfully.
#[test]
fn test_verify_swap_settlement_eth_locked_valid_secret() {
    let swap = sample_swap(SwapState::EthLocked);
    let secret = array![0x74_u8, 0x65_u8, 0x73_u8, 0x74_u8]; // "test"
    assert!(verify_swap_settlement(@swap, secret));
}

/// A swap in Initiated state (ETH not yet locked) must NOT settle.
#[test]
fn test_verify_swap_settlement_wrong_state_fails() {
    let swap = sample_swap(SwapState::Initiated);
    let secret = array![0x74_u8, 0x65_u8, 0x73_u8, 0x74_u8];
    assert!(!verify_swap_settlement(@swap, secret));
}

/// Even in the correct state, a wrong secret must prevent settlement.
#[test]
fn test_verify_swap_settlement_wrong_secret_fails() {
    let swap = sample_swap(SwapState::EthLocked);
    let wrong_secret = array![0xff_u8, 0xfe_u8];
    assert!(!verify_swap_settlement(@swap, wrong_secret));
}

// ---------------------------------------------------------------------------
// verify_atomic_swap tests
// ---------------------------------------------------------------------------

/// A fully configured swap in EthLocked state should pass top-level verification.
#[test]
fn test_verify_atomic_swap_eth_locked_state() {
    let swap = sample_swap(SwapState::EthLocked);
    assert!(verify_atomic_swap(@swap));
}

/// A swap in the initial Initiated state must NOT pass top-level verification
/// (BTC and ETH are not yet locked).
#[test]
fn test_verify_atomic_swap_initiated_state_fails() {
    let swap = sample_swap(SwapState::Initiated);
    assert!(!verify_atomic_swap(@swap));
}

/// A refunded swap must NOT pass top-level verification.
#[test]
fn test_verify_atomic_swap_refunded_state_fails() {
    let swap = sample_swap(SwapState::Refunded);
    assert!(!verify_atomic_swap(@swap));
}
