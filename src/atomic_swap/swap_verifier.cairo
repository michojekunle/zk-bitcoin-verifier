use zk_bitcoin_verifier::crypto::sha256::sha256;
use super::swap_state::{AtomicSwap, SwapState};

pub fn verify_btc_lock(secret_hash: u256, refund_block: u32, current_block: u32) -> bool {
    let _ = secret_hash;
    current_block < refund_block
}

pub fn verify_eth_lock(eth_amount: u256, secret_hash: u256) -> bool {
    eth_amount != 0_u256 && secret_hash != 0_u256
}

pub fn verify_secret_reveal(secret: Array<u8>, secret_hash: u256) -> bool {
    sha256(secret) == secret_hash
}

pub fn verify_swap_settlement(swap: @AtomicSwap, secret: Array<u8>) -> bool {
    *swap.state == SwapState::EthLocked && verify_secret_reveal(secret, *swap.secret_hash)
}

pub fn verify_atomic_swap(swap: @AtomicSwap) -> bool {
    *swap.state == SwapState::EthLocked
}
