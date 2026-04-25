pub mod crypto;
pub mod bitcoin;
pub mod atomic_swap;

pub use crypto::sha256::sha256;
pub use crypto::secp256k1::secp256k1_verify_signature;
pub use crypto::merkle::merkle_verify;
pub use bitcoin::block_header::verify_block_header;
pub use bitcoin::transaction::verify_transaction_signature;

#[cfg(test)]
mod tests;
