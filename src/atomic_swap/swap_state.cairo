/// The lifecycle state of a cross-chain atomic swap.
///
/// State transitions follow this DAG:
///   Initiated → BtcLocked → EthLocked → Revealed → Settled
///                                ↘                 ↗
///                                      Refunded
#[derive(Drop, Copy, PartialEq)]
pub enum SwapState {
    /// The swap has been proposed but no funds are locked on either chain.
    Initiated,
    /// The initiator has locked BTC in a HTLC on the Bitcoin network.
    BtcLocked,
    /// The counterparty has locked ETH/ERC-20 tokens in response.
    EthLocked,
    /// The secret preimage has been revealed to claim the ETH side.
    Revealed,
    /// Both parties have successfully claimed their funds; swap is complete.
    Settled,
    /// The timelock expired and at least one party has reclaimed their funds.
    Refunded,
}

/// All data describing an in-flight or completed atomic swap.
#[derive(Drop)]
pub struct AtomicSwap {
    /// Starknet address (as felt252) of the party who initiated the swap.
    pub initiator: felt252,
    /// Amount of BTC locked in satoshis.
    pub btc_amount: u64,
    /// Amount of ETH (or ERC-20 tokens) locked, denominated in wei.
    pub eth_amount: u256,
    /// SHA-256 hash of the secret preimage (the HTLC hash lock).
    pub secret_hash: u256,
    /// Bitcoin block height after which the BTC HTLC can be refunded.
    pub btc_refund_block: u32,
    /// Unix timestamp (seconds) after which the ETH HTLC can be refunded.
    pub eth_refund_time: u64,
    /// Current state in the swap lifecycle.
    pub state: SwapState,
}
