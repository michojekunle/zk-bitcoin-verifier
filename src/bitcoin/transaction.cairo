/// One input of a Bitcoin transaction.
#[derive(Drop, Clone)]
pub struct TxInput {
    /// Txid of the output being spent (little-endian as stored in the UTXO set).
    pub prev_txid: u256,
    /// Output index within the previous transaction.
    pub prev_index: u32,
    /// Unlocking script (scriptSig) that satisfies the previous output's scriptPubKey.
    pub script_sig: Array<u8>,
    /// Sequence number used for opt-in RBF and relative timelocks.
    pub sequence: u32,
}

/// One output of a Bitcoin transaction.
#[derive(Drop, Clone)]
pub struct TxOutput {
    /// Value in satoshis transferred to this output.
    pub value: u64,
    /// Locking script (scriptPubKey) that must be satisfied to spend this output.
    pub script_pubkey: Array<u8>,
}

/// A fully parsed Bitcoin transaction (legacy, non-segwit serialisation).
#[derive(Drop, Clone)]
pub struct Transaction {
    /// Transaction format version (currently 1 or 2).
    pub version: u32,
    /// List of transaction inputs.
    pub inputs: Array<TxInput>,
    /// List of transaction outputs.
    pub outputs: Array<TxOutput>,
    /// Absolute timelock: transaction is invalid before this block height or timestamp.
    pub locktime: u32,
}

/// Deserialises a raw Bitcoin transaction byte array into a `Transaction`.
///
/// # Arguments
/// * `raw_bytes` - The full serialised transaction bytes.
///
/// # Returns
/// A `Transaction` struct with all fields populated.
///
/// TODO: Implement varint decoding and recursive input/output parsing.
pub fn parse_transaction(raw_bytes: Array<u8>) -> Transaction {
    // STUB: returns an empty transaction until implementation is complete.
    Transaction {
        version: 0_u32,
        inputs: ArrayTrait::new(),
        outputs: ArrayTrait::new(),
        locktime: 0_u32,
    }
}

/// Verifies that the scriptSig at `input_idx` correctly spends its previous output,
/// given the signing public key.
///
/// # Arguments
/// * `tx`        - The transaction being verified (passed by snapshot to avoid copying Arrays).
/// * `input_idx` - Index into `tx.inputs` identifying which input to verify.
/// * `pubkey`    - The expected public key as a compressed `felt252` identifier.
///
/// # Returns
/// `true` if the signature is valid for that input, `false` otherwise.
///
/// TODO: Extract DER signature from scriptSig, hash the sighash preimage, call secp256k1_verify.
pub fn verify_transaction_signature(tx: @Transaction, input_idx: u32, pubkey: felt252) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}

/// Computes the double-SHA256 of the serialised transaction (the "txid").
///
/// # Arguments
/// * `tx` - The transaction to hash.
///
/// # Returns
/// The 256-bit txid.
///
/// TODO: Serialise `tx` to bytes and call sha256d.
pub fn compute_transaction_hash(tx: @Transaction) -> u256 {
    // STUB: returns zero until implementation is complete.
    0_u256
}

/// Checks that a transaction is a valid coinbase transaction.
///
/// Coinbase transactions have exactly one input whose prev_txid is all-zeros and
/// prev_index is 0xFFFFFFFF.
///
/// # Returns
/// `true` if the transaction is a well-formed coinbase, `false` otherwise.
///
/// TODO: Validate input count, prev_txid, prev_index, and scriptSig length bounds.
pub fn verify_coinbase_transaction(tx: @Transaction) -> bool {
    // STUB: always returns false until implementation is complete.
    false
}
