use zk_bitcoin_verifier::crypto::field_utils::reverse_bytes32;
use zk_bitcoin_verifier::crypto::sha256::sha256d;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// One input of a Bitcoin transaction.
#[derive(Drop, Clone)]
pub struct TxInput {
    /// Txid of the output being spent (display / big-endian form).
    pub prev_txid: u256,
    /// Output index within the previous transaction.
    pub prev_index: u32,
    /// Unlocking script (scriptSig).
    pub script_sig: Array<u8>,
    /// Sequence number.
    pub sequence: u32,
}

/// One output of a Bitcoin transaction.
#[derive(Drop, Clone)]
pub struct TxOutput {
    /// Value in satoshis.
    pub value: u64,
    /// Locking script (scriptPubKey).
    pub script_pubkey: Array<u8>,
}

/// A fully parsed Bitcoin transaction (legacy, non-segwit serialisation).
#[derive(Drop, Clone)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Array<TxInput>,
    pub outputs: Array<TxOutput>,
    pub locktime: u32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Deserialises a raw Bitcoin transaction byte array into a Transaction.
///
/// Handles variable-length inputs and outputs via varint decoding.
pub fn parse_transaction(raw_bytes: Array<u8>) -> Transaction {
    let s = raw_bytes.span();
    let mut offset: u32 = 0;

    let version = read_u32_le(s, offset);
    offset += 4;

    // Parse inputs.
    let (in_count, in_size) = read_varint(s, offset);
    offset += in_size;
    let mut inputs: Array<TxInput> = array![];
    let mut i: u32 = 0;
    while i < in_count {
        let prev_txid = read_u256_le(s, offset);
        offset += 32;
        let prev_index = read_u32_le(s, offset);
        offset += 4;
        let (script_len, vsize) = read_varint(s, offset);
        offset += vsize;
        let script_sig = read_bytes(s, offset, script_len);
        offset += script_len;
        let sequence = read_u32_le(s, offset);
        offset += 4;
        inputs.append(TxInput { prev_txid, prev_index, script_sig, sequence });
        i += 1;
    }

    // Parse outputs.
    let (out_count, out_size) = read_varint(s, offset);
    offset += out_size;
    let mut outputs: Array<TxOutput> = array![];
    let mut j: u32 = 0;
    while j < out_count {
        let value = read_u64_le(s, offset);
        offset += 8;
        let (script_len, vsize) = read_varint(s, offset);
        offset += vsize;
        let script_pubkey = read_bytes(s, offset, script_len);
        offset += script_len;
        outputs.append(TxOutput { value, script_pubkey });
        j += 1;
    }

    let locktime = read_u32_le(s, offset);
    Transaction { version, inputs, outputs, locktime }
}

/// Computes the txid (double-SHA256 of serialised tx, bytes reversed).
///
/// Returns the txid in display (big-endian) form, matching what block
/// explorers show and what appears in Merkle trees.
pub fn compute_transaction_hash(tx: @Transaction) -> u256 {
    let raw = serialize_transaction(tx);
    let hash_raw = sha256d(raw);
    // Bitcoin txids are the reversed sha256d bytes (little-endian display).
    reverse_bytes32(hash_raw)
}

/// Returns false — full script-based signature verification is out of scope
/// for this MVP (requires secp256k1 and script interpreter).
pub fn verify_transaction_signature(tx: @Transaction, input_idx: u32, pubkey: felt252) -> bool {
    false
}

/// Checks that a transaction is a valid coinbase.
///
/// A coinbase has exactly one input with prev_txid = 0 and prev_index = 0xFFFFFFFF.
pub fn verify_coinbase_transaction(tx: @Transaction) -> bool {
    let inputs = tx.inputs;
    if inputs.len() != 1 {
        return false;
    }
    let input = inputs.at(0);
    *input.prev_txid == 0_u256 && *input.prev_index == 0xffffffff_u32
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

fn serialize_transaction(tx: @Transaction) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    append_u32_le(ref bytes, *tx.version);

    // Inputs.
    let inputs = tx.inputs;
    let in_len = inputs.len();
    append_varint(ref bytes, in_len);
    let mut i: u32 = 0;
    while i < in_len {
        let inp = inputs.at(i);
        // prev_txid: display BE → wire LE
        append_u256_le(ref bytes, *inp.prev_txid);
        append_u32_le(ref bytes, *inp.prev_index);
        let ss = inp.script_sig;
        append_varint(ref bytes, ss.len());
        let mut k: u32 = 0;
        while k < ss.len() {
            bytes.append(*ss.at(k));
            k += 1;
        }
        append_u32_le(ref bytes, *inp.sequence);
        i += 1;
    }

    // Outputs.
    let outputs = tx.outputs;
    let out_len = outputs.len();
    append_varint(ref bytes, out_len);
    let mut j: u32 = 0;
    while j < out_len {
        let out = outputs.at(j);
        append_u64_le(ref bytes, *out.value);
        let sp = out.script_pubkey;
        append_varint(ref bytes, sp.len());
        let mut k: u32 = 0;
        while k < sp.len() {
            bytes.append(*sp.at(k));
            k += 1;
        }
        j += 1;
    }

    append_u32_le(ref bytes, *tx.locktime);
    bytes
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn append_u32_le(ref arr: Array<u8>, val: u32) {
    arr.append((val & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x100_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x10000_u32) & 0xff_u32).try_into().unwrap());
    arr.append(((val / 0x1000000_u32) & 0xff_u32).try_into().unwrap());
}

fn append_u64_le(ref arr: Array<u8>, val: u64) {
    arr.append((val & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x100_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x10000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x1000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x100000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x10000000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x1000000000000_u64) & 0xff_u64).try_into().unwrap());
    arr.append(((val / 0x100000000000000_u64) & 0xff_u64).try_into().unwrap());
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

fn append_u256_le(ref arr: Array<u8>, val: u256) {
    let reversed = reverse_bytes32(val);
    append_u128_be(ref arr, reversed.high);
    append_u128_be(ref arr, reversed.low);
}

/// Appends a Bitcoin variable-length integer.
fn append_varint(ref arr: Array<u8>, val: u32) {
    if val < 0xfd_u32 {
        arr.append(val.try_into().unwrap());
    } else if val <= 0xffff_u32 {
        arr.append(0xfd_u8);
        arr.append((val & 0xff_u32).try_into().unwrap());
        arr.append(((val / 0x100_u32) & 0xff_u32).try_into().unwrap());
    } else {
        arr.append(0xfe_u8);
        arr.append((val & 0xff_u32).try_into().unwrap());
        arr.append(((val / 0x100_u32) & 0xff_u32).try_into().unwrap());
        arr.append(((val / 0x10000_u32) & 0xff_u32).try_into().unwrap());
        arr.append(((val / 0x1000000_u32) & 0xff_u32).try_into().unwrap());
    }
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

fn read_u32_le(bytes: Span<u8>, offset: u32) -> u32 {
    (*bytes.at(offset)).into()
        + (*bytes.at(offset + 1)).into() * 0x100_u32
        + (*bytes.at(offset + 2)).into() * 0x10000_u32
        + (*bytes.at(offset + 3)).into() * 0x1000000_u32
}

fn read_u64_le(bytes: Span<u8>, offset: u32) -> u64 {
    (*bytes.at(offset)).into()
        + (*bytes.at(offset + 1)).into() * 0x100_u64
        + (*bytes.at(offset + 2)).into() * 0x10000_u64
        + (*bytes.at(offset + 3)).into() * 0x1000000_u64
        + (*bytes.at(offset + 4)).into() * 0x100000000_u64
        + (*bytes.at(offset + 5)).into() * 0x10000000000_u64
        + (*bytes.at(offset + 6)).into() * 0x1000000000000_u64
        + (*bytes.at(offset + 7)).into() * 0x100000000000000_u64
}

fn read_u256_le(bytes: Span<u8>, offset: u32) -> u256 {
    let mut wire: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 32 {
        wire.append(*bytes.at(offset + i));
        i += 1;
    }
    let reversed = reverse_u8_array(wire);
    bytes_be_to_u256(reversed.span())
}

/// Decodes a Bitcoin varint. Returns (value, byte_size).
fn read_varint(bytes: Span<u8>, offset: u32) -> (u32, u32) {
    let first: u32 = (*bytes.at(offset)).into();
    if first < 0xfd_u32 {
        (first, 1_u32)
    } else if first == 0xfd_u32 {
        let val: u32 = (*bytes.at(offset + 1)).into() + (*bytes.at(offset + 2)).into() * 0x100_u32;
        (val, 3_u32)
    } else if first == 0xfe_u32 {
        let val: u32 = read_u32_le(bytes, offset + 1);
        (val, 5_u32)
    } else {
        // 0xff — 8-byte varint; we only support up to u32 range here.
        let val: u32 = read_u32_le(bytes, offset + 1);
        (val, 9_u32)
    }
}

fn read_bytes(bytes: Span<u8>, offset: u32, len: u32) -> Array<u8> {
    let mut out: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < len {
        out.append(*bytes.at(offset + i));
        i += 1;
    }
    out
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
