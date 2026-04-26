# API Reference

Complete documentation for all public functions and types exported by `zk_bitcoin_verifier`.

---

## Table of Contents

- [Crypto Primitives](#crypto-primitives)
  - [sha256](#sha256)
  - [sha256d](#sha256d)
  - [secp256k1](#secp256k1)
  - [merkle](#merkle)
  - [field_utils](#field_utils)
- [Bitcoin Layer](#bitcoin-layer)
  - [block_header](#block_header)
  - [transaction](#transaction)
  - [utxo](#utxo)
  - [script](#script)
- [Atomic Swap](#atomic-swap)
  - [swap_state](#swap_state)
  - [swap_verifier](#swap_verifier)

## Crypto Primitives

### sha256

**Module path:** `zk_bitcoin_verifier::crypto::sha256`

#### `sha256`

```cairo
pub fn sha256(input: Array<u8>) -> u256
```

Computes the SHA-256 digest of the given byte array.

**Parameters**

| Name    | Type        | Description                   |
|---------|-------------|-------------------------------|
| `input` | `Array<u8>` | Raw bytes to hash. May be empty. |

**Returns**

`u256` — The 256-bit SHA-256 digest, stored big-endian (most-significant byte first).

**Example**

```cairo
use zk_bitcoin_verifier::crypto::sha256::sha256;

let digest = sha256(array![0x61, 0x62, 0x63]); // SHA-256("abc")
// expected: 0xba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656bd6e2d
```

#### `sha256d`

```cairo
pub fn sha256d(input: Array<u8>) -> u256
```

Computes SHA-256(SHA-256(input)) — the double-hash used throughout the Bitcoin protocol
for transaction IDs, block hashes, and Merkle tree nodes.

**Parameters**

| Name    | Type        | Description          |
|---------|-------------|----------------------|
| `input` | `Array<u8>` | Raw bytes to hash.   |

**Returns**

`u256` — The double-SHA-256 digest.

### secp256k1

**Module path:** `zk_bitcoin_verifier::crypto::secp256k1`

#### Types

```cairo
#[derive(Drop, Copy)]
pub struct Point {
    pub x: u256,
    pub y: u256,
}

#[derive(Drop, Copy)]
pub struct Signature {
    pub r: u256,
    pub s: u256,
}
```

`Point` represents an affine point on the secp256k1 curve. The point at infinity
is represented as `Point { x: 0, y: 0 }`.

`Signature` holds an ECDSA (r, s) pair. Both components must satisfy `1 <= r, s < n`
where `n` is the secp256k1 group order.

#### `secp256k1_verify_signature`

```cairo
pub fn secp256k1_verify_signature(
    message_hash: u256,
    sig: Signature,
    pubkey: Point,
) -> bool
```

Verifies an ECDSA signature over the secp256k1 curve.

**Parameters**

| Name           | Type        | Description                                      |
|----------------|-------------|--------------------------------------------------|
| `message_hash` | `u256`      | The 256-bit digest of the signed message.        |
| `sig`          | `Signature` | The (r, s) signature pair.                       |
| `pubkey`       | `Point`     | The signer's public key as an affine curve point.|

**Returns**

`bool` — `true` if and only if the signature is valid for the given message and key.

**Failure conditions**

- `sig.r` or `sig.s` is zero or >= curve order `n`.
- The recovered point does not match `pubkey`.
- `pubkey` is the point at infinity.

#### `secp256k1_recover_pubkey`

```cairo
pub fn secp256k1_recover_pubkey(
    message_hash: u256,
    sig: Signature,
    recovery_id: u8,
) -> Point
```

Recovers the public key from a message hash, signature, and recovery identifier,
following SEC 1 §4.1.6.

**Parameters**

| Name           | Type        | Description                                  |
|----------------|-------------|----------------------------------------------|
| `message_hash` | `u256`      | The 256-bit digest that was signed.          |
| `sig`          | `Signature` | The (r, s) signature pair.                   |
| `recovery_id`  | `u8`        | 0 or 1 — selects which candidate point to use.|

**Returns**

`Point` — The recovered public key. Returns `Point { x: 0, y: 0 }` on failure.

### merkle

**Module path:** `zk_bitcoin_verifier::crypto::merkle`

#### `merkle_verify`

```cairo
pub fn merkle_verify(leaf: u256, proof: Array<u256>, root: u256) -> bool
```

Verifies a Merkle inclusion proof using Bitcoin's double-SHA-256 pairing convention.

**Parameters**

| Name    | Type          | Description                                              |
|---------|---------------|----------------------------------------------------------|
| `leaf`  | `u256`        | The double-SHA-256 hash of the leaf data (e.g. a txid). |
| `proof` | `Array<u256>` | Ordered sibling hashes from the leaf level to the root. |
| `root`  | `u256`        | The expected Merkle root (as stored in the block header).|

**Returns**

`bool` — `true` if recomputing the root via the proof path matches `root`.

**Note:** An empty `proof` is valid when `leaf == root` (single-element tree).

#### `merkle_root`

```cairo
pub fn merkle_root(leaves: Array<u256>) -> u256
```

Computes the Merkle root of an ordered list of leaf hashes, following Bitcoin's
convention of duplicating the last element when the count is odd.

**Parameters**

| Name     | Type          | Description                                              |
|----------|---------------|----------------------------------------------------------|
| `leaves` | `Array<u256>` | Ordered leaf hashes (typically double-SHA-256 of txids). |

**Returns**

`u256` — The Merkle root. Returns `0` for an empty list.

### field_utils

**Module path:** `zk_bitcoin_verifier::crypto::field_utils`

#### `u32_to_felt252`

```cairo
pub fn u32_to_felt252(val: u32) -> felt252
```

Converts a `u32` to a `felt252` field element. This conversion is lossless.

#### `bytes_to_u256`

```cairo
pub fn bytes_to_u256(bytes: Array<u8>) -> u256
```

Interprets up to 32 bytes (big-endian) as a `u256`. Returns `0` for an empty array.

#### `reverse_bytes32`

```cairo
pub fn reverse_bytes32(val: u256) -> u256
```

Reverses the 32-byte (256-bit) representation of `val`. Used to convert between
Bitcoin's little-endian wire format and Cairo's big-endian arithmetic.

## Bitcoin Layer

### block_header

**Module path:** `zk_bitcoin_verifier::bitcoin::block_header`

#### Types

```cairo
#[derive(Drop, Copy)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: u256,
    pub merkle_root: u256,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}
```

Represents an 80-byte Bitcoin block header.

#### `parse_block_header`

```cairo
pub fn parse_block_header(raw_bytes: Array<u8>) -> BlockHeader
```

Deserialises exactly 80 bytes of little-endian wire data into a `BlockHeader`.

#### `verify_block_header`

```cairo
pub fn verify_block_header(header: BlockHeader) -> bool
```

Runs all validity checks: block hash meets target (`verify_block_hash`) and
difficulty bounds are valid (`verify_block_difficulty`).

#### `verify_block_hash`

```cairo
pub fn verify_block_hash(header: BlockHeader) -> bool
```

Checks that `sha256d(serialise(header)) <= bits_to_target(header.bits)`.

#### `verify_block_difficulty`

```cairo
pub fn verify_block_difficulty(header: BlockHeader) -> bool
```

Validates that `header.bits` encodes a target within the permitted network bounds.

#### `bits_to_target`

```cairo
pub fn bits_to_target(bits: u32) -> u256
```

Decodes the compact nBits field to a full 256-bit difficulty target.

**Formula:** `target = mantissa * 256^(exponent - 3)` where the high byte of `bits`
is the exponent and the lower three bytes are the mantissa.

### transaction

**Module path:** `zk_bitcoin_verifier::bitcoin::transaction`

#### Types

```cairo
#[derive(Drop, Clone)]
pub struct TxInput {
    pub prev_txid: u256,
    pub prev_index: u32,
    pub script_sig: Array<u8>,
    pub sequence: u32,
}

#[derive(Drop, Clone)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Array<u8>,
}

#[derive(Drop, Clone)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Array<TxInput>,
    pub outputs: Array<TxOutput>,
    pub locktime: u32,
}
```

#### `parse_transaction`

```cairo
pub fn parse_transaction(raw_bytes: Array<u8>) -> Transaction
```

Deserialises a raw Bitcoin transaction (legacy serialisation, no segwit witness).

#### `verify_transaction_signature`

```cairo
pub fn verify_transaction_signature(
    tx: @Transaction,
    input_idx: u32,
    pubkey: felt252,
) -> bool
```

Verifies that the scriptSig at `input_idx` correctly signs the SIGHASH_ALL preimage
under `pubkey`.

#### `compute_transaction_hash`

```cairo
pub fn compute_transaction_hash(tx: @Transaction) -> u256
```

Returns the txid: `sha256d(serialise(tx))`. The result is big-endian (as displayed
in block explorers).

#### `verify_coinbase_transaction`

```cairo
pub fn verify_coinbase_transaction(tx: @Transaction) -> bool
```

Returns `true` when the transaction has exactly one input with `prev_txid == 0`
and `prev_index == 0xFFFFFFFF`.

### utxo

**Module path:** `zk_bitcoin_verifier::bitcoin::utxo`

#### Types

```cairo
#[derive(Drop, Copy)]
pub struct UTXO {
    pub txid: u256,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: felt252,
}
```

#### `compute_outpoint_hash`

```cairo
pub fn compute_outpoint_hash(txid: u256, vout: u32) -> u256
```

Returns `sha256d(txid || vout)` as a unique outpoint identifier.

#### `verify_utxo_ownership`

```cairo
pub fn verify_utxo_ownership(utxo: UTXO, pubkey: felt252) -> bool
```

Returns `true` if `HASH160(pubkey)` matches the hash embedded in `utxo.script_pubkey`.

### script

**Module path:** `zk_bitcoin_verifier::bitcoin::script`

#### `validate_p2pkh_script`

```cairo
pub fn validate_p2pkh_script(script: Array<u8>, pubkey_hash: u256) -> bool
```

Returns `true` if `script` is a well-formed P2PKH output script
(`OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`) and the embedded
hash matches `pubkey_hash`.

#### `validate_p2sh_script`

```cairo
pub fn validate_p2sh_script(script: Array<u8>, redeem_script_hash: u256) -> bool
```

Returns `true` if `script` is a well-formed P2SH output script
(`OP_HASH160 <hash> OP_EQUAL`) and the embedded hash matches `redeem_script_hash`.

#### `validate_p2wpkh_script`

```cairo
pub fn validate_p2wpkh_script(script: Array<u8>, pubkey_hash: u256) -> bool
```

Returns `true` if `script` is a valid P2WPKH output (`OP_0 <20-byte hash>`)
and the witness program matches `pubkey_hash`.

## Atomic Swap

### swap_state

**Module path:** `zk_bitcoin_verifier::atomic_swap::swap_state`

#### Types

```cairo
#[derive(Drop, Copy, PartialEq)]
pub enum SwapState {
    Initiated,
    BtcLocked,
    EthLocked,
    Revealed,
    Settled,
    Refunded,
}

#[derive(Drop)]
pub struct AtomicSwap {
    pub initiator: felt252,
    pub btc_amount: u64,
    pub eth_amount: u256,
    pub secret_hash: u256,
    pub btc_refund_block: u32,
    pub eth_refund_time: u64,
    pub state: SwapState,
}
```

**State machine transitions:**

```
Initiated → BtcLocked → EthLocked → Revealed → Settled
                              ↘                 ↗
                                   Refunded
```

### swap_verifier

**Module path:** `zk_bitcoin_verifier::atomic_swap::swap_verifier`

#### `verify_btc_lock`

```cairo
pub fn verify_btc_lock(
    secret_hash: u256,
    refund_block: u32,
    current_block: u32,
) -> bool
```

Returns `true` if `current_block < refund_block` (the BTC HTLC has not yet expired).

#### `verify_eth_lock`

```cairo
pub fn verify_eth_lock(eth_amount: u256, secret_hash: u256) -> bool
```

Returns `true` if the ETH HTLC is correctly funded with `eth_amount` wei and
locked with `secret_hash`.

#### `verify_secret_reveal`

```cairo
pub fn verify_secret_reveal(secret: Array<u8>, secret_hash: u256) -> bool
```

Returns `true` if `sha256(secret) == secret_hash`.

#### `verify_swap_settlement`

```cairo
pub fn verify_swap_settlement(swap: @AtomicSwap, secret: Array<u8>) -> bool
```

Returns `true` if the swap is in `EthLocked` state and `verify_secret_reveal` passes.

#### `verify_atomic_swap`

```cairo
pub fn verify_atomic_swap(swap: @AtomicSwap) -> bool
```

Top-level check. Returns `true` if every validity condition is satisfied:
BTC is locked, ETH is locked, and the state machine is in a consistent state.
