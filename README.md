# ZK Bitcoin Verifier

[![CI](https://github.com/amd/zk-bitcoin-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/amd/zk-bitcoin-verifier/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Cairo](https://img.shields.io/badge/Cairo-2.x-orange)](https://www.cairo-lang.org/)
[![Starknet](https://img.shields.io/badge/Starknet-ready-purple)](https://starknet.io/)

A Cairo 2.x library for verifying Bitcoin block headers, transactions, and atomic swaps
entirely on-chain on Starknet, using zero-knowledge proofs.

## Mission

Enable trustless Bitcoin-to-Starknet interoperability by proving Bitcoin state
(block hashes, transaction inclusion, UTXO ownership, HTLC conditions) inside
Cairo's provable computation model — without relying on any trusted oracle or
bridge custodian.

## Architecture

```
zk_bitcoin_verifier
├── crypto/                     # Low-level primitives
│   ├── sha256       ──────────► SHA-256 / double-SHA-256
│   ├── secp256k1    ──────────► ECDSA verify + pubkey recovery
│   ├── merkle       ──────────► Merkle root + inclusion proof
│   └── field_utils  ──────────► Byte ↔ felt252 / u256 conversions
│
├── bitcoin/                    # Bitcoin protocol layer
│   ├── block_header ──────────► 80-byte header parse + PoW verify
│   ├── transaction  ──────────► Tx parse + sighash + signature verify
│   ├── utxo         ──────────► Outpoint hash + ownership check
│   └── script       ──────────► P2PKH / P2SH / P2WPKH validation
│
└── atomic_swap/                # Cross-chain swap layer
    ├── swap_state   ──────────► SwapState enum + AtomicSwap struct
    └── swap_verifier ─────────► BTC lock / ETH lock / settlement proofs
```

## Quick Start

**Prerequisites:** [Scarb](https://docs.swmansion.com/scarb/) >= 2.6.3

```bash
# Build the library
scarb build

# Run the test suite
scarb test

# Check formatting
scarb fmt --check

# All-in-one (format check + build + test)
make all
```

**Python integration tests** (requires Python 3.11+ and pytest):

```bash
# Install pytest if you haven't
pip install pytest
make py-test
```

## Module Overview

| Module | Path | Status | Description |
|--------|------|--------|-------------|
| `sha256` | `src/crypto/sha256.cairo` | Stub | SHA-256 and double-SHA-256 |
| `secp256k1` | `src/crypto/secp256k1.cairo` | Stub | ECDSA verify + pubkey recovery |
| `merkle` | `src/crypto/merkle.cairo` | Stub | Merkle proof verify + root compute |
| `field_utils` | `src/crypto/field_utils.cairo` | Stub | Byte/field conversions |
| `block_header` | `src/bitcoin/block_header.cairo` | Stub | Header parse + PoW verify |
| `transaction` | `src/bitcoin/transaction.cairo` | Stub | Tx parse + sighash verify |
| `utxo` | `src/bitcoin/utxo.cairo` | Stub | UTXO ownership proof |
| `script` | `src/bitcoin/script.cairo` | Stub | Script type validation |
| `swap_state` | `src/atomic_swap/swap_state.cairo` | Complete | State machine types |
| `swap_verifier` | `src/atomic_swap/swap_verifier.cairo` | Stub | HTLC condition proofs |

## API Reference Summary

### Crypto

```cairo
// SHA-256 of raw bytes
pub fn sha256(input: Array<u8>) -> u256

// Double SHA-256 (Bitcoin standard)
pub fn sha256d(input: Array<u8>) -> u256

// Verify Merkle inclusion proof
pub fn merkle_verify(leaf: u256, proof: Array<u256>, root: u256) -> bool

// ECDSA signature verification on secp256k1
pub fn secp256k1_verify_signature(
    message_hash: u256, sig: Signature, pubkey: Point
) -> bool
```

### Bitcoin

```cairo
// Full block header validation (hash + difficulty)
pub fn verify_block_header(header: BlockHeader) -> bool

// Decode compact nBits to 256-bit difficulty target
pub fn bits_to_target(bits: u32) -> u256

// Verify a specific input's scriptSig
pub fn verify_transaction_signature(
    tx: @Transaction, input_idx: u32, pubkey: felt252
) -> bool

// Compute txid (double-SHA-256 of serialised tx)
pub fn compute_transaction_hash(tx: @Transaction) -> u256
```

### Atomic Swap

```cairo
// Verify BTC HTLC is live (before refund block)
pub fn verify_btc_lock(
    secret_hash: u256, refund_block: u32, current_block: u32
) -> bool

// Verify revealed preimage matches the hash lock
pub fn verify_secret_reveal(secret: Array<u8>, secret_hash: u256) -> bool

// Top-level swap validity check
pub fn verify_atomic_swap(swap: @AtomicSwap) -> bool
```

## Contributing

1. Fork the repository and create a feature branch from `develop`.
2. Implement one module at a time — each function has a `// TODO` comment
   describing the expected behaviour.
3. Ensure `make all` passes before opening a pull request.
4. Add or update tests so that the new implementation makes previously-failing
   tests pass.
5. Follow [Conventional Commits](https://www.conventionalcommits.org/) for
   commit messages.

---

## License

Copyright 2026 AMD. Licensed under the [Apache License, Version 2.0](../LICENSE).
