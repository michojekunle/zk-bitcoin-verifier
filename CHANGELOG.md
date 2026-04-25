# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure with Scarb 2.6.3 configuration
- Crypto primitive stubs: SHA-256, SHA-256d, secp256k1 ECDSA, Merkle tree
- Bitcoin verification stubs: block header parsing, transaction parsing, UTXO, Script
- Atomic swap state machine (SwapState enum, AtomicSwap struct)
- Atomic swap verifier stubs: BTC lock, ETH lock, secret reveal, settlement
- Full failing test suite (50+ tests across crypto, bitcoin, and atomic swap modules)
- Python integration test skeleton with real Bitcoin mainnet fixture data
- GitHub Actions CI/CD pipeline for Cairo build/test and Python integration tests
- Makefile with build, test, fmt, clean, and coverage targets
