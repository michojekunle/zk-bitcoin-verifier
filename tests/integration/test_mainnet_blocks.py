"""
Integration tests for mainnet Bitcoin block verification via the Cairo ZK verifier.

All tests are skipped until the Cairo FFI bridge is wired up. Once the bridge is
implemented, remove the skip decorator and supply the `cairo_verifier` fixture.
"""
import pytest


@pytest.mark.skip(reason="Cairo FFI not yet wired")
def test_genesis_block_hash(genesis_block):
    """
    The verifier must compute the genesis block hash as:
    000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    """
    expected_hash = genesis_block["hash"]
    # result = cairo_verifier.verify_block_header(genesis_block)
    # assert result["hash"] == expected_hash
    raise NotImplementedError("Cairo FFI bridge not implemented")


@pytest.mark.skip(reason="Cairo FFI not yet wired")
def test_block_700000_header(mainnet_blocks):
    """
    Block #700000 header verification must succeed with the known hash:
    0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959
    """
    block = mainnet_blocks["blocks"]["700000"]
    expected_hash = block["hash"]
    # result = cairo_verifier.verify_block_header(block)
    # assert result["valid"] is True
    # assert result["hash"] == expected_hash
    raise NotImplementedError("Cairo FFI bridge not implemented")


@pytest.mark.skip(reason="Cairo FFI not yet wired")
def test_coinbase_tx_verification(genesis_block):
    """
    The genesis coinbase transaction must be identified as a valid coinbase.

    Coinbase txid (big-endian):
    4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
    """
    coinbase_txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    # result = cairo_verifier.verify_coinbase_transaction(coinbase_txid)
    # assert result["valid"] is True
    raise NotImplementedError("Cairo FFI bridge not implemented")
