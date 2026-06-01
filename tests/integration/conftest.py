import json
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def mainnet_blocks():
    with open(FIXTURES_DIR / "mainnet_blocks.json") as f:
        return json.load(f)


@pytest.fixture
def genesis_block(mainnet_blocks):
    return mainnet_blocks["blocks"]["0"]


@pytest.fixture
def test_vectors():
    with open(FIXTURES_DIR / "test_vectors.json") as f:
        return json.load(f)


@pytest.fixture
def sha256_vectors(test_vectors):
    return test_vectors["sha256"]


@pytest.fixture
def secp256k1_vectors(test_vectors):
    return test_vectors["secp256k1"]


@pytest.fixture
def merkle_vectors(test_vectors):
    return test_vectors["merkle"]
