import json
import os
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
