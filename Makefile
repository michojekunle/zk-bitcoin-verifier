.PHONY: build test fmt fmt-check clean coverage py-test all

build:
	scarb build

test:
	scarb test

fmt:
	scarb fmt

fmt-check:
	scarb fmt --check

clean:
	rm -rf target/

coverage:
	scarb test --features enable_for_testing

py-test:
	pytest tests/integration/ -v

all: fmt-check build test
