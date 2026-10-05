.PHONY: install dev lint format test test-unit test-integration test-compliance coverage build-sanctions-tree update-sanctions-oracle deploy relay-sanctions refresh-and-relay-sanctions regen-protobufs check-protobufs

RUFF_PATHS := src tests scripts

install:
	uv sync --all-extras

dev:
	uv run uvicorn src.api.main:app --reload --port 8000

lint:
	uv run ruff check $(RUFF_PATHS)
	uv run ruff format --check $(RUFF_PATHS)

format:
	uv run ruff format $(RUFF_PATHS)
	uv run ruff check --fix $(RUFF_PATHS)

test:
	uv run python -m pytest tests/ -v

test-unit:
	uv run python -m pytest tests/unit/ -v

test-integration:
	uv run python -m pytest tests/integration/ -v

test-compliance:
	uv run python -m pytest tests/compliance/ -v

# Full suite with branch coverage of src/ and the 100% gate (pyproject fail_under).
# CI's gate (circuits job) additionally uses PostgreSQL (DATABASE_URL), fresh circuit
# artifacts (CLEARPROOF_PILOT_TEST_ARTIFACTS / CLEARPROOF_LEGACY_TEST_ARTIFACTS) and combines
# checkpoint/mirror evidence; without those, gated tests skip and the gate will not reach 100%.
coverage:
	uv run python -m pytest tests --cov=src --cov-branch --cov-report=term -q

build-sanctions-tree:
	uv run python scripts/build_sanctions_tree.py

# Regenerate gRPC stubs from protos/ (pinned grpcio-tools, documented post-processing)
regen-protobufs:
	bash scripts/regen_protobufs.sh

# Verify committed gRPC stubs match protos/ (runs in CI)
check-protobufs:
	bash scripts/regen_protobufs.sh --check

# Submit the existing artifacts/sanctions_tree.json root to one network's oracle.
# Does not rebuild the tree: run `make build-sanctions-tree` (and review it) first.
# Usage: make update-sanctions-oracle NETWORK=sepolia
update-sanctions-oracle:
	cd packages/contracts && npx hardhat run scripts/update-sanctions-root.ts --network $(NETWORK)

# Multi-chain deployment — deploy all contracts to a single network
# Usage: make deploy NETWORK=arbitrum-sepolia
deploy:
	cd packages/contracts && npx hardhat run scripts/deploy-multichain.ts --network $(NETWORK)

# Multi-chain sanctions relay — sync the existing artifacts/sanctions_tree.json root to all
# deployed networks. Does not rebuild the tree.
# Usage: make relay-sanctions
# Usage: RELAY_NETWORKS=sepolia,base-sepolia make relay-sanctions
relay-sanctions:
	cd packages/contracts && npx ts-node scripts/relay-sanctions-root.ts

# Explicit combined flow: rebuild from live feeds, then relay the new root everywhere.
refresh-and-relay-sanctions:
	$(MAKE) build-sanctions-tree
	$(MAKE) relay-sanctions
