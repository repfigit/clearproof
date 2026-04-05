.PHONY: install dev lint format test test-unit test-integration test-compliance build-sanctions-tree update-sanctions-oracle benchmark deploy relay-sanctions

install:
	uv sync --all-extras

dev:
	uvicorn src.api.main:app --reload --port 8000

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

test:
	uv run pytest tests/ -v

test-unit:
	uv run pytest tests/unit/ -v

test-integration:
	uv run pytest tests/integration/ -v

test-compliance:
	uv run pytest tests/compliance/ -v

build-sanctions-tree:
	python scripts/build_sanctions_tree.py

update-sanctions-oracle:
	@echo "Step 1: Rebuild sanctions tree from live feeds..."
	python scripts/build_sanctions_tree.py
	@echo ""
	@echo "Step 2: Submit new root to on-chain oracle..."
	cd packages/contracts && npx hardhat run scripts/update-sanctions-root.ts --network $(NETWORK)

benchmark:
	python scripts/benchmark_proof_latency.py

# Multi-chain deployment — deploy all contracts to a single network
# Usage: make deploy NETWORK=arbitrum-sepolia
deploy:
	cd packages/contracts && npx hardhat run scripts/deploy-multichain.ts --network $(NETWORK)

# Multi-chain sanctions relay — sync root to all deployed networks
# Usage: make relay-sanctions
# Usage: RELAY_NETWORKS=sepolia,base-sepolia make relay-sanctions
relay-sanctions:
	@echo "Step 1: Rebuild sanctions tree from live feeds..."
	python scripts/build_sanctions_tree.py
	@echo ""
	@echo "Step 2: Relay root to all deployed chains..."
	cd packages/contracts && npx ts-node scripts/relay-sanctions-root.ts
