.PHONY: install dev lint test test-unit test-integration test-compliance spike-ezkl docker-up docker-down benchmark

install:
	pip install -e ".[all]"

dev:
	uvicorn src.api.main:app --reload --port 8000

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-compliance:
	pytest tests/compliance/ -v

spike-ezkl:
	python scripts/spike_ezkl.py

build-sanctions-tree:
	python scripts/build_sanctions_tree.py

benchmark:
	python scripts/benchmark_proof_latency.py

docker-up:
	docker compose -f docker/docker-compose.yml up -d

docker-down:
	docker compose -f docker/docker-compose.yml down
