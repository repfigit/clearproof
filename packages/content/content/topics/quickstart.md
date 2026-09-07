---
title: Quick Start
category: getting-started
order: 1
cli-topic: quickstart
---

# Quick Start

This is a development setup guide, checked September 5, 2026. Use synthetic data and testnet funds. There is no guaranteed setup or proving time.

## Public package access

The [main source repository](https://github.com/repfigit/clearproof) is public. Public npm packages are available at version 0.3.0:

```bash
npm install @clearproof/proof@0.3.0
```

Proof generation requires compatible circuit WASM and proving-key files. Verification requires the matching verification key. Inspect package contents before relying on exported artifact paths; installing the SDK alone does not create a complete proving environment.

The development checkout is version 0.4.0. Do not assume it is identical to the published packages.

The published CLI currently cannot be installed from the public registry because its `@clearproof/content` dependency is unavailable. The standalone proof SDK installation was verified. Use a source checkout for CLI evaluation.

## Source setup for the unreleased pilot

Prerequisites: Git, Python 3.11+, Node.js 20+ with npm, and circom 2.2.2 for the circuit compilation path used in CI.

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
uv sync --frozen --extra dev --python 3.12
npm run build
node packages/cli/dist/index.js --help
```

To compile development artifacts with the repository's documented setup:

```bash
bash scripts/compile_circuits.sh
```

Expected artifact locations include `artifacts/compliance_js/compliance.wasm`, `artifacts/compliance_final.zkey` and `artifacts/verification_key.json`. The compilation path requires Powers of Tau input and circuit-specific setup. Locally generated development keys are not production keys.

## API exploration

For a disposable local evaluation:

```bash
export AUTH_MODE=api-key
export API_KEY="$(openssl rand -hex 32)"
export PII_MASTER_KEY="$(openssl rand -hex 32)"
uv run uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open [the local OpenAPI UI](http://localhost:8000/docs). Protected requests use `X-API-Key` in this mode. Keep keys stable and protected for any evaluation whose encrypted records need to survive restart.

Starting the server does not establish a working proof workflow. Generation requires compatible artifacts, credential/issuer state and sanctions witnesses. Durable state, authenticated input binding and API/circuit consistency are still being completed. Do not treat synthetic demo output as a live transfer authorization.

## Checks

```bash
make test
npm run test:ts
npm run build
```

At this checkout, root `npm test` runs Python tests; `npm run test:ts` runs the TypeScript workspaces. Database integration tests need an isolated PostgreSQL instance. Real circuit checks have additional artifact/toolchain requirements.

See [project status](/docs/status) before planning an integration.
