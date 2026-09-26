---
title: Quick Start
category: getting-started
order: 1
cli-topic: quickstart
---

# Quick Start

This is a development setup guide, checked September 25, 2026. Use synthetic data and testnet funds. There is no guaranteed setup or proving time.

## Public package access

The [main source repository](https://github.com/repfigit/clearproof) is public. npm packages are at version 0.5.0:

```bash
npm install @clearproof/proof@0.5.0
```

Proof generation requires compatible circuit WASM and proving-key files. Verification requires the matching verification key. Inspect package contents before relying on exported artifact paths; installing the SDK alone does not create a complete proving environment.

0.5.0 includes the pilot and the current `pilot-transfer-v3` profile. `@clearproof/circuits` remains at 0.3.0 and holds only the legacy demo artifacts.

The CLI installs from npm with `npm install -g @clearproof/cli` (verified September 26, 2026). The source setup below builds the same workspaces and adds the Python API, circuits and pilot acceptance tooling.

## Source setup for the unreleased pilot

Prerequisites: Git, Python 3.11+ with uv (the locked install uses 3.12), Node.js 20+ with npm, Circom 2.2.2 and PostgreSQL 18 for the pilot acceptance run.

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
uv sync --frozen --extra dev --python 3.12
npm run build
node packages/cli/dist/index.js --help
```

To generate development artifacts for both proof profiles and run the pilot end to end, follow the [local acceptance guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/local-pilot-acceptance.md):

```bash
curl --fail -L -o /absolute/ppot_0080_17.ptau \
  https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-artifacts \
  --prepared-ptau /absolute/ppot_0080_17.ptau
.venv/bin/python scripts/test_pilot_local.py /absolute/new-development-artifacts/pilot \
  /absolute/new-pilot-run --postgres-bin /usr/lib/postgresql/18/bin
```

Check the file's SHA-256 against the one pinned in the guide before using it. Locally generated development keys are not production keys. `bash scripts/compile_circuits.sh` still builds the legacy profile on its own.

## API exploration

For a disposable local evaluation:

```bash
export AUTH_MODE=api-key
export API_KEY="$(openssl rand -hex 32)"
export PII_MASTER_KEY="$(openssl rand -hex 32)"
uv run uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open [the local OpenAPI UI](http://localhost:8000/docs). Protected requests use `X-API-Key` in this mode. Keep keys stable and protected for any evaluation whose encrypted records need to survive restart.

Starting the server does not establish a working proof workflow. The pilot routes need PostgreSQL, storage keys, tenant trust configuration and compatible artifacts; `/health` reports process liveness only. Do not treat synthetic output as a live transfer authorization.

## Checks

```bash
make test
npm run test:ts
npm run build
```

At this checkout, root `npm test` runs Python tests; `npm run test:ts` runs the TypeScript workspaces. Database integration tests need an isolated PostgreSQL instance. Real circuit checks have additional artifact/toolchain requirements.

See [project status](/docs/status) before planning an integration.
