---
title: Quick Start
category: getting-started
order: 1
cli-topic: quickstart
---

# Quick Start

This is a development setup guide. Use synthetic data and testnet funds. Nothing in Clearproof is independently audited, every proving key is a development key, and the pilot contracts are not deployed on any network. There is no guaranteed setup or proving time.

The commands on this page that need no circuit artifacts and no PostgreSQL were rerun from a source checkout on November 11, 2026. The complete pilot run was last checked on September 25, 2026.

## Two proof profiles

| Profile | Public signals | Status | Where to start |
| --- | --- | --- | --- |
| `pilot-transfer-v3` | 8 | Current. Used by the pilot API, the pilot CLI commands and the pilot contracts | [Current profile: complete local pilot](#current-profile-complete-local-pilot) |
| Legacy `compliance.circom` | 16 | Demo and parity path only. A legacy proof is never a pilot authorization | [Legacy demo: quick verification example](#legacy-demo-quick-verification-example) |

The profiles have different circuits, keys and verifiers. Do not pick one by counting signals.

## Packages and source versions

The [main source repository](https://github.com/repfigit/clearproof) is public. The npm packages were last published as version 0.7.2 on October 7, 2026:

```bash
npm install @clearproof/proof@0.7.2
```

A source checkout of `main` can contain changes made after that release, even while its `package.json` files still say 0.7.2. `CHANGELOG.md` lists them under `[Unreleased]`. Compare the two before relying on either:

```bash
npm view @clearproof/proof version
git log --oneline v0.7.2..HEAD
```

The published SDK and CLI include the pilot commands and API clients for `pilot-transfer-v3`. They do not include circuit artifacts: `@clearproof/circuits` publishes circuit sources only, with no compiled WASM and no keys. Installing a package does not create a proving environment.

The CLI installs from npm with `npm install -g @clearproof/cli` (verified September 26, 2026). The source setup below builds the same workspaces and adds the Python API, circuits and pilot acceptance tooling.

## Current profile: complete local pilot

The current profile has no example that runs without generated circuit artifacts. There are two levels.

### Without Circom or PostgreSQL

Prerequisites: Git and Node.js 22.12+ with npm.

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
npm run build
node packages/cli/dist/index.js --help
(cd packages/contracts && npx hardhat test test/PilotCurrentRegistryLogic.test.ts test/PilotRootCheckpoint.test.ts)
```

The build compiles the TypeScript workspaces and the docs site. The help output lists the pilot commands (`inspect-current`, `authorize-current`, `observation`, `policy`, `investigation`, `counterparty`, `doctor`, `verify-history`) and marks `prove`, `verify`, `demo` and `explain` as legacy. The two Hardhat suites exercise `PilotCurrentRegistry` (with a mock verifier) and `PilotRootCheckpoint` on a local in-process EVM: checkpoints, publisher epochs, pause, domain binding and receipt mirroring. No proof is generated or verified, and nothing is deployed to a network.

The pilot CLI commands other than `doctor` and `verify-history` call an authenticated Clearproof API that you run; see [API exploration](#api-exploration).

### Complete run

Prerequisites: Git, Python 3.11+ with uv (the locked install uses 3.12), Node.js 22.12+ with npm, Circom 2.2.2 and PostgreSQL 18.

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
uv sync --frozen --extra dev --python 3.12
npm run build
```

To generate development artifacts for both proof profiles and run the pilot end to end, follow the [local acceptance guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/local-pilot-acceptance.md):

```bash
curl --fail -L -o /absolute/ppot_0080_17.ptau \
  https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau
echo "f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c  /absolute/ppot_0080_17.ptau" | sha256sum --check
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-artifacts \
  --prepared-ptau /absolute/ppot_0080_17.ptau
.venv/bin/python scripts/test_pilot_local.py /absolute/new-development-artifacts/pilot \
  /absolute/new-pilot-run --postgres-bin /usr/lib/postgresql/18/bin --preflight
.venv/bin/python scripts/test_pilot_local.py /absolute/new-development-artifacts/pilot \
  /absolute/new-pilot-run --postgres-bin /usr/lib/postgresql/18/bin
```

Stop if the SHA-256 check fails. The downloaded file is the public powers-of-tau input that CI also uses; the keys derived from it here come from a single local contribution and are development keys, not production keys.

Preflight checks the selected Python dependencies, Node/Hardhat, built CLI, PostgreSQL 18 and the artifact doctor's development acceptance and production rejection. It creates no output directory and starts no service. The full run exercises the eight-signal `pilot-transfer-v3` path, encrypted PostgreSQL records, observations, counterparty scenarios and offline historical review. It owns its database and EVM, stops them on failure, and retains nine scoped reports plus a report-only inventory. Keep `private/`, database files and logs private. After a failure, follow the [recovery steps](https://github.com/repfigit/clearproof/blob/main/docs/operations/onboarding.md#recover-a-failed-complete-run) and use a new run directory.

## Legacy demo: quick verification example

This example uses the **legacy 16-signal profile**, not `pilot-transfer-v3`. It is kept because it runs with Node alone.

Prerequisites: Git and Node.js 22.12+ with npm. It needs no Circom, PostgreSQL, Python, proving key, testnet account or API credentials.

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
npm run build --workspace=@clearproof/proof
node scripts/inspect_example.mjs
```

The script independently pairs the repository's existing **historical legacy 16-signal development proof**, then alters its public registry domain and verifies that pairing rejects the tampered statement. Expected output includes:

```json
{
  "cryptographic_valid": true,
  "policy_accepted": false,
  "rejection_reasons": ["threshold_mismatch"],
  "tampered_pairing_rejected": true,
  "authorization_consumed": false,
  "production_eligible": false
}
```

The original fixture deliberately has policy-negative thresholds, a zero chain ID and an old timestamp. Exit 0 means the expected pairing, policy rejection and tamper rejection occurred. It does not authorize a transfer or demonstrate the current eight-signal pilot. If the example fails, rebuild the SDK from this checkout and restore the unchanged fixture; do not alter its thresholds to make it pass. See the [repository guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/onboarding.md).

### Legacy proof generation

`clearproof prove`, `verify` and `demo` generate and verify legacy proofs locally. They need legacy artifacts, which no package supplies. The `scripts/test_development_circuits.py` run above writes a matching development set, and then:

```bash
node packages/cli/dist/index.js demo --artifacts /absolute/new-development-artifacts/legacy
```

`bash scripts/compile_circuits.sh` builds the legacy circuit on its own into `artifacts/`; it does not build the pilot circuit and uses a different powers-of-tau file from CI.

## API exploration

For a disposable local evaluation:

```bash
export AUTH_MODE=api-key
export API_KEY="$(openssl rand -hex 32)"
export PII_MASTER_KEY="$(openssl rand -hex 32)"
export HKDF_SALT="$(openssl rand -hex 32)"
uv run uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open [the local OpenAPI UI](http://localhost:8000/docs). Protected requests use `X-API-Key` in this mode. Keep keys and the HKDF salt stable and protected for any evaluation whose encrypted records need to survive restart. The commands above generate new material for a disposable run; do not rerun them over retained data. See the [legacy encryption migration guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/legacy-encryption-migration.md) before upgrading a deployment that used the old default salt.

Download the schema generated by this running instance from `http://localhost:8000/openapi.json`. To generate a schema from a source checkout without starting the API or connecting storage:

```bash
uv run python -c 'import json; from src.api.main import create_app; print(json.dumps(create_app().openapi(), indent=2, sort_keys=True))' > /absolute/openapi.json
```

The schema describes routes and validation; deployment trust and role requirements still apply. The `/proof/generate` and `/proof/verify` routes belong to the legacy profile. Pilot routes are under `/pilot/` (wallet-ownership routes under `/wallet/`) and in API-key mode additionally require operator-configured `API_KEY_TENANT_ID`, `API_KEY_ACTOR_ID` and `API_KEY_ROLES`; use the intended tenant/actor and only the roles needed for the operation. See the [current SDK example](/docs/sdk#current-pilot-read-only-inspection).

Starting the server does not establish a working proof workflow. The pilot routes need PostgreSQL, storage keys, tenant trust configuration and compatible artifacts; `/health` reports process liveness only. Do not treat synthetic output as a live transfer authorization.

## Checks

```bash
make test
npm run test:ts
npm run build
```

At this checkout, root `npm test` runs Python tests; `npm run test:ts` runs the TypeScript workspaces. Database integration tests need an isolated PostgreSQL instance. Real circuit checks have additional artifact/toolchain requirements.

See [project status](/docs/status) before planning an integration.
