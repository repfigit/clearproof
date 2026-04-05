---
title: Troubleshooting
category: operations
order: 8
cli-topic: troubleshooting
---

# Troubleshooting

Common issues and fixes for clearproof development and deployment.

## Circuit compilation fails

**Symptom:** `bash scripts/compile_circuits.sh` exits with a circom error.

**Fix:** Ensure circom 2.2.2+ is installed and on your PATH:

```bash
circom --version
# Expected: circom compiler 2.2.2 or higher
```

If you see `command not found`, follow the [circom install guide](https://docs.circom.io/getting-started/installation/).

## `PII_MASTER_KEY` entropy error at startup

**Symptom:** API server refuses to start with `PII_MASTER_KEY entropy too low`.

**Fix:** The key must be at least 32 bytes (64 hex characters):

```bash
export PII_MASTER_KEY=$(openssl rand -hex 32)
```

Do not use short strings or predictable values -- the startup check will reject them.

## Proof generation returns 500

**Symptom:** `POST /proof/generate` returns HTTP 500 with `missing runtime state`.

**Causes:**
1. No credentials issued yet -- issue at least one via `POST /credential/issue`
2. Sanctions tree not built -- run `python scripts/build_sanctions_tree.py --offline`
3. Issuer registry empty -- the first credential issuance populates this automatically

## Sanctions oracle is stale

**Symptom:** On-chain `verifyAndRecord()` reverts with `SanctionsOracleStale`.

**Fix:** The oracle's grace period defaults to 24 hours. Update the sanctions root:

```bash
python scripts/relay_sanctions_root.py --network sepolia
```

If running locally with Hardhat, advance time or use a longer grace period in tests.

## Nullifier already spent

**Symptom:** `verifyAndRecord()` reverts with `NullifierAlreadySpent`.

**Cause:** The same credential + transfer_id combination was used before. Each proof requires a unique `idempotency_key` to produce a unique `transfer_id_hash` and therefore a unique nullifier.

**Fix:** Use a different `idempotency_key` for each transfer attempt.

## WASM prover not found

**Symptom:** `@clearproof/proof` throws `ENOENT: no such file or directory` for `compliance.wasm`.

**Fix:** Compile circuits first:

```bash
bash scripts/compile_circuits.sh
```

The SDK expects artifacts at `artifacts/compliance_js/compliance.wasm` relative to the repo root.

## Hardhat tests fail with `HH700`

**Symptom:** `npx hardhat test` errors with `HH700: Artifact not found`.

**Fix:** Compile contracts before running tests:

```bash
cd packages/contracts
npx hardhat compile
npx hardhat test
```

## CORS errors in browser

**Symptom:** Browser console shows `Access-Control-Allow-Origin` errors when calling the API.

**Fix:** Set `CORS_ALLOWED_ORIGINS` to your frontend origin:

```bash
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
```

Using `*` with credentials enabled will trigger a startup warning and may not work in all browsers.

## TypeScript build errors after pulling

**Symptom:** `npm run build` fails with type errors after `git pull`.

**Fix:** Clean install and rebuild:

```bash
rm -rf node_modules packages/*/dist
npm install
npm run build
```
