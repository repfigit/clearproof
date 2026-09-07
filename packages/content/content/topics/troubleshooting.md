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

## `PII_MASTER_KEY` validation error at startup

**Symptom:** API startup rejects a missing or insufficiently long `PII_MASTER_KEY`.

**Fix:** Supply 64 hex characters or at least 32 UTF-8 bytes. Generate a random value for a disposable local evaluation:

```bash
export PII_MASTER_KEY="$(openssl rand -hex 32)"
```

The startup check validates encoding and length, not randomness. Protect and retain the key when encrypted records must survive restart; changing it can prevent decryption of existing records.

## Proof generation returns 500

**Symptom:** `POST /proof/generate` fails because runtime state or proving artifacts are unavailable.

Check that the requested credential, trusted issuer root, sanctions witnesses and compatible artifacts are available to the running process. Starting the API, issuing one development credential or building an offline sanctions tree does not alone establish a complete generation workflow. See the quickstart and current project status.

## Sanctions oracle is stale

**Symptom:** On-chain `verifyAndRecord()` reverts with `SanctionsOracleStale`.

**Fix:** The oracle's grace period defaults to 24 hours. Update the sanctions root:

```bash
python scripts/relay_sanctions_root.py --network sepolia
```

Check the configured grace period and actual root update time on each intended chain. Test fixtures may deliberately exercise stale state; do not bypass freshness checks to authorize a transfer.

## Nullifier already spent

**Symptom:** The development `verifyAndRecord()` path reverts with `ProofAlreadyUsed` or `TransferAlreadyRecorded`.

**Cause:** The nullifier or transfer reference has already been recorded in the target registry.

**Fix:** Inspect the original transaction and transfer state before retrying. Preserve the same transfer identity across retries; do not create a new idempotency key just to bypass duplicate protection. API/registry transfer-hash consistency remains planned work.

## WASM prover not found

**Symptom:** `@clearproof/proof` throws `ENOENT: no such file or directory` for `compliance.wasm`.

**Fix:** Compile circuits first:

```bash
bash scripts/compile_circuits.sh
```

Pass the actual compatible WASM, proving-key and verification-key paths to the SDK. The repository's development build writes the WASM under `artifacts/compliance_js/`; public package installation alone is not a complete proving setup.

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
