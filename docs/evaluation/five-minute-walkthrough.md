# Five-minute synthetic walkthrough

This walkthrough uses the committed historical fixture and the real proof SDK. It
takes about five minutes on a fresh checkout with Node 22.12+ and npm. It creates
no proof, no keys and no database, reads no secrets and writes no files. It is an
inspection of an old single-party fixture, not a current pilot transfer and not
production assurance.

## 1. Prepare the checkout (about 3 minutes)

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
npm run build --workspace=@clearproof/proof
```

Record the `git rev-parse HEAD` value before continuing. Keep install time
separate from review time.

## 2. Confirm the fixture is the expected one (about 30 seconds)

```bash
git rev-parse HEAD
sha256sum tests/vectors/compliance/proof.json tests/vectors/compliance/verification_key.json
cat tests/vectors/compliance/MANIFEST.json
```

Compare `verification_key.json` with `artifacts.vkey_sha256` in the manifest. The
manifest also pins the original wasm/zkey hashes and records that this is a
single-party development setup, not a production one. A mismatch means the
fixture or checkout is not the one you intend to review.

## 3. Run the inspection (about 30 seconds)

```bash
node scripts/inspect_example.mjs
```

The script checks the verification-key hash, pairs the proof through the SDK and
changes the registry-domain signal for a second pairing check. It exits non-zero
if any check fails.

Expected output fields and values:

| Field | Expected |
| --- | --- |
| `cryptographic_valid` | `true` |
| `policy_accepted` | `false` |
| `rejection_reasons` | `["threshold_mismatch"]` |
| `tampered_pairing_rejected` | `true` |
| `authorization_consumed` | `false` |
| `production_eligible` | `false` |
| exit code | `0` |

The pair of facts to take away: the proof is cryptographically valid, and the
policy still rejects it. The fixture is a **legacy 16-signal** example; its chain
ID is zero and its timestamp is old. Preserve those negatives.

## 4. Record it (about 1 minute)

Copy the [report template](report-template.md) and fill only the fields this
walkthrough actually measured. Mark the rest unknown. Start the
[evaluation feedback form](https://github.com/repfigit/clearproof/issues/new?template=evaluation.yml)
afterward if the result was useful.

## What this does not show

- It does not exercise the current eight-signal `pilot-transfer-v3` workflow,
  encrypted storage, observations or history review. Use the
  [complete local pilot](../operations/local-pilot-acceptance.md) for those.
- It does not establish artifact or key provenance. The fixture is historical and
  the SDK build is local.
- A successful run is one completed example, not an internal or external review.

For a predeclared set of current-profile cases and expected labels, use the
[expected-outcome test pack](expected-outcomes.md).
