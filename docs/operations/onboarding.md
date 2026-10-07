# Try Clearproof from a source checkout

Choose a path by what you need to inspect. Neither path establishes production
assurance, real customer acceptance or legal compliance.

## Quick real-proof inspection

Install Git, Node 22.12+ and npm. From a fresh checkout:

```bash
git clone --branch main https://github.com/repfigit/clearproof.git
cd clearproof
npm exec --yes --package=npm@11.9.0 -- npm ci
npm run build --workspace=@clearproof/proof
node scripts/inspect_example.mjs
```

The source script reads only the existing public fixture under
`tests/vectors/compliance/`, checks its verification-key hash, pairs the proof
through the real SDK, and changes the registry-domain signal for a second
pairing check. It generates no new proof or keys, reads no environment secrets,
contacts no service and writes no files. This script is available in the source
checkout; it is not a new command in the published 0.7.2 CLI.

Expected: `cryptographic_valid: true`, `policy_accepted: false`,
`rejection_reasons: ["threshold_mismatch"]`, `tampered_pairing_rejected: true`,
`authorization_consumed: false`, `production_eligible: false`, exit 0.
Exit 1 means the fixture, pairing or expected rejection checks did not succeed.
Restore the unchanged fixture and rebuild the SDK from the same checkout.

For generation with separately supplied compatible artifacts, the legacy
`clearproof demo` remains available. In this source checkout its export requires
a new directory, records selected artifact hashes and marks compiler/setup
provenance as not established. It makes no fixed runtime promise. This does not
change the committed historical fixture or claim a new npm release.

This is a historical **legacy 16-signal, single-party development fixture**. Its
thresholds deliberately fail policy binding, chain ID is zero and timestamp is
old. Preserve those negative cases. It illustrates the difference between a
pairing-valid proof and an accepted statement; it is not a current pilot transfer.

## Complete current pilot

Follow [local pilot acceptance](local-pilot-acceptance.md) for locked installation,
Circom 2.2.2, PostgreSQL 18 and the pinned public powers-of-tau download. That
workflow builds real unapproved artifacts outside the checkout and exercises
the eight-signal `pilot-transfer-v3` path, encrypted PostgreSQL records,
observations, counterparty scenarios and offline historical review.

Before creating the owned database and local EVM:

```bash
.venv/bin/python scripts/test_pilot_local.py /absolute/development-artifacts/pilot \
  /absolute/new-pilot-run --postgres-bin /usr/lib/postgresql/18/bin --preflight
```

Preflight requires a new output path but does not create it. It checks Python
dependencies, Node/Hardhat, built CLI, PostgreSQL version and executable access,
then runs the artifact doctor in both modes. The development profile must pass;
production use must fail. Remove `--preflight` to run acceptance with the same
arguments. The normal run repeats preflight before creating any output or service.
Read `pilot/run.json` only after success. Its report-only hash inventory is local
integrity evidence, not a signed authenticity or clean-environment attestation.

## Recover a failed complete run

1. For dependency or version errors, repeat the locked install and workspace
   build from the same checkout, select the correct interpreter and PostgreSQL
   binaries, then rerun preflight. Preflight failure starts no service.
2. For artifact or pin rejection, restore the complete matching development
   bundle or regenerate into a new directory. Preserve the exact bundle used
   by retained reports. Never edit a manifest pin to conceal a mismatch.
3. After an acceptance failure, the runner attempts to stop both owned services.
   If it reports PostgreSQL cleanup failure, inspect only that run's private
   setup log and cluster state. If that cluster is still running, stop it with
   `pg_ctl -D /absolute/failed-run/postgres -m immediate -w stop`, using the same
   PostgreSQL binaries. Do not stop unrelated databases or EVM processes.
4. Keep partial output private, correct the failure and choose a new run path.
   Existing directories are never reused; no successful inventory is published
   for a failed run. Keep database/logs and `pilot/private/` out of shared reports.

## Explore the API and current SDK

See the hosted [quickstart](https://docs.clearproof.world/docs/quickstart) for a
disposable loopback API, generated `/openapi.json`, and offline schema export
without application startup. The schema documents implementation shape, not
configured trust or production readiness. `/health` reports process liveness.
API-key pilot access needs operator-selected tenant, actor and role settings.

Start with [current SDK inspection](https://docs.clearproof.world/docs/sdk):
`inspectCurrentProof` needs `proof:inspect` and `evidence:decrypt`, leaves
authorization unconsumed and uses the selected API as its trust boundary.
An independently configured target and current retained state are prerequisites.
