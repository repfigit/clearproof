# Test vectors

These are development fixtures, not production attestations. The legacy
`compliance/` vector has 16 public signals; the current `pilot-transfer-v3`
profile has eight and uses separate artifacts and acceptance tests.

## Historical legacy fixture

The committed `compliance/` input, proof, public signals and verification key
form one historical key set. Its pairing check passes, but its US thresholds
are intentionally rejected by the SDK's policy binding. Its domain chain ID
is zero. Preserve those negative cases rather than advertising this proof as
a policy-valid or replay-protected transfer.

| File | Content |
| --- | --- |
| `input.json` | Synthetic camelCase SDK input, including private witness fields |
| `proof.json` | Groth16 proof for the historical development key |
| `public.json` | Recorded 16-signal statement |
| `verification_key.json` | Matching historical development verification key |
| `MANIFEST.json` | Historical artifact hashes, toolchain and development warning |

Ordinary SDK tests require the committed files, compare every declared public
input with the recorded statement, verify pairing and preserve threshold-policy
rejection. Contract tests pair the same proof against the historical verifier.
Those checks alone cannot establish that private witness fields derive the
recorded public statement.

## One-command input-derived regeneration

After `npm ci` and `uv sync --locked --extra dev`, with Node and Circom installed,
run from the repository root:

```bash
uv run python scripts/test_development_circuits.py /tmp/clearproof-development-vectors
```

The output directory must be new. The command prepares development parameters,
builds both profiles and their matching keys, and runs SDK/Python/local-EVM
acceptance. `--prepared-ptau /absolute/path/parameters.ptau` can reuse an explicit
local development input; CI verifies its pinned public phase-1 parameters before
supplying them. Fresh phase-2 keys remain unapproved in both cases.

For the legacy fixture, the command computes the witness from `input.json`,
generates a fresh proof, compares **all 16 derived signals** with committed
`public.json`, and independently pairs the new proof. A mismatch or unsatisfied
private witness fails the command. It retains these matching files together in
`legacy/regenerated-parity/`:

- `input.json`, `proof.json`, `public.json` and `verification_key.json`;
- `MANIFEST.json`, written after successful derivation and pairing, with hashes
  of all four files, the actual WASM/key hashes, phase-1 digest and the
  `devKeysOnly: true` / `NOT valid for production` warning.

The fresh proof is randomized and uses a new key. It is not expected to equal
the historical proof bytes. Never replace only half a key set, and never copy
these unapproved development keys or generated verifiers into repository source
or a production deployment. Production artifacts require the documented audit
and multi-party ceremony.

## CI evidence

The **UNAPPROVED development circuits** job runs the one-command build and
retains the regenerated vector. The existing required `circuits` check now
gates that job's successful completion, including failures and skipped runs. The full
Python regression re-derives the recorded statement and tests that changed
public signals and an inconsistent private credential preimage fail before a
vector is published.

That same development job runs `packages/contracts/test/E2E.test.ts` with explicit
fresh legacy artifacts and normal verifier bytecode: prove, submit and record
on a local EVM. A supplied empty or incomplete bundle fails. The ordinary
`hardhat-tests` job omits artifact-dependent tests; it is not the evidence for
the real prove-submit-verify flow. The development CLI demo separately tests a
policy-positive SDK proof.
