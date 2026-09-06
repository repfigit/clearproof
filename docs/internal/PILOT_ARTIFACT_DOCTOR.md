# Pilot artifact inspection

The composed proof profile has a separate, read-only Python diagnostic:

```bash
.venv/bin/python -m src.prover.pilot_artifacts /path/to/pilot-artifacts \
  --trusted-manifest-digest APPROVED_LOCAL_DEVELOPMENT_MANIFEST_DIGEST
```

Supply the digest from independently reviewed operator configuration. Copying a
bundle's own claimed digest into the trust configuration establishes no trust.
The command performs no download, proof generation, transaction or file write.
Exit zero means the pinned **development** files match the declared profile;
JSON reports `development_unapproved` and `production_eligible: false`.
`--mode production` rejects every currently supported manifest. There is no
supported production approval label, and relabeling a manifest cannot enable it.
Exit one emits a stable rejection code without paths, contents or key material.

Place `manifest.json` and four distinct regular artifact files in the directory.
Manifest schema: `src.prover.pilot_artifacts.PilotArtifactManifest`. It binds:

- `pilot-transfer-v1`, Groth16/BN128, transfer/context schema versions and the
  exact ordered eight public signal names;
- the declared policy schema, reviewed source bundle and compiler SHA-256
  digests;
- each WASM, R1CS, proving-key and verification-key basename, byte length and
  SHA-256 digest.

The manifest digest is the canonical restricted record digest under
`clearproof/artifact-manifest/v1`, with model defaults included. Generate it
using `PilotArtifactManifest.model_validate_json(raw).digest`, review the source
and artifact provenance, then pin it outside the bundle. Duplicate JSON keys,
unknown fields, path traversal, repeated filenames and unsupported layouts are
rejected. Files are opened without following symlinks, must be regular, and are
streamed with size limits. FIFOs are opened nonblocking and rejected. The
verification key must declare Groth16/BN128, eight public signals and nine IC
entries. This structural check is not a pairing or subgroup check.

The Python return value captures verified key bytes; consumers must use that
snapshot, not reopen a path that could have changed. Other files are inspected
but not retained. A future prover must snapshot or revalidate its files before
use. `check_artifact_context` additionally rejects a context selecting another
manifest or proof profile; it does not check current roots, policy or transfer
eligibility.

Limitations: source and compiler digests are pinned provenance declarations,
not a reproducible-build attestation. The loader does not establish that the
proving and verification keys came from the declared R1CS; review and the real
proof reproduction in ADR 0006 are separate evidence. Runtime binary/dependency
pins, authenticated policy schema loading, CLI package integration and enforced
use at API/SDK/contract acceptance boundaries remain required before CP-009 is
complete. This development profile is not an audit, production ceremony or
regulatory certification.

Local validation on September 5, 2026 inspected the actual composed WASM,
R1CS, development zkey and exported verification key from ADR 0006. The local
manifest used an all-zero synthetic policy-schema marker, so it cannot serve as
an approved policy binding. No generated artifacts or manifest were committed.

## Read-only pairing inspection

`src.prover.pilot_verifier.PilotPairingVerifier.load()` accepts the inspected
artifacts, an absolute operator-owned Node executable, and the independently
pinned SHA-256 of the self-contained `snarkjs/build/snarkjs.min.js` IIFE bundle.
The bundle is opened without following symlinks, bounded to 2 MiB and copied into
an immutable byte snapshot. No npx or package resolution runs during verification.
The Node binary and operating-system libraries remain trusted host components;
they are not covered by the artifact manifest or JS bundle pin.

`inspect(proof_bytes, signals, expected_signals=...)` requires the exact eight
canonical scalar strings. The expected vector must come from the trusted caller;
copying the submitted vector into it is not context authentication. Proof JSON
is bounded to 8 KiB, rejects duplicate/unknown keys, uses the exact Groth16/BN128
shape and finite affine encodings, and rejects coordinate aliases modulo the
BN254 base field. Pairing verification still checks whether points are valid.

Only the snapshotted public verification key, signals and proof are sent through
stdin. No customer input is written into the temporary runtime directory. The
child receives a minimal environment without NODE_OPTIONS or inherited secrets,
a bounded Node heap and a 1–60 second caller-selected timeout. Timeout and task
cancellation kill and reap the owned process group. Runtime failures raise stable
codes distinct from a failed pairing. A successful return exposes
`cryptographic_valid`, the manifest digest and profile, never a compliance or
authorization result. Trusted current roots, enrollment, quote/policy authority,
revocation and atomic consumption still belong to the authorization layer.

Run the opt-in real integration after the local proof and development manifest
have been created (the manifest pin file is a synthetic test convention only):

```bash
CLEARPROOF_PILOT_TEST_ARTIFACTS=/path/to/local-development-artifacts \
  .venv/bin/python -m pytest tests/integration/test_pilot_pairing.py -q
```

The integration reads `proof.json`, `public.json`, `expected-public.json`,
`manifest.json` and `development-manifest-pin.txt` from that directory. It checks
the real pairing, rejects an altered proof coordinate, rejects a context mismatch
before the pairing, and rejects altered public signals even when a test caller
intentionally supplies the same incorrect expected vector. This opt-in fixture
reads its own development pin and bundle hash for reproducibility; that is not
an independent production trust bootstrap.

## CI development setup

`scripts/test_development_circuits.py OUTPUT_DIRECTORY` creates a new local
2^16 Powers of Tau transcript (enough for both unchanged circuits), adds a development contribution, prepares phase
two, and compiles both the legacy and composed circuits into separate output
subdirectories. Each gets a fresh Groth16 setup, development contribution,
verification key and generated Solidity verifier. Generated circuit files stay
in the supplied new directory; tracked contracts and committed vectors are not
replaced. The required Node, Circom and repository dependencies must already be
installed. The script builds the TypeScript workspaces needed for the CLI smoke
test, which writes their normal ignored `dist` files.

CI uses this explicitly local development setup instead of downloading the
unavailable Hermez URL. It preserves the legacy CLI proof smoke test and adds
the composed proof round trip, artifact inspection and adversarial pairing test.
It does not downgrade a production setup: there is no production approval path
in this job. Setup entropy, fresh proving keys and verification keys can differ
between runs; reproducibility here means repeating the tested workflow, not
byte-identical keys. A locally generated Powers of Tau transcript is not a
multi-party ceremony, independent audit, or production provenance evidence.

For local debugging only, `--prepared-ptau PATH` copies an explicitly selected
prepared development input into the isolated output directory. The input's
SHA-256 and a circuit/source-dependency hash inventory are recorded. No download
fallback is used and no file-existence check is treated as production approval.
The output marker and CI upload name both say `UNAPPROVED`. The CI upload excludes
the large phase-one transcript; it retains the per-profile development artifacts
for seven days. The production ceremony remains a separate follow-on gate.

The hosted circuit run 34009491967 timed out during phase-two preparation at
1,800 seconds. Preparation now has a bounded 5,400-second allowance and verbose
snarkjs progress; other commands retain their 1,800-second limits. The CI job
has a 150-minute total ceiling. Every command reports elapsed time, and the
runner kills and reaps its owned process group on timeout or interruption.
These changes do not establish CI success: a completed remote proof run is
still required. Real subprocess tests cover success, nonzero exit and timeout
termination of a spawned worker.
