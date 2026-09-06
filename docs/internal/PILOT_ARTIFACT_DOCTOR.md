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
