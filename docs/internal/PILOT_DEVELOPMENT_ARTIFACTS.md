# Development artifacts and legacy CLI availability

The 0.4.0 source checkout does not bundle compiled circuit WASM or proving keys.
`@clearproof/circuits` exports legacy artifact locations plus `artifactStatus()`
to report missing files. Its 16-signal metadata is separate from the current
pilot-transfer-v2 profile. File presence is not artifact approval or compatibility.

Generate both profiles in a new isolated directory:

```bash
npm install
uv sync --extra dev
# Install the pinned Circom compiler documented in the repository CI setup.
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-output
```

The script compiles legacy and pilot circuits, creates explicitly unapproved
local development keys, exports verification keys, builds the CLI and performs
real proof round trips. It refuses to overwrite an existing output directory.
The initial setup can take many minutes. `--prepared-ptau /local/development.ptau`
reuses an explicitly selected local development setup; that is not ceremony or
production approval. Generated keys stay outside the source package/checkout.

The legacy demo then runs with an explicit directory:

```bash
node packages/cli/dist/index.js demo \
  --artifacts /absolute/new-development-output/legacy
```

`demo` and `prove` accept either a flat `compliance.wasm` layout or the compiler's
`compliance_js/compliance.wasm` layout, alongside `compliance_final.zkey` and
`verification_key.json`. A complete installed package set is preferred by default;
otherwise the CLI selects the monorepo artifact directory. Missing, partial,
empty or symlinked files cause a setup diagnostic before proving and exit code 2.
The CLI never downloads or generates keys implicitly.

This preflight checks availability only. It does not authenticate a legacy key,
WASM source or verification key, and it is not the v2 manifest validation path.
The legacy demo uses public synthetic data and cannot authorize a transfer or
establish production compliance. The pilot workflow uses independently pinned
manifests and its separate services; historical review is documented in
[PILOT_VERIFY_HISTORY_CLI.md](PILOT_VERIFY_HISTORY_CLI.md).

Validation for this change used an existing isolated development legacy bundle
to generate and verify a real demo proof. It did not repeat a fresh setup or turn
those keys into approved package artifacts. Complete clean-environment onboarding,
release artifact provenance and package distribution remain CP-017 work.
