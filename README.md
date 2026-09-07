# clearproof

Privacy-focused evidence for crypto transfers. Clearproof combines scoped
zero-knowledge statements, encrypted transfer information, policy decisions and
retained evidence for controlled evaluation by stablecoin processors and custodians.
A valid proof establishes its encoded statement; it does not establish legal
compliance, source truth, counterparty acceptance or settlement by itself.

**Status checked September 7, 2026:** the main GitHub repository is **private**.
Public npm packages remain **0.3.0**; this unreleased development checkout is
**0.4.0**. Source access is required for the local pilot. Current circuits and
contracts have not completed independent audits, and generated proving keys are
explicitly unapproved development artifacts.

## Local adoption pilot

The development branch implements:

- Authenticated credential enrollment, holder-bound issuance membership and a
  canonical transfer/context projection with exact asset and valuation arithmetic.
- Encrypted tenant-scoped storage, retained policy/root/revocation history,
  actor-bound retries and atomic authorization consumption.
- Explained policy evaluation, comparison, review and activation history.
- Signed synthetic custody-event ingestion, simulated bilateral outcomes and
  read-only transfer investigations with independent lifecycle states.
- Non-authorizing observation reports with scoped coverage, disagreement and timing.
- Recipient-encrypted historical exports and offline review under independently
  configured proof, policy, source, decision, status and timing authorities.

The [acceptance audit](docs/plans/adoption-pilot-acceptance-audit.md) maps each
requirement to source and tests. The [implementation plan](docs/plans/2026-09-05-adoption-pilot-implementation.md)
tracks M0–M5 and the separate customer, integration, distribution and production
gates. Local simulation is not evidence of customer adoption or live interoperability.

## Start from an authorized checkout

Install the host prerequisites documented in the
[local acceptance guide](docs/operations/local-pilot-acceptance.md), then:

```bash
npm exec --yes --package=npm@11.9.0 -- npm ci
uv sync --frozen --extra dev --python 3.12
npm run build

# Both output directories must be new. These keys are development-only.
.venv/bin/python scripts/test_development_circuits.py /absolute/new-development-artifacts
.venv/bin/python scripts/test_pilot_local.py \
  /absolute/new-development-artifacts/pilot \
  /absolute/new-pilot-run \
  --postgres-bin /usr/lib/postgresql/18/bin
```

The runner owns a disposable PostgreSQL cluster and loopback EVM, exercises real
proofs and retains synthetic reports plus an encrypted historical export. The
same guide provides exact offline-reproduction commands and private-output rules.
The [compatibility matrix](docs/operations/pilot-compatibility.md) and
[operator runbook](docs/operations/pilot-observability.md) describe version,
migration, recovery and observability limits.

The API requires valid independently configured storage keys and tenant/trust
configuration. Start with [.env.example](.env.example) and the
[tenant storage guide](docs/operations/pilot-tenant-storage.md). A successful
`/health` response is process liveness, not pilot readiness. Do not put keys,
customer information or decrypted envelopes in logs or source control.

## Proof and authorization boundaries

The current `pilot-transfer-v2` profile has **eight public signals**, with no
public amount tier or SAR advisory flag. The credential-bound projection and
approved roots are reconstructed from trusted inputs. See the
[v2 statement](specs/pilot-transfer-v2.md) and
[signal reference](docs/internal/CIRCUIT_SIGNALS.md).

Python and Solidity check matching real proof statements. API/SDK clients use
server-selected trust, PostgreSQL owns authorization consumption, and contracts
mirror already-consumed receipts under source-validated publisher checkpoints.
Read-only inspection and observation cannot consume an authorization. See the
[current registry boundary](docs/internal/PILOT_CURRENT_REGISTRY.md).

The older `compliance.circom` **16-signal** profile remains a separate legacy demo
and parity path. Its public outputs include amount-tier/SAR metadata. Never select
artifacts by signal count alone or reinterpret legacy proofs as current pilot
authorization. All current artifact manifests retain development assurance;
production configuration rejects unapproved keys.

## Packages and deployments

| Public npm package | Checked version | Availability |
| --- | --- | --- |
| [@clearproof/proof](https://www.npmjs.com/package/@clearproof/proof) | 0.3.0 | SDK installation verified; proving still requires matching artifacts |
| [@clearproof/circuits](https://www.npmjs.com/package/@clearproof/circuits) | 0.3.0 | Inspect package contents; installation alone is not a proving setup |
| [@clearproof/cli](https://www.npmjs.com/package/@clearproof/cli) | 0.3.0 | Public install is blocked by unavailable `@clearproof/content`; build from an authorized checkout |
| [@clearproof/contracts](https://www.npmjs.com/package/@clearproof/contracts) | 0.3.0 | Solidity package; not a current pilot deployment |

Recorded Sepolia addresses are in the [deployment manifest](packages/contracts/deployments/sepolia.json)
and [public contract documentation](apps/docs/app/docs/contracts/page.mdx).
They are historical test deployments, not evidence that the current profile is
deployed or independently reviewed. Local acceptance makes no shared-network
transaction or production fund movement.

## Development and next steps

`make test` runs Python tests. `npm run test:ts` runs uncached workspace tests;
provide both development artifact directories and the selected Python executable
as documented to include all contract cases. `npm run build` builds the workspaces.
CI commands are maintained in [.github/workflows/ci.yml](.github/workflows/ci.yml);
local results do not assert remote CI success.

Source lives in `src/` and uses `src.*` imports despite the Python distribution
name `clearproof`. Circom sources are in `circuits/`; TypeScript SDK, CLI,
contracts and shared content are under `packages/`; the documentation app is
`apps/docs/`. The [proof-system decision](docs/adr/0003-proof-system.md) records
the implemented Groth16 choice and its assurance limits.

The [paid-pilot preparation packet](docs/commercial/README.md) contains a buyer
brief, interview script, measurement worksheet, hypothetical pricing and usage
counter semantics. Live customer/provider access, broader issuer/wallet support,
ongoing re-screening, managed distribution and independently reviewed production
operations remain follow-on gates. See [SECURITY.md](SECURITY.md) for reporting.

## License

[Apache-2.0](LICENSE) for all clearproof code, per [REUSE.toml](REUSE.toml) (SPDX metadata, verified in CI).

One third-party component: [`packages/contracts/contracts/Pairing.sol`](packages/contracts/contracts/Pairing.sol) is the MIT-licensed alt_bn128 pairing library (Copyright 2017 Christian Reitwiessner), ported to Solidity 0.8 — attribution in [NOTICE](NOTICE). The on-chain Groth16 verifier is clearproof's own Apache-2.0 implementation generated by `scripts/generate_verifier.mjs` — it does **not** use the GPL-3.0 snarkjs template (see [ADR 0001](docs/adr/0001-groth16-verifier-licensing.md)). License texts live in [`LICENSES/`](LICENSES/).
