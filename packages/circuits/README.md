# @clearproof/circuits

Legacy Circom circuit sources and artifact paths for controlled evaluation. This package exposes the 16-signal legacy profile, not the separate eight-signal pilot-transfer-v2 authorization workflow.

## Install

```bash
npm install @clearproof/circuits
```

## Artifact availability in the 0.4.0 source package

The source checkout does not include compiled WASM or proving keys. Exported paths
are locations, not a guarantee that files are installed. Check availability first:

```javascript
const { artifactStatus } = require("@clearproof/circuits");
console.log(artifactStatus()); // available, missing filenames, legacy profile
```

Availability checks regular, nonempty files only. It does not validate provenance,
key/circuit compatibility, an audit or a production trusted setup. Published older
versions may have different contents; inspect the exact package being used.

For a local source demo, generate isolated development artifacts using
`scripts/test_development_circuits.py <new-output-directory>` from the monorepo,
then run `clearproof demo --artifacts <new-output-directory>/legacy`. The builder
requires Node, Circom and the installed Python/workspace dependencies. Its keys
are unapproved and must remain separate from production artifacts. See
`docs/internal/PILOT_DEVELOPMENT_ARTIFACTS.md` in the repository for exact commands.

## Use separately prepared artifacts

```javascript
const snarkjs = require("snarkjs");

const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  "/approved/legacy/compliance_js/compliance.wasm",
  "/approved/legacy/compliance_final.zkey"
);
```

## Use circuits in your own Circom project

```circom
include "@clearproof/circuits/src/sanctions_nonmembership.circom";
include "@clearproof/circuits/src/credential_validity.circom";
```

```bash
circom my-circuit.circom \
  -l node_modules/@clearproof/circuits/src \
  -l node_modules/circomlib/circuits \
  --r1cs --wasm
```

## Circuits

| Circuit | Constraints | Purpose |
|---------|------------|---------|
| `compliance.circom` | Build-dependent | Legacy composed circuit |
| `sanctions_nonmembership.circom` | — | Sorted Merkle gap proof |
| `credential_validity.circom` | — | Poseidon commitment + expiry + issuer |
| `amount_tier.circom` | — | Jurisdiction threshold encoding |

## Public Signals (16)

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `is_compliant` | 1 if all checks pass |
| 1 | `sar_review_flag` | 1 if tier >= 3 |
| 2 | `sanctions_tree_root` | Current sanctions Merkle root |
| 3 | `issuer_tree_root` | Trusted issuer Merkle root |
| 4 | `amount_tier` | 1-4 |
| 5 | `transfer_timestamp` | Unix epoch |
| 6 | `jurisdiction_code` | ISO 3166 as uint |
| 7 | `credential_commitment` | Poseidon hash |
| 8-10 | `tier2/3/4_threshold` | Jurisdiction boundaries |
| 11 | `domain_chain_id` | Blockchain chain ID |
| 12 | `domain_contract_hash` | Verifier contract hash |
| 13 | `transfer_id_hash` | Transfer binding |
| 14 | `credential_nullifier` | One-time use |
| 15 | `proof_expires_at` | Proof TTL enforced on-chain |

## License

Apache-2.0
