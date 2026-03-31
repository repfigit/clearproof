# @clearproof/circuits

Circom circuits for ZK compliance proofs. Prove sanctions clearance, credential validity, and jurisdiction-correct tier encoding — without revealing private data.

## Install

```bash
npm install @clearproof/circuits
```

## Use pre-compiled artifacts

```javascript
const { artifacts } = require("@clearproof/circuits");
const snarkjs = require("snarkjs");

const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  artifacts.wasmPath,
  artifacts.zkeyPath
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
| `compliance.circom` | 15,754 | Main composed circuit |
| `sanctions_nonmembership.circom` | — | Sorted Merkle gap proof |
| `credential_validity.circom` | — | Poseidon commitment + expiry + issuer |
| `amount_tier.circom` | — | Jurisdiction threshold encoding |

## Public Signals (15)

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

## License

Apache-2.0
