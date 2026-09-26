# @clearproof/circuits

Circom source for the clearproof proof profiles, published so anyone can inspect and compile the exact circuits:

- **`pilot-transfer-v3`** (current): `pilot_compliance.circom`, `PilotCompliance(32, 20, 20)`, with 8 public signals. See [`specs/pilot-transfer-v3.md`](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md).
- **Legacy demo** (`compliance.circom`, 16 public signals). It is never valid as current pilot authorization.

**Source only.** There is no compiled WASM, proving key or verification key. All current keys are development-only, and the production setup path is an open decision. Versions up to 0.3.0 shipped legacy development artifacts; this package no longer does.

## Install and compile

```bash
npm install @clearproof/circuits circomlib
circom node_modules/@clearproof/circuits/circuits/pilot_compliance.circom -l node_modules --r1cs --wasm
```

Includes of `circomlib` use `circomlib/...` paths, so pass `-l node_modules`. `circomlib` is a peer dependency licensed **GPL-3.0**; this package is Apache-2.0 and does not bundle it. The pilot circuit has 95,408 constraints and needs `2^17` powers-of-tau parameters for a Groth16 setup.

## What's inside

The sources are copied from the repository's [`circuits/`](https://github.com/repfigit/clearproof/tree/main/circuits) directory at publish time. The only change is that includes of the repo-root `../node_modules/circomlib/...` are rewritten to `circomlib/...`. `circuits/MANIFEST.json` lists the SHA-256 of each original repository file and each packaged file, so you can check the package against a tagged commit. Releases are published from GitHub Actions with signed npm provenance.

```javascript
const circuits = require("@clearproof/circuits");
circuits.pilot.main;          // path to pilot_compliance.circom
circuits.pilot.publicSignals; // the 8 public signals, in order
circuits.pilot.treeDepths;    // { issuance: 32, authorizedIssuers: 20, sanctions: 20 }
circuits.legacy.main;         // path to compliance.circom
```

These are unaudited development components. See the [security page](https://docs.clearproof.world/docs/security).
