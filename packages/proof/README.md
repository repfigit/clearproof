# @clearproof/proof

TypeScript SDK for generating and verifying ZK compliance proofs using Groth16/snarkjs.

## Current pilot inspection

The source SDK also exports `inspectCurrentProof(origin, token, requestBytes)` for
read-only pilot-transfer-v3 inspection through an operator-selected authenticated
Clearproof API. It validates the scoped response and preserves development
assurance; it does not authorize a transfer or independently verify API claims.
This is separate from the legacy 16-signal `verifyProof` function below. See
`docs/internal/PILOT_CURRENT_INSPECTION_API.md` in the monorepo for server setup,
request format, CLI usage and real-proof integration validation. Available from
npm 0.5.0 and later.

## Install

```bash
npm install @clearproof/proof
```

## Usage

```typescript
import { generateProof, verifyProof } from "@clearproof/proof";

// Legacy 16-signal demo. Paths are caller-supplied.
// @clearproof/circuits publishes Circom sources only: no WASM, zkey, or verification key.
const wasmPath = "/absolute/development-artifacts/legacy/compliance_js/compliance.wasm";
const zkeyPath = "/absolute/development-artifacts/legacy/compliance_final.zkey";
const vkeyPath = "/absolute/development-artifacts/legacy/verification_key.json";

const { proof, publicSignals } = await generateProof(
  {
    // ... legacy circuit inputs (sanctions path, credential, amount, etc.)
  },
  wasmPath,
  zkeyPath,
);

const result = await verifyProof(proof, publicSignals, vkeyPath);

console.log("Proof valid:", result.valid);
```

## Requirements

`generateProof` and `verifyProof` are the legacy 16-signal demo. Callers supply the WASM, proving key and verification key. `@clearproof/circuits` publishes the Circom sources and does not ship those files. In this repository, `scripts/test_development_circuits.py` writes matching development artifacts under `<output>/legacy`; those keys are unapproved. Current pilot authorization is the separate `inspectCurrentProof` path above, not this demo.

## Discovery (profile 0.4.0)

Use `DiscoveryClient` in Node.js to fetch a counterparty's domain-declared HPKE metadata:

```typescript
import { DiscoveryClient, DiscoveryError } from '@clearproof/proof';

const discovery = new DiscoveryClient();
try {
  const info = await discovery.discover('did:web:beneficiary.example');
  // Apply your recipient-authorization policy before trusting this key.
  console.log(info.clearproof.hpkeKeyId);
} catch (error) {
  if (error instanceof DiscoveryError) console.error(error.code);
  throw error; // A lookup failure must not weaken encryption.
}
```

The 0.4.0 profile requires exact identity, key purpose, key fingerprint and suite/version checks. It blocks private destinations unless an operator supplies an exact authority-to-CIDR exception, pins the connected IP, verifies TLS and forbids redirects. Errors distinguish `unsupported`, `unavailable` and `invalid`; older profiles are unsupported. The `publicKey` legacy field is never used for HPKE.

Each client keeps a bounded cache (five-minute default). Call `clearCache()` after a known rotation. Browser integrations need a controlled server transport. See the [discovery profile](../../specs/well-known-clearproof.md) for migration, enterprise CA configuration and limits of trust. This profile is what the published SDK implements from 0.5.0 on. It is not a description of the historical npm 0.3.0 package, and profile `0.4.0` is not the package version.

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
