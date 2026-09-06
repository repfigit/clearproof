# @clearproof/proof

TypeScript SDK for generating and verifying ZK compliance proofs using Groth16/snarkjs.

## Install

```bash
npm install @clearproof/proof
```

## Usage

```typescript
import { generateProof, verifyProof } from "@clearproof/proof";
import { artifacts } from "@clearproof/circuits";

// Generate a proof
const { proof, publicSignals } = await generateProof(
  {
    // ... circuit inputs (sanctions path, credential, amount, etc.)
  },
  artifacts.wasmPath,
  artifacts.zkeyPath,
);

// Verify a proof
const result = await verifyProof(
  proof,
  publicSignals,
  artifacts.vkeyPath,
);

console.log("Proof valid:", result.valid);
```

## Requirements

Circuit artifacts (WASM, zkey, verification key) must be compiled locally or obtained from the `@clearproof/circuits` package.

## Discovery (development 0.4.0 profile)

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

Each client keeps a bounded cache (five-minute default). Call `clearCache()` after a known rotation. Browser integrations need a controlled server transport. See the [discovery profile](../../specs/well-known-clearproof.md) for migration, enterprise CA configuration and limits of trust. This development behavior is not a description of the public npm 0.3.0 release.

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
