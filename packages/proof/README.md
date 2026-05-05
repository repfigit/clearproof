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

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
