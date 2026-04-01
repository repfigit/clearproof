# @clearproof/proof

TypeScript SDK for generating and verifying ZK compliance proofs using Groth16/snarkjs.

## Install

```bash
npm install @clearproof/proof
```

## Usage

```typescript
import { generateComplianceProof, verifyComplianceProof } from "@clearproof/proof";

// Generate a proof
const { proof, publicSignals } = await generateComplianceProof({
  wasmPath: "./artifacts/compliance.wasm",
  zkeyPath: "./artifacts/compliance_final.zkey",
  input: {
    // ... circuit inputs (sanctions path, credential, amount, etc.)
  },
});

// Verify a proof
const valid = await verifyComplianceProof({
  vkeyPath: "./artifacts/verification_key.json",
  proof,
  publicSignals,
});

console.log("Proof valid:", valid);
```

## Requirements

Circuit artifacts (WASM, zkey, verification key) must be compiled locally or obtained from the `@clearproof/circuits` package.

## Links

- [Main repository](https://github.com/clearproof/clearproof)
- [Circuit documentation](https://github.com/clearproof/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
