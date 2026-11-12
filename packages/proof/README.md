# @clearproof/proof

TypeScript SDK for Clearproof. Nothing in it is audited, and no production proving or verification keys exist. It has three separate parts:

| Part | Functions | What they do |
| --- | --- | --- |
| Current pilot profile (`pilot-transfer-v3`, 8 public signals) | `inspectCurrentProof`, `authorizeCurrentProof`, `createObservation`, `readObservation`, `listObservations`, `reportObservationCohort`, `requestReport`, `reportEndpoint` | HTTP clients for a Clearproof API that an operator runs. They do not generate or verify a proof locally. They check the response schema, profile and digests; the selected API is the trust boundary. |
| Legacy demo profile (16 public signals) | `generateProof`, `verifyProof` | Local Groth16 proving and verification with snarkjs, using artifacts the caller supplies. Not the current profile. |
| Helpers | `DiscoveryClient`, `discoverVASP`, `canonicalBytes`, `recordDigest`, `walletOwnershipSigningMessage`, `siweWalletOwnershipMessage`, field and threshold helpers | Counterparty discovery, canonical encoding and wallet-ownership message text. |

This package has no local prover or verifier for `pilot-transfer-v3`. Pilot proofs are generated and checked by the Python gateway in the source repository.

Everything is exported from the package root. The `exports` map does not allow subpath imports.

## Current pilot API clients

`inspectCurrentProof(origin, token, requestBytes)` is a read-only `pilot-transfer-v3`
inspection through an operator-selected authenticated Clearproof API. It validates
the scoped response and preserves development assurance; it does not authorize a
transfer, consume an authorization or independently verify API claims.
`authorizeCurrentProof` is the only function here that asks the API to consume an
authorization; PostgreSQL behind that API decides. See
[`PILOT_CURRENT_INSPECTION_API.md`](https://github.com/repfigit/clearproof/blob/main/docs/internal/PILOT_CURRENT_INSPECTION_API.md)
for server setup, request format, CLI usage and real-proof integration validation.
Available from npm 0.5.0 and later.

## Wallet-ownership signing text

`walletOwnershipSigningMessage(challenge, expected)` validates a challenge against
context you retained independently and returns the exact text to sign: the
EIP-4361 (SIWE) message for `clearproof-wallet-challenge-v2` challenges, or the
canonical v1 text. `siweWalletOwnershipMessage(challenge)` renders the v2 message
without validating context or time, for example to reproduce the signed text of
a retained, expired challenge; do not use it to decide what to sign. The types
`WalletOwnershipChallenge`, `WalletOwnershipChallengeV2` and
`AnyWalletOwnershipChallenge` are exported. The v2 (SIWE) profile,
`siweWalletOwnershipMessage` and the two v2 types are in the source checkout and
are not in npm 0.7.2. See
[`WALLET_OWNERSHIP.md`](https://github.com/repfigit/clearproof/blob/main/docs/internal/WALLET_OWNERSHIP.md).

## Install

```bash
npm install @clearproof/proof
```

## Legacy demo usage

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

`generateProof` and `verifyProof` are the legacy 16-signal demo. Callers supply the WASM, proving key and verification key. `@clearproof/circuits` publishes the Circom sources and does not ship those files. In this repository, `scripts/test_development_circuits.py` writes matching development artifacts under `<output>/legacy`; those keys are unapproved. The current pilot profile uses the API clients above, not this demo.

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

Each client keeps a bounded cache (five-minute default). Call `clearCache()` after a known rotation. Browser integrations need a controlled server transport. See the [discovery profile](https://github.com/repfigit/clearproof/blob/main/specs/well-known-clearproof.md) for migration, enterprise CA configuration and limits of trust. This profile is what the published SDK implements from 0.5.0 on. It is not a description of the historical npm 0.3.0 package, and profile `0.4.0` is not the package version.

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
