---
title: TypeScript SDK
category: reference
order: 6
cli-topic: sdk
---

# TypeScript SDK

`@clearproof/proof` provides proof generation, cryptographic verification and counterparty discovery. Published version: **0.7.1**, checked October 7, 2026. It includes the pilot functions and the legacy 16-signal functions described below. Confirm the installed version before using its types.

## Installation

```bash
npm install @clearproof/proof@0.7.1
```

## Current pilot: read-only inspection

```typescript
import { inspectCurrentProof } from '@clearproof/proof';

// Exact JSON bytes from a protected input file: target_id, credential_id,
// proof_json and the eight public_signals of pilot-transfer-v3.
async function inspect(origin: string, token: string, input: Uint8Array) {
  const report = await inspectCurrentProof(origin, token, input);
  return {
    paired: report.cryptographic_valid,
    artifactManifest: report.manifest_digest,
    consumed: report.authorization_consumed, // always false on this path
  };
}
```

The operator configures the API target, current roots, policy, artifacts and tenant. The bearer principal needs `proof:inspect` and `evidence:decrypt`; input cannot select another tenant or replace trust. The client checks the returned schema and profile. Pairing and current-state checks happen on the selected server; this client is not an independent local verifier. A successful inspection does not consume authorization or establish counterparty acceptance.

Use the [complete local pilot](/docs/quickstart#complete-local-pilot) to exercise generation, encrypted storage, observation and historical review with synthetic data. The [quick verification example](/docs/quickstart#quick-verification-example) requires only Node and uses an explicitly historical legacy fixture.

## Pilot functions

| Function | Purpose |
| --- | --- |
| `inspectCurrentProof` | Read-only inspection of a `pilot-transfer-v3` proof through the authenticated API |
| `authorizeCurrentProof` | Request consumption of one authorization; returns the receipt |
| `createObservation`, `readObservation`, `listObservations`, `reportObservationCohort` | Non-authorizing observations and cohort reports |
| `requestReport`, `reportEndpoint` | Authenticated report requests |
| `canonicalBytes`, `recordDigest` | Canonical encoding and domain-separated digests, matching the Python implementation |
| `walletOwnershipSigningMessage` | Build the exact EIP-191 message for the wallet ownership challenge |

These use server-selected trust: the API owns current roots, policy and consumption. The client validates response shape and profile (`pilot-transfer-v3`) but does not independently establish current state.

## Legacy proof API

```typescript
import { generateProof, verifyProof, type ComplianceInput } from '@clearproof/proof';

// Supply a complete, authenticated input with witnesses matching your circuit.
async function evaluate(input: ComplianceInput, wasm: string, zkey: string, vkey: string) {
  const generated = await generateProof(input, wasm, zkey);
  const verified = await verifyProof(generated.proof, generated.publicSignals, vkey);
  return { generated, verified };
}
```

The caller supplies compatible artifacts. The SDK maps camelCase fields to Circom signal names; it does not create issuer or sanctions witnesses for you. Field encodings, amount units and public-signal ordering must match the exact proof version.

`verified.proofValid` is the Groth16 pairing result. `verified.valid` additionally requires the public thresholds to match the verifier's jurisdiction table. `isCompliant` and `sarReviewFlag` interpret circuit outputs only when `valid` is true (`isCompliant` is `false` and `sarReviewFlag` is `null` otherwise; `rejectionReasons` explains why). Expected jurisdiction, current registry acceptance, policy authorization, freshness, revocation, domain and replay checks remain separate. None establishes legal compliance.

## Discovery

`discoverVASP(domain)` and `supportsChain(domain, chainId)` read self-declared well-known metadata. A domain response is not independent issuer/VASP authorization. Python and TypeScript discovery compatibility and destination/key validation are active hardening work.

## Input and privacy limitations

The current SDK validates selected fields, including proof expiry relative to the transfer timestamp and a nonzero credential nullifier. A zero domain chain ID currently emits a warning; it is not a safe production configuration.

Do not log complete witnesses or sensitive proof metadata. Use the installed package's declarations for exact types and dependencies, and review [status](/docs/status) before integration.
