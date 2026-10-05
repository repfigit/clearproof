# PACKAGES/PROOF AGENTS.md

**Scope:** TypeScript SDK (`@clearproof/proof`) — the public API for generating and verifying Groth16 compliance proofs.

## OVERVIEW
Thin wrapper around snarkjs that (1) maps camelCase SDK inputs to the snake_case signal names the Circom circuit expects, (2) calls `groth16.fullProve`, and (3) interprets verification results. Also includes a lightweight VASP discovery helper via `.well-known/clearproof.json`.

## STRUCTURE
```
packages/proof/
├── src/
│   ├── index.ts               # Public exports (the only supported entry point; see package.json "exports")
│   │
│   │   # Legacy 16-signal profile (circuits/compliance.circom) — demo/parity path
│   ├── prover.ts              # generateProof + camel→snake mapping + validation
│   ├── verifier.ts            # verifyProof: shape check, pairing, threshold binding, output interpretation
│   ├── thresholds.ts          # Jurisdiction → tier threshold table (mirrors config/jurisdiction_thresholds.json)
│   ├── types.ts               # ComplianceInput, ProofResult, VerifyResult
│   ├── snarkjs.d.ts           # Type declarations for snarkjs
│   │
│   │   # Shared helpers
│   ├── field.ts               # BN254 scalar modulus + canonical decimal field-element validators
│   ├── canonical.ts           # Restricted canonical JSON bytes + domain-separated record digests
│   │
│   │   # Current pilot profile (pilot-transfer-v3) — thin clients of the operator API
│   ├── api-client.ts          # requestReport/reportEndpoint: bounded, authenticated POST to the gateway
│   ├── authorization.ts       # authorizeCurrentProof + receipt validation; pilot signal indices [3]/[5]
│   ├── current-inspection.ts  # inspectCurrentProof (read-only; never consumes an authorization)
│   ├── observation.ts         # createObservation/readObservation + portable-record consistency
│   ├── observation-page.ts    # listObservations (paged retained-record discovery)
│   ├── observation-cohort.ts  # reportObservationCohort (selected-cohort consistency)
│   ├── wallet-ownership.ts    # walletOwnershipSigningMessage (canonical challenge bytes)
│   │
│   │   # VASP discovery (self-declared .well-known metadata)
│   ├── discovery.ts           # discoverVASP, supportsChain, DiscoveryClient, cache
│   ├── discovery-profile.ts   # Target parsing, document schema, HPKE key decoding
│   └── discovery-transport.ts # Node HTTPS transport with EgressPolicy (DNS resolved once, vetted IP)
├── test/                      # Vitest unit tests (100% coverage gate via test:coverage)
└── dist/                      # Compiled output (generated)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add new circuit input field | `types.ts` (ComplianceInput) + `prover.ts` (mapping) | Must match Circom signal name exactly |
| Change validation rules | `prover.ts` (top of generateProof) | Keep in sync with circuit constraints |
| Modify proof interpretation | `verifier.ts` | Legacy profile: publicSignals[0]=is_compliant, [1]=sar_review_flag; reported only when `valid` |
| Validate public signals | `field.ts` | Use `isFieldElementString`/`isFieldElementArray` before any `BigInt()` on caller input |
| Pilot signal indices | `authorization.ts` | `AUTHORIZATION_NULLIFIER_INDEX`/`PROOF_EXPIRES_AT_INDEX`; `test/signal-order.test.ts` checks them against `src/prover/pilot_compliance.py` |
| Add discovery metadata field | `discovery.ts` + types | Update well-known schema docs too |
| Debug input mapping bugs | `prover.ts` lines 37–70 (the big object literal) | This is the only place the SDK knows the circuit ABI |

## PUBLIC API

Everything is exported from the package root (`@clearproof/proof`); there are no supported subpath imports.

**Legacy profile proving/verification (16 signals, demo/parity only):**
```ts
import { generateProof, verifyProof, type ComplianceInput } from '@clearproof/proof';

const result = await generateProof(input, wasmPath, zkeyPath);
// result: { proof, publicSignals: string[], proofTime }

const verified = await verifyProof(proof, publicSignals, vkeyPath, 'US' /* optional */);
// verified: { valid, proofValid, thresholdsBound, jurisdictionMatchesVASP, jurisdiction,
//             rejectionReasons, isCompliant, sarReviewFlag, publicSignals }
// valid = pairing check AND threshold binding. isCompliant is false and sarReviewFlag is null
// unless valid. Wrong-length or non-canonical signals return valid:false with
// 'invalid_signal_count' / 'malformed_public_signals' before snarkjs runs.
```

Threshold helpers: `JURISDICTION_THRESHOLDS`, `DEFAULT_THRESHOLDS`, `getThresholds`, `decodeJurisdiction`, `thresholdsMatchJurisdiction`.
Field helpers: `SCALAR_FIELD_MODULUS`, `isFieldElementString`, `isFieldElementArray`. Constants: `LEGACY_PUBLIC_SIGNAL_COUNT`, `PILOT_PUBLIC_SIGNAL_COUNT`, `AUTHORIZATION_NULLIFIER_INDEX`, `PROOF_EXPIRES_AT_INDEX`.

**Current pilot (pilot-transfer-v3) API clients** — the operator gateway is the trust boundary; these validate response shape and digests only:
```ts
import { authorizeCurrentProof, inspectCurrentProof, createObservation, readObservation,
  listObservations, reportObservationCohort, requestReport, reportEndpoint } from '@clearproof/proof';
```
`authorizeCurrentProof` is the only call that consumes an authorization. Inspection and observation are read-only.

**Canonical encoding / wallet ownership:** `canonicalBytes`, `recordDigest`, `walletOwnershipSigningMessage`.

**VASP discovery (optional convenience):**
```ts
import { discoverVASP, supportsChain, clearDiscoveryCache, DiscoveryClient, DiscoveryError, EgressPolicy } from '@clearproof/proof';

const info = await discoverVASP('exchange.example.com');
// Fetches https://exchange.example.com/.well-known/clearproof.json
```

## INPUT MAPPING (THE CONTRACT)

The SDK converts camelCase → snake_case to match the exact public/private signal names declared in `circuits/compliance.circom`.

**Critical fields (must never drift):**
- `credentialNullifier` → `credential_nullifier` (Poseidon(credential_commitment, transfer_id_hash))
- `proofExpiresAt` → `proof_expires_at` (must be > transferTimestamp — SDK validates this)
- `domainChainId` → `domain_chain_id` (0 triggers a console.warn; proof has no chain binding)
- All Merkle path arrays (`issuerPathElements`, `leftPathElements`, etc.) are passed through as string arrays

**Validation performed in the SDK (before calling snarkjs):**
- `proofExpiresAt > transferTimestamp`
- `credentialNullifier` present and non-zero
- `domainChainId === 0` → warning only (not an error)

**Do not add validation that the circuit already enforces** (e.g., sanctions_clear === 1, threshold ordering). Let the circuit fail — it produces a clearer error and keeps the SDK thin.

## ARTIFACT REQUIREMENTS

The SDK has **no baked-in artifacts**. Callers must supply:
- `wasmPath` — compiled circuit WASM
- `zkeyPath` — proving key
- `vkeyPath` — verification key (for `verifyProof`)

`@clearproof/circuits` publishes Circom sources only. It does not ship WASM, proving keys, or verification keys. In this repository, `scripts/test_development_circuits.py` writes matching development artifacts; `scripts/compile_circuits.sh` still builds the legacy profile on its own. Development artifacts are **not** safe for production. An approved artifact path is still an open decision (ADR 0004).

## CONVENTIONS

- Keep the SDK **dumb** about circuit logic. It only translates names and calls snarkjs.
- Error messages should be actionable for integrators ("proofExpiresAt must be greater than..."), not internal circuit details.
- Discovery is best-effort and self-declared. The README explicitly says: if you need registry-backed assurance, cross-check against on-chain `VASPRegistry`.
- Cache in `discovery.ts` is in-memory only (per-process). Use `clearDiscoveryCache()` in tests.

## ANTI-PATTERNS

- **NEVER** hardcode artifact paths inside this package. Paths are always caller-supplied.
- **NEVER** reorder or rename fields in `ComplianceInput` without a corresponding change in `prover.ts` mapping **and** the circuit.
- **NEVER** treat `domainChainId: 0` as harmless in production code — the warning exists because a zero chain ID means the proof can be replayed across chains.
- **NEVER** add heavy business logic (tier calculation, sanctions tree building, etc.) to this package. It belongs in Python or the contracts.
- **NEVER** assume the well-known discovery response is authoritative without additional verification.

## TESTING

- Run with `npm test` (vitest) inside the package or via turbo from root. `npm run test:coverage` enforces 100% lines/branches/functions/statements.
- Most tests should focus on the mapping layer and validation, not on actual proving (which is slow and requires artifacts).

## COMMANDS (from package root)

```bash
npm run build          # tsc → dist/
npm test               # vitest run
```

## NOTES

- The legacy proving path (`prover.ts`, `verifier.ts`, `thresholds.ts`) stays deliberately thin. The pilot modules are API clients that validate response shape; they make no authorization decision of their own.
- When the circuit public signal order changes, both this package (if it interprets indices) and the Python model must be updated together. `verifier.ts` hardcodes legacy indices 0, 1, 6 and 8-10; `authorization.ts` exports the pilot indices it reads.
- Discovery feature was added later and is deliberately decoupled from the proving path.
