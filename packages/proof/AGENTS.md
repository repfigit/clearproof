# PACKAGES/PROOF AGENTS.md

**Scope:** TypeScript SDK (`@clearproof/proof`) — the public API for generating and verifying Groth16 compliance proofs.

## OVERVIEW
Thin wrapper around snarkjs that (1) maps camelCase SDK inputs to the snake_case signal names the Circom circuit expects, (2) calls `groth16.fullProve`, and (3) interprets verification results. Also includes a lightweight VASP discovery helper via `.well-known/clearproof.json`.

## STRUCTURE
```
packages/proof/
├── src/
│   ├── index.ts          # Public exports
│   ├── prover.ts         # generateProof + camel→snake mapping + validation
│   ├── verifier.ts       # verifyProof + result interpretation
│   ├── types.ts          # ComplianceInput, ProofResult, VerifyResult
│   ├── discovery.ts      # discoverVASP + well-known client
│   └── snarkjs.d.ts      # Type declarations for snarkjs
├── test/                 # Vitest unit tests
└── dist/                 # Compiled output (generated)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add new circuit input field | `types.ts` (ComplianceInput) + `prover.ts` (mapping) | Must match Circom signal name exactly |
| Change validation rules | `prover.ts` (top of generateProof) | Keep in sync with circuit constraints |
| Modify proof interpretation | `verifier.ts` | Currently assumes publicSignals[0]=is_compliant, [1]=sar_review_flag |
| Add discovery metadata field | `discovery.ts` + types | Update well-known schema docs too |
| Debug input mapping bugs | `prover.ts` lines 37–70 (the big object literal) | This is the only place the SDK knows the circuit ABI |

## PUBLIC API

**Core proving/verification:**
```ts
import { generateProof, verifyProof, type ComplianceInput } from '@clearproof/proof';

const result = await generateProof(input, wasmPath, zkeyPath);
// result: { proof, publicSignals: string[], proofTime }

const verified = await verifyProof(proof, publicSignals, vkeyPath);
// verified: { valid, isCompliant, sarReviewFlag, publicSignals }
```

**VASP discovery (optional convenience):**
```ts
import { discoverVASP, supportsChain, clearDiscoveryCache } from '@clearproof/proof';

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

**Recommended source:** `@clearproof/circuits` package (when it ships pre-built audited artifacts).

**Current reality (documented in root README):** artifacts are generated locally via `scripts/compile_circuits.sh`. Dev artifacts are **not** safe for production.

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

- Run with `npm test` (vitest) inside the package or via turbo from root.
- Most tests should focus on the mapping layer and validation, not on actual proving (which is slow and requires artifacts).

## COMMANDS (from package root)

```bash
npm run build          # tsc → dist/
npm test               # vitest run
```

## NOTES

- The package is intentionally small (~6 source files) so that the only thing that can go wrong is the name mapping or a missing validation that the circuit already performs.
- When the circuit public signal order changes, both this package (if it interprets indices) and the Python model must be updated together. Currently `verifier.ts` hardcodes indices 0 and 1.
- Discovery feature was added later and is deliberately decoupled from the proving path.
