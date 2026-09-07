# Verifier Predicate Specification

This document defines the shared predicate that all implementations (Python, TypeScript, Hardhat) must satisfy.

## Security Properties Checklist

| Check | Description | Implemented |
|-------|-------------|-------------|
| Groth16 validity | Proof cryptographically valid | ✅ |
| Sanctions root freshness | Root not stale (isStale()) | ❌ → ✅ |
| Sanctions root matches current | Root matches current registry | ❌ → ✅ |
| Issuer root matches current | Issuer using current root | ❌ → ✅ |
| Proof expiry vs now | Proof not expired | ❌ → ✅ |
| Timestamp not in future | Proof timestamp reasonable | ❌ → ✅ |
| Domain chain ID | Correct blockchain network | ❌ → ✅ |
| Domain contract hash | Correct contract version | ❌ → ✅ |
| Transfer binding | Proof bound to specific transfer | ❌ → ✅ |
| VASP active / not paused | Issuer VASP is active | ❌ → ✅ |
| Sender is registered wallet | Sender is registered | ❌ → ✅ |
| Credential revocation | Credential not revoked | ❌ → ✅ |
| Nullifier not spent | Proof not already used | ❌ → ✅ |
| Transfer not already recorded | Transfer not duplicated | ❌ → ✅ |

## Implementation Requirements

1. All three implementations (Python, TypeScript, Hardhat) must agree on every fixture
2. Fail closed on stale roots with explicit failure reason
3. Add transfer_id to ProofVerifyRequest and enforce binding
4. Return detailed error messages for failed checks