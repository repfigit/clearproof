# PR #11 resolution: versioned wallet ownership extension

Implementation and local verification reference. Consult the replacement PR for current CI, merge and supersession status.

PR #11 / AIF-67 requires five-minute EIP-191 challenges, 24-hour attestations,
revocation, APIs, a committed verification flag at index 5 and a circuit constraint.
It also explicitly preserves existing credential issuance, on-chain verifiers and
trusted setup. Changing the existing Poseidon(5) commitment cannot satisfy that
compatibility requirement. The replacement therefore introduces a versioned
six-field **extension commitment**, bound to an existing pilot credential and
retained attestation, rather than rewriting that credential.

| Requirement | Implementation | Verification coverage |
|---|---|---|
| AC-1–3 challenge/signature | Exact readable EIP-191 message, wallet/issuer/time/nonce plus tenant, actor, credential and deployment binding; 300-second TTL | Real signatures, wrong signer/context, malformed signatures, expiry boundaries |
| AC-4 attestation | Encrypted durable attestation, expires 86400 seconds after verification | Restart, exact TTL, independent tenants, concurrent single-use verification |
| AC-5 flag index 5 | Versioned extension Poseidon(domain, credential commitment, attestation digest scalar, issued_at, expires_at, wallet_ownership_verified) | Python/circuit parity, index/layout vector, existing credential commitment unchanged |
| AC-6 constraint | Isolated staged extension circuit; flag must be 1, commitment/context/time bound | Real witness success and adversarial witness rejection; no changed legacy/pilot artifacts |
| AC-7 endpoints | Authenticated challenge/verify/status/revoke/extension issuance; exact existing enrollment binding | Real HTTP and PostgreSQL tests, authorization failures and encrypted persistence |
| AC-8 revocation | Immutable scoped revocation; extension eligibility rechecked against attestation and enrollment | Revocation, expiry, and cross-issuer/tenant negative cases |
| NG-1 compatibility | Existing enrollment and legacy issuance/proof routes unchanged | Legacy regression tests and existing real proofs |
| NG-2/3 staged circuit | No on-chain changes or trusted setup; no claim extension is accepted by existing deployed verifiers | Diff/artifact inspection and explicit documented unsupported routing |

The extension proves an issuer-side recorded statement. The circuit does not
verify an EIP-191 signature, establish legal ownership or by itself authorize a
transfer. EOA wallets are supported; contract wallets require a separate profile.

Local verification: real EOA signatures and Circom witnesses pass, including
adversarial flag/context/time mutations. Real PostgreSQL and HTTP tests exercise
atomic single-use verification, reconnects, encryption, tenant/issuer/actor scopes,
expiry, parent revocation, attestation revocation and schema upgrades. The wider
storage regression suite passes 77 tests (7 artifact/CLI-dependent cases skipped
in that invocation). The full Python run passes 1023 tests (97 service/artifact
cases skipped without their environments). The SDK suite passes 173 tests.
Circomspect reports no findings in the new extension circuit. Existing required
CI proof jobs must still pass against the replacement PR before merge.

No prior PR #11 legacy circuit edits are included. Existing issuance and proof
formats are byte-for-byte preserved; the new commitment is a separate optional
extension, not an implicit migration. The original AC-5 representation is adapted
this way to satisfy the explicit backward-compatibility non-goal. AC-6 remains
staged, as required by the no-verifier-change/no-ceremony non-goals.

Merge and supersession require green remote CI and confirmation that the
replacement is merged. This document alone is not evidence that #11 is closed.
