# ADR 0003: authenticated pilot credential construction

Status: accepted for implementation; not activated for legacy authorization.

The legacy five-field commitment omits subject and jurisdiction. Membership of an
issuer DID alone cannot authenticate any particular credential. Profile
`clearproof-credential-v1` therefore uses two membership proofs: the complete
credential is in an issuance tree; the issuer identity and that issuance root are
in a separately authorized issuer tree. A caller-selected root is never trusted.

A credential commits to a version domain, the full SHA-256 issuer DID and tenant
identity (each split into two 128-bit limbs), a 256-bit random credential nonce
(two limbs), subject EVM address, holder commitment, jurisdiction, KYC tier,
issuance/expiry times and the issuer's screening assertion. Hashes are not reduced
modulo the scalar field. The holder commitment is Poseidon(101, secret), with a
nonzero canonical BN254 secret generated and retained by the holder. The leaf is
Poseidon(102, remaining fields), using the exact order in the Python model and
circuit. The authorized issuer leaf is Poseidon(103, issuer_hi, issuer_lo,
issuance_root). Merkle internal nodes use the existing Poseidon(left, right).

The circuit checks holder-secret knowledge, both memberships, bound tenant and
subject/jurisdiction, valid tier, positive screening assertion, issuance no later
than evaluation, and expiry strictly after evaluation. A transfer-specific holder
authorization/nullifier belongs in the composed transfer circuit; this credential
subcircuit alone does not authorize a transfer or consume anything.

Trust authorities and activation requirements:

- The configured authentication provider grants exact issuer scopes within a
  tenant. An issuer-scoped principal can issue only for that issuer. The service
  must verify wallet-signed enrollment consent binding tenant, credential nonce,
  holder commitment, issuer and expiry before recording issuance. Secret knowledge
  alone does not prove that the issuer checked the wallet's authority.
- An operator-configured registrar authenticates approved issuer/root changes,
  binds tenant, profile, revision and validity to signed snapshots, and publishes
  the authorized root. Verifiers authenticate that registrar and compare against
  the configured current root; signed input supplied by a caller is insufficient.
- Issuance-root authentication and wallet-signature verification occur outside
  the circuit. The circuit proves membership in the trusted root and possession
  of the bound secret. Do not describe those external signatures as ZK-verified.
- Revocation, issuer status, root freshness, transfer facts, recipient identity,
  policy and deployment audience are additional composed verifier requirements.
  Historical verification uses the independently authenticated snapshot valid
  for its evaluation time and does not consume a current authorization.

Legacy five-field credentials cannot be converted without fresh issuer approval
and holder enrollment. Keep historical verification explicitly versioned; never
route legacy proofs into the new authorization profile. The subcircuit and its
witness checks are development components. Activation requires the composed
proof ABI, trusted snapshot handling, real Groth16 proofs and all adversarial
acceptance checks in the adoption plan. No production ceremony is claimed.


Implementation checkpoint: the local pilot now has wallet-signed enrollment,
registrar-signed root snapshots, composed credential/transfer witness checks and
real development Groth16 verification. The [v2 binding decision](0009-credential-bound-pilot-profile.md)
adds the exact credential and issuance root to the outer commitment so two valid
credentials cannot substitute for each other under one public statement. The
[enrollment service](../operations/pilot-enrollment.md) rechecks retained consent;
[current inspection](../internal/PILOT_CURRENT_STATEMENT.md) reconstructs expected
signals using independently configured root authorities/current pins and the
retained credential. Wallet and registrar signatures remain outside ZK.
The full pilot and production assurance gates remain separate from this decision.
