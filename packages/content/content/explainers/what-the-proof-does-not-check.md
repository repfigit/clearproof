---
id: UP-EX-010
title: What the proof does not check — trusted issuers, published roots and configuration
date: 2026-10-12
publishAfter: 2026-10-12T00:00:00Z
sourceCommit: ae60385165b28cacb95ecc1c404ca9885ac1367c
claimRefs:
  - packages/content/content/topics/security.md
  - packages/content/content/topics/circuits.md
  - specs/pilot-transfer-v3.md
  - docs/operations/pilot-observability.md
status: approved
summary: A Groth16 proof can be cryptographically valid and still prove nothing you should act on. The pilot-transfer-v3 circuit enforces credential, sanctions and transfer binding inside the statement, but issuers, root publishers and configuration are trusted inputs no circuit can check — and the eight public signals can still be correlated. This explainer walks the trust boundary from the current source.
canonical: /explainers/what-the-proof-does-not-check
templateVersion: explainer-v1
---

A proof that verifies is the easy part. In Clearproof's pilot, every
cryptographic check succeeds or fails inside the statement: credential issuance,
holder knowledge, issuer authorization, sanctions non-membership, replay and
expiry binding, exact USD-cent valuation. But a Groth16 circuit cannot verify
its own inputs' provenance. Someone publishes the issuance tree, the sanctions
tree and the authorized-issuer tree — and the circuit proves membership in
whatever roots it is handed. This explainer walks the trust boundary that sits
around a valid proof, from the current source and the
[security documentation](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/security.md).

## What the circuit does enforce

The [pilot-transfer-v3 statement](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md)
(`PilotCompliance(32, 20, 20)`, 95,408 constraints) enforces, inside the
circuit:

- the credential is a member of the issuance root and its issuer is a member of
  the authorized-issuer root,
- the holder knows the secret behind the credential commitment, and the tenant,
  subject wallet and jurisdiction match the transfer,
- each raw 160-bit wallet address lies strictly between two adjacent leaves of
  the sorted sanctions tree (a gap proof, with adjacency derived from the Merkle
  path bits and all compared values range-checked),
- the nullifier binds the proof to one holder and one authorization scope, so a
  replacement proof cannot be spent twice, and the five-minute expiry bound is
  enforced in-circuit,
- the amount is converted to USD cents with exact integer arithmetic and the
  tier is derived privately from policy thresholds.

Eight values are public: the projection commitment, the two roots, the
nullifier, two timestamps and the chain/registry binding fields. The wallets,
amount, tier, jurisdiction, participants and credential fields stay private.

## What no circuit can check

The same documentation is explicit about who is trusted:

> Credential, holder, jurisdiction and transfer binding are enforced by the
> `pilot-transfer-v3` statement and the authorization service, tested locally.
> They rely on trusted issuers, root publishers and a trusted registry
> publisher; the contract cannot detect a publisher that lies about private
> records.

That sentence is the boundary this explainer is about. The circuit proves
membership in a root; it cannot prove the root's publisher included the right
leaves. A sanctions tree that omits a sanctioned address yields valid gap
proofs that mean nothing. An issuance root minted from a fake credential set
yields valid credential proofs. Merkle proofs are structural: they attest
"this leaf is in this tree," never "this tree is honest."

Three trusted roles sit outside the math:

1. **Issuers** mint the credentials in the issuance tree. A credential from an
   approved issuer is meaningful only if the issuer's approval actually
   happened and was recorded honestly.
2. **Root publishers** build and publish the issuance, authorized-issuer and
   sanctions trees. The authorization service must check *current* roots — the
   circuit sees a root as data, and cannot know whether it is fresh or
   correct.
3. **The registry publisher** publishes the on-chain deployment binding. The
   contract cannot detect a publisher that lies about private records.

## The rest of the boundary is configuration

Several checks depend not on the circuit but on the operator's configuration of
the authorization service and registry: domain, expiry, root freshness, replay
handling and duplicate consumption. The security documentation says this
directly:

> Domain, expiry, root and replay checks depend on correct configuration of the
> authorization service and registry. The site does not claim that replay is
> universally impossible.

The same file carries the key-management corollary: `PII_MASTER_KEY` startup
validation checks accepted encoding and minimum length, and "cannot establish
that a supplied value has adequate randomness." A validation pass on a weak
secret is a pass. Generate secrets securely and manage rotation and retention
deliberately.

Two more boundaries worth naming before you evaluate the pilot:

- **A valid proof is not an accepted transfer.** In the pilot, the
  authorization service checks current roots, revocation, policy and signed
  facts before consuming an authorization in PostgreSQL. Pairing alone checks
  none of these.
- **The eight public signals can still be correlated.** Commitments, roots, a
  nullifier and timestamps publish no amount, tier, jurisdiction or review
  flag — but timings and roots can still line up with other records an
  observer holds. The signal design minimizes exposure; it does not make the
  proof unlinkable.

## How to evaluate it

The documented evaluation path assumes none of the trust roles are honest by
default. Use synthetic records and testnet funds. Check approved issuer, root
and artifact provenance, recipient identity, key purpose, freshness, revocation,
transfer binding and duplicate handling. Confirm that sensitive inputs remain
inside authorized encrypted data flows and do not appear in logs or exports.

Clearproof is pre-production, pilot-stage software. Independent circuit and
contract audits have not been completed, current proving artifacts use a
development-only trusted setup, and testnet deployment with passing tests does
not establish production safety. The [local acceptance
guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/local-pilot-acceptance.md)
exercises the full synthetic path if you want to see these boundaries
demonstrated rather than described.
