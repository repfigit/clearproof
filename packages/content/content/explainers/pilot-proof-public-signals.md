---
id: UP-EX-002
title: The pilot proof's eight public signals — what they show and what they hide
date: 2026-09-16
publishAfter: 2026-09-16T00:00:00Z
sourceCommit: caa15cb49a3d9da8f0978dcfaebf5bf958161b67
claimRefs:
  - README.md
  - specs/pilot-transfer-v3.md
  - packages/content/content/topics/security.md
  - packages/content/content/topics/circuits.md
status: approved
summary: A Clearproof pilot proof publishes exactly eight public signals. Reading them is the fastest way to understand what a verifier learns without the encrypted envelope — and what it still cannot conclude.
canonical: /explainers/pilot-proof-public-signals
templateVersion: explainer-v1
---

Every Groth16 proof publishes a fixed array of public signals. In a Travel Rule
system those signals are metadata that any verifier — and anyone who sees the
proof — can read. So before evaluating any privacy claim, it is worth reading
the actual array. Clearproof's current pilot profile, `pilot-transfer-v3`, has
exactly eight. The
[public statement](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md)
in the repository lists them in mandatory order:

| Index | Signal |
| --- | --- |
| 0 | `projection_commitment` |
| 1 | `authorized_issuer_root` |
| 2 | `sanctions_root` |
| 3 | `authorization_nullifier` |
| 4 | `evaluated_at` |
| 5 | `proof_expires_at` |
| 6 | `domain_chain_id` |
| 7 | `domain_registry` |

## What a verifier learns from these alone

The three root signals (`authorized_issuer_root`, `sanctions_root`) and the
timestamp pair (`evaluated_at`, `proof_expires_at`) say which sanctions tree,
issuer set and validity window the proof was built against. The domain pair
(`domain_chain_id`, `domain_registry`) pins the exact chain and registry
deployment the proof is bound to, which is what stops a proof made for one
deployment being replayed against another.

Two signals deserve closer reading. `projection_commitment` is a Poseidon hash
over the 48-field canonical transfer projection, the exact credential
commitment and the issuance root — it reveals nothing about the fields, but it
does mean the verifier must independently reconstruct the expected commitment
from its own authenticated records before the proof means anything.
`authorization_nullifier` is deliberately unlinkable-by-design across
contexts: it prevents the same holder authorization being consumed twice
without identifying the holder.

## What is deliberately not public

The v3 profile carries **no public amount tier and no SAR advisory flag**. The
[README](https://github.com/repfigit/clearproof/blob/main/README.md) is
explicit about this, and about the contrast: the older 16-signal
`compliance.circom` demo profile publishes amount-tier and SAR metadata among
its sixteen values. The README warns never to select artifacts by signal count
alone and never to reinterpret legacy proofs as current pilot authorization —
a real risk, because both profiles have passing tests and committed manifests.

## The boundary that matters more than the signal list

The security documentation states the boundary directly: public signals expose
metadata, and omitting a named field from a bridge payload does not conceal
information that remains in the public-signal array. A valid proof establishes
its encoded statement — nothing more. Proof verification alone neither
authenticates the verifier's reconstructed records nor establishes current
roots, revocation, policy compliance or legal compliance. Current circuits and
contracts have not completed an independent audit, and generated proving keys
are explicitly unapproved development artifacts.

If you are evaluating the system, the signal array is where to start: it tells
you exactly what every observer learns, before any encrypted envelope is even
opened. The full statement, including the private 48-field projection and the
subcircuit binding, is in
[specs/pilot-transfer-v3.md](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md).
