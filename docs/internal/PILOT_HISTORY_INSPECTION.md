# Offline integrity and proof inspection

`inspect_history_bundle` accepts a decrypted export, an independently configured
`PilotPairingVerifier`, expected tenant and receipt ID, and the reviewer's current
verification time. It performs no network calls, database reads, writes or
authorization consumption. The bundle cannot choose the expected receipt pin or
the verifier's artifact/runtime pins.

Integrity checks cover receipt and evidence-manifest identities, transfer/context
scope, proof bytes/digest, profile/artifact/runtime agreement, public domain/time
fields, nullifier, declared policy-decision references, exact recipient-envelope
binding, information-signature digest, proof identity, unique record references
and pinned record hashes. Captured configuration must match its recorded bytes
and the independently supplied artifact manifest and verification key.

With reviewer-supplied `HistoryStatementTrust`, inspection also reconstructs the
v2 expected public vector at the claimed authorization time. It revalidates the
captured wallet consent and credential/audience binding, compares captured root
pins with independently approved historical pins, verifies signed root and
valuation approvals, rebuilds the catalog, and uses independently selected policy
thresholds. The same current-statement implementation performs the projection,
credential/root binding, integer valuation and lifetime checks. Reviewer time is
not substituted for the claimed historical evaluation time.

The pinned verifier then performs real Groth16 pairing against those expectations.
Without statement trust it checks only the captured vector. The report keeps
`integrity_valid` and `cryptographic_valid` separate from its historical outcome:

- Altered linked evidence or failed pairing yields `contradicted`, with a scoped
  integrity/pairing reason. This contradicts the artifact's claim; it is not a
  regulatory policy DENY decision.
- Missing referenced evidence or unavailable pairing yields `indeterminate`.
- Successful reconstruction sets `statement_valid`; unavailable historical trust
  stays indeterminate, and a reconstructed-vector mismatch contradicts the claim.
- Successful pairing still yields `indeterminate`, naming any unverified decision authority,
  historical revocation and independent timing evidence gaps. If reconstruction
  was omitted, unverified semantics is also reported. This implementation cannot
  yet return `supported`.

Supplying independent `fact_trust` as well as statement trust enables conditional
policy replay after successful reconstruction and pairing. Exact retained fact
IDs and signatures, source/tenant/context scope and historical validity are checked
at the claimed authorization time. The same derived-fact helper used in current
authorization combines the facts, and the policy evaluator must reproduce the
entire retained report, including its reasons and matched rules.

`policy_reproduced` describes that conditional equality. The replay explicitly
requires the captured local non-revocation observation at the decision time; it
does not authenticate that observation. Missing or untrusted fact authority stays
indeterminate. A report that differs from the replay is contradicted even when
the underlying Groth16 proof is valid. No policy replay runs on failed pairing or
without reconstructed statement semantics.

Proof expiry at the reviewer's time does not itself prevent historical pairing.
`verified_at` is recorded separately; embedded decision/capture times remain
claims to authenticate. Integrity and pairing alone cannot upgrade a locally observed absence of
revocation into authoritative historical status or authorize a replay.

The PostgreSQL/real-proof scenario checks exported history after expiry, later
policy activation and credential revocation. It rejects altered receipts, roots,
policies, keys, envelopes, signals and duplicate records; missing source records
remain indeterminate. A fresh process decrypts and pairs with database access
closed and Python socket connections disabled, using independently supplied
artifact and runtime pins. Reports contain codes and booleans, not personal fields.

Tests also reconstruct the expired historical proof with independent original
pins and reject a replacement root pin or the latest policy selection. Accepting
historical pins is an explicit reviewer configuration decision; the bundle does
not establish those pins' authority or prove absence of intervening compromise.

Tests reproduce the original policy report, detect a fabricated report reason,
and refuse a fact source excluded by reviewer trust. Successful replay still
retains status history and independent timing reasons, plus decision authority
when its independent check is omitted.

Required next layers are broader source compromise handling, independent timing authority, the
`supported` path and `verify-history` CLI. This stage does not complete CP-015.

Reviewer-supplied `decision_trust` verifies the retained
[decision attestation](PILOT_DECISION_ATTESTATION.md) against the exact receipt,
evidence and context. Success sets `decision_authenticated` and removes the
unverified-decision reason. An invalid signature yields `contradicted`; missing,
unknown or compromised authority yields `indeterminate`. Compromise is checked at
reviewer time, so an operator's claimed earlier time cannot bypass it. Successful
authentication still leaves historical status and independent timing unresolved.

Optional reviewer-supplied `status_trust` independently delegates registry status
authority for the issuer. The [historical status check](PILOT_HISTORY_STATUS.md)
runs only after statement reconstruction, verifies the signed captured observation
and records `status_authenticated`. Successful status authentication removes the
missing-revocation-evidence reason for that configured pilot registry scope;
independent timing remains unresolved. Current status is never queried or used
as a replacement for the original observation.
