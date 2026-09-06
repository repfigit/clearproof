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

After those checks, the existing pinned verifier performs real Groth16 pairing
over the captured public vector. This is not full reconstruction of the private
statement or verification of historical policy/source authority. The report keeps
`integrity_valid` and `cryptographic_valid` separate from its historical outcome:

- Altered linked evidence or failed pairing yields `contradicted`, with a scoped
  integrity/pairing reason. This contradicts the artifact's claim; it is not a
  regulatory policy DENY decision.
- Missing referenced evidence or unavailable pairing yields `indeterminate`.
- Successful integrity and pairing also yields `indeterminate`, explicitly naming
  unverified statement semantics, decision authority, historical revocation and
  independent timing evidence. This implementation cannot yet return `supported`.

Proof expiry at the reviewer's time does not itself prevent historical pairing.
`verified_at` is recorded separately; embedded decision/capture times remain
claims to authenticate. A locally observed absence of revocation is not upgraded
into historical non-revocation, and valid pairing cannot authorize a replay.

The PostgreSQL/real-proof scenario checks exported history after expiry, later
policy activation and credential revocation. It rejects altered receipts, roots,
policies, keys, envelopes, signals and duplicate records; missing source records
remain indeterminate. A fresh process decrypts and pairs with database access
closed and Python socket connections disabled, using independently supplied
artifact and runtime pins. Reports contain codes and booleans, not personal fields.

Required next layers are authenticated statement/source/policy reconstruction,
historical status and compromise handling, decision/timing authority, the
`supported` path and `verify-history` CLI. This stage does not complete CP-015.
