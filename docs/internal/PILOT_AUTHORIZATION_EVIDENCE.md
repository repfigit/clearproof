# Captured authorization evidence

Additive migration 15 introduces immutable encrypted `authorization-evidence`
records, writable with `proof:generate`. Authorization captures evidence in the
same tenant transaction as the verified decision, recipient envelope and
nullifier consumption. A subsequent failure rolls back the capture too.

The receipt binds a `clearproof-authorization-evidence-v1` manifest. It pins exact
retained record identities, revisions and canonical byte hashes for enrollment,
reviewed policy, policy activation, issuance/issuer/sanctions roots and external
fact attestations. Revision references must be resolved as recorded; reading the
latest root or policy during export would change the evidence.

The manifest also identifies captured bytes for the artifact manifest, matching
verification key, complete asset catalog, signed valuation approval and configured
root pins. These are retained in content-addressed encrypted chunks, bounded to
fit canonical storage. Each descriptor records size, SHA-256 and ordered chunk
identities. The verification runtime is identified by its pinned bundle hash;
the runtime itself is an independently installed verifier dependency.

The capture records `captured_at` separately from source signatures and decision
time, and labels its clock `operator-clock-only`. Its credential status says only
that no revocation was present in the local tenant store at the observed time.
This is not authenticated global revocation history or trusted timestamp evidence.
Later revocation or activation cannot overwrite the prior capture, but must still
be considered by a future historical verifier under independently configured
trust and compromise rules.

This is the durable input-preservation layer for CP-015. A separate
[encrypted export service](PILOT_EVIDENCE_EXPORT.md) assembles these pinned records
for an approved reviewer. Authenticated decision/timing evidence, independent bundle trust configuration,
and offline supported/contradicted/indeterminate evaluation are not implemented by
the capture function. Captured manifests or keys are evidence to check, not trust
anchors to accept automatically.

The real proof/PostgreSQL authorization test reconstructs all captured bytes,
checks hashes and pinned revisions, rejects cross-tenant reads and mutation, then
changes policy activation and revokes the credential. After reconnect it verifies
that the capture still identifies the original activation and observation. The
existing failure-after-consumption injection checks that chunks and manifest also
roll back with the rest of authorization.

New captures include `clearproof-local-status-observation-v1`, binding the issuer
and a tenant/deployment registry ID to the credential and observation time. The
decision signature covers this manifest through its digest. Independent
[historical status delegation](PILOT_HISTORY_STATUS.md) is required to regard
that registry as authoritative for the issuer; capture alone cannot approve it.
