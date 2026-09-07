# Decision attestation

Local authorization requires a server-configured `DecisionSigner`. Its Ed25519
signature binds the exact receipt digest, captured evidence digest, tenant,
chain/registry, verification context and claimed decision time. The signature uses
a dedicated domain, separate from information approvals. Signing failure rolls
back evidence capture and prevents receipt retention or consumption. The signed
statement is retained inside the encrypted proof record and included in exports;
private signing keys are never retained there.

Offline review supplies an independent `DecisionTrustStore`. A bundle cannot
approve its own signer. Keys are scoped to a tenant and deployment and must have
been valid at the claimed decision time. Key expiration permits older signatures;
removing the key makes authority unavailable. A known compromise at or before
review time rejects trust even if the statement claims an earlier decision time:
that self-asserted timestamp cannot prove a signature predates compromise.

Successful verification sets `decision_authenticated`. A changed signature or
receipt binding contradicts the claim. Missing, removed, out-of-scope or compromised
signer authority leaves the review indeterminate. The signature authenticates the
operator decision, not every underlying source's truth or legal sufficiency.

The statement explicitly labels its clock `operator-clock-only`. This is not an
independent timestamp or proof of historical non-revocation. Historical support requires all independent checks. Status requires separate
[registry authority delegation](PILOT_HISTORY_STATUS.md); independent timing
evidence remains required. Exact idempotent retries recover the original receipt even after signer
rotation or expiry and do not create a fresh authorization.

Tests use real synthetic Ed25519 keys for scope, receipt rebinding, purpose,
expiry, rotation and compromise rejection. The real-proof PostgreSQL scenario
checks signing failure rollback, exported signature verification, tampering and
compromise after the claimed decision time.
