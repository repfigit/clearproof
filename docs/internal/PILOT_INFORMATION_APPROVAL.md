# Exact information approval

`InformationApproval` is a separate, versioned Ed25519 statement binding exact
payload bytes, transfer/context digests, credential ID, source ID, source-evidence
digest, signing/expiry times and signing key ID. The payload schema is fixed to
`clearproof-transfer-information-v1`. Both key identity and signed message use
information-specific domains; an external business-fact or valuation signature
cannot substitute for this approval.

`InformationTrustStore` is independent operator configuration. It scopes keys to
tenant, chain, registry, allowed sources, validity and maximum approval lifetime.
Verification checks that the exact credential and payload match and that the
approval is currently valid within both the transfer and authority intervals.
Removing a key prevents new authorizations; overlapping replacement keys can be
approved explicitly. No network discovery response becomes trusted automatically.

Authorization requires this approval in addition to structural information
validation, current proof inspection, external business facts, policy ALLOW and
trusted recipient encryption. Signature verification occurs inside the tenant
transaction before current inspection and writes. Failed approval checks add no
records and cannot consume. The signed approval is retained only inside the
encrypted proof record. The receipt binds its signature through a digest; personal
payload fingerprints are not published in the receipt. Treat the full approval as
private evidence: its payload digest can support guessing attacks if disclosed.

Exact idempotent retries recover the original receipt after expiry or key removal;
they do not grant a new authorization. Changed payload bytes or a changed approval
with the same key conflict. A new request with altered information requires a new
source approval as well as all other current checks, and cannot spend an already
consumed authorization again.

The signer is an explicitly trusted source authority. Its signing utility does
not review KYC documents or establish their truth. Operators must define the
source review process before granting authority. The referenced source documents
are not fetched or retained by this service. Live source validation, independent
historical authority, full IVMS101 mapping and sender-authenticated delivery remain
separate work; local signatures do not certify legal sufficiency.

Tests use real Ed25519 keys and synthetic information. They cover correctly signed
scope substitution, independent authority limits, current time bounds, payload
and credential changes, key overlap/removal, source-reference tampering and
cross-purpose signatures. The PostgreSQL authorization test rejects a structurally
valid but unapproved name and an invalid signature, then verifies encrypted
approval retention and receipt binding after a real proof/authorization/restart.

## Historical source authentication

`InformationTrustStore.verify_attestation` verifies the source signature and exact
transfer/context/credential scope without accepting or decrypting private payload
bytes. The claimed decision time selects the original approval and key validity;
the separate reviewer time checks known key compromise. Ordinary expiration does
not invalidate a signature that was valid at the decision time. A removed key,
excluded source or compromise known by review time leaves authority unavailable;
a claimed earlier signing time does not bypass compromise.

Current `verify` still validates the exact payload hash and bounds before calling
the same attestation checks. Historical attestation verification cannot substitute
for current payload validation. The source evidence digest remains a signed
reference, not proof that the underlying documents were correct or retained.

Offline inspection accepts independent `information_trust` and reports
`information_authenticated`. Changing a signed source claim without updating its
signature contradicts the claim. The historical reviewer does not need the
beneficiary's decryption key and does not log payload fields or hashes. This
check authenticates the retained source assertion; it does not independently
prove that ciphertext decrypts to the approved payload. The authenticated
operator receipt binds the approved signature and recipient envelope together.
Historical root, valuation and fact checks also apply reviewer-time compromise
configuration. Support requires every layer in
[historical inspection](PILOT_HISTORY_INSPECTION.md).
