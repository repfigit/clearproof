# Historical timestamp evidence

`timestamp_request(SignedDecision)` constructs an RFC 3161 DER query over the
complete signed decision using SHA-256. It performs no network or file I/O. An
operator-controlled adapter may obtain a response from an approved authority;
the local test helper uses OpenSSL with ephemeral synthetic certificates/keys.

`TimestampEvidenceService.attach` requires `proof:generate` and `evidence:decrypt`.
It loads the tenant's original receipt/proof, independently authenticates the
decision, verifies the response with server-approved timestamp trust, and checks
the complete timestamp accuracy interval lies within the allowed decision window
and before proof expiry. It stores a bounded response as encrypted chunks inside
one immutable authorization-evidence record. It never alters the original receipt
or consumes another authorization. An exact response retry returns its identity;
a different response conflicts. Revalidation still applies on retries.

Exports include the retained timestamp when present. Offline inspection accepts
reviewer-supplied `timing_trust`; bundled certificates cannot configure that trust.
Successful verification sets `timing_authenticated` and a `timestamp_observation`
with genTime/accuracy in integer microseconds, TSA certificate fingerprint and
policy OID. Missing, changed, oversized, untrusted or out-of-window evidence leaves
review indeterminate. A successful timing check can coexist with missing decision
trust; it authenticates existence of bytes, not their truth.

The [timing ADR](../adr/0010-historical-rfc3161-timing.md) documents the maintained
library, certificate/policy pinning, accuracy and compromise rules. No production
TSA or operational clock assurance is claimed. Historical source approvals and known compromise are checked separately.
A supported local-decision result requires every independent trust layer described
in [historical inspection](PILOT_HISTORY_INSPECTION.md).

Tests exercise real OpenSSL responses, offline verification after certificate
expiry, incorrect leaf/root pins and policy, tampering, rebinding, future review,
insufficient capture window and known compromise. The PostgreSQL scenario creates
a current synthetic proof, retains the verified response, checks role rejection,
exact retries and restart, exports after later policy/revocation changes, then
verifies pairing and timestamp in a fresh process with the database closed and
Python socket connections disabled. Only encrypted evidence leaves the service.
