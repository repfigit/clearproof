# Pilot enrollment inventory and backfill

Enrollment adds its credential and opaque tenant/issuer/deployment index entry
atomically, together with an encrypted audience count head and retry receipt.
The index stores opaque credential IDs and domain-separated audience digests;
wallets, signatures and credential contents stay in encrypted records. Admission
allows at most 256 distinct audiences per tenant. No startup decrypts old data,
assigns it an owner or automatically changes retained enrollment.

## Discover current enrollment

`POST /pilot/credential/list` requires `credential:issue`, `evidence:decrypt` and
the exact canonical issuer DID grant. Admin does not imply these roles. The
operator configures `PILOT_CHAIN_ID` and `PILOT_REGISTRY_ADDRESS`; the request
cannot select a tenant or another deployment. Supply selectors in a private JSON
body, not a URL or access log:

```json
{"issuer_did":"did:web:issuer.example","limit":64}
```

The response contains `checked_at`, at most 64 `{credential_id, eligible}`
entries, `next_cursor`, `scope: "live-enrollment-inventory"` and
`authorization_consumed: false`. Repeat with `after` set to the returned cursor.
Never log production request/response bodies. Successful responses are marked
`Cache-Control: no-store`. Each page uses a tenant transaction and authenticates
retained consent/signatures, acceptance time and current revocation. Eligibility
also requires valid credential time and successful recorded screening. It does
not establish independent KYC, sanctions feed freshness, signed root membership,
proof validity or transfer authorization.

Pagination is a live view: enrollments inserted before the cursor can be missed
by an ongoing walk, and revocations can change eligibility between requests.
Restart discovery for a new complete view. Registrar root construction instead
holds the tenant lock through a complete audience scan and revalidation.

The index is checked against encrypted count heads and the existence of all
retained enrollment. Missing records/index entries, scope changes and ciphertext
corruption fail closed. A coordinated rollback of the entire database is not
independently detectable by these records; trusted current-head checks still
apply. A bad or incomplete audience blocks tenant discovery and root refresh
until the operator repairs it; the service never silently truncates.

## Upgrade retained records

After migration 22, existing credential records remain encrypted but unindexed.
Use `POST /pilot/credential/backfill` with explicit `tenant:admin`,
`credential:issue`, `evidence:decrypt` and every relevant issuer grant. Start with:

```json
{"limit":64}
```

Repeat with `after` set to `next_cursor` until it is null. Each page authenticates
the immutable consent, original acceptance interval, tenant identity, commitment
and wallet signature before indexing. Expired or revoked credentials can be
indexed because backfill establishes historical enrollment, not current
eligibility. A malformed record or missing issuer grant rolls back the entire
page. Correct the source through a reviewed operator recovery procedure; never
invent consent or disable signature checks to finish migration.

The response includes `validated_records`, `next_cursor` and
`inventory_complete`. Pages can be retried safely, and indexes survive connection
or application reconstruction. A null cursor alone does not prove completion:
starting past skipped records leaves `inventory_complete: false`. Discovery and
root construction independently reject missing indexes. Keep backups and key
retention in place before migration, and check completion for every tenant.

## Root source and capacity

The accepted pilot circuit has a 32-level issuance path. Sources of up to 256
leaves preserve the original source format/digest. Larger sources use a bounded
manifest and encrypted 128-entry pages. Every referenced page is authenticated
and included in root reconstruction; a missing page prevents witness creation.
Publication and its retry receipt are atomic. The software guard is 1,024 scanned
enrollments across all configured issuers in one registrar refresh, including
expired/revoked entries; a 30-second tenant
transaction limit also applies. These are guards, not throughput guarantees.

See the [synthetic inventory benchmark](../benchmarks/2026-10-06-pilot-enrollment-inventory.md)
for measured workloads and exclusions. Real accepted-profile proof tests exercise
258 enrolled leaves, a 32-sibling witness and independent pairing verification.
No circuit, accepted public-signal count or proving key changes for pagination.
