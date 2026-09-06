# Scoped external policy-fact attestations

`src.policy.fact_approval` authenticates claims about applicability resolution,
counterparty trust, required information completeness and counterparty
acknowledgment. The signer is independently configured for a tenant, chain,
registry, source IDs, predicates, validity interval, maximum fact lifetime and
maximum observation age. Ed25519 signatures use a distinct application purpose
and bind the exact transfer and verification-context digests, predicate, boolean
value, evidence digest, observation/expiry times and signing time.

Authority configuration cannot be derived from an incoming attestation. Retaining
a signature does not establish the claim's truth, legal sufficiency, the source
document's availability or independent trusted timing. Those remain operational
and historical-verification requirements. A context digest also binds its policy,
artifact and deployment; an attestation cannot silently migrate to another context.

Verification accepts up to 64 attestations and 256 configured authorities. Exact
retries deduplicate; different attestations for a single predicate reject even if
both signers are trusted. Arrival order never chooses a winner. False values stay
false, and missing facts stay missing. The output is minimized `PolicyFacts`, not
an authorization, approval or claim of complete evidence.

Attestors cannot supply credential validity, sanctions clearance, valuation
authentication or proof validity. Those predicates must come from the appropriate
current verification workflow. Tests feed externally attested facts into the
existing evaluator and require INDETERMINATE while those derived facts are absent.

The verification module performs no network calls or storage writes; the retention
service below provides encrypted persistence. Policy activation and atomic
authorization remain open. Services must apply independent current trust and
combine derived facts only after their corresponding checks succeed. Evidence
digests alone are not retention of underlying source documents.

## Encrypted retention and current loading

`FactEvidenceService` now verifies a bounded batch before retaining complete signed
attestations as immutable encrypted `fact-evidence` records. Additive migration 13
permits this record kind. Ingestion requires `facts:ingest` and `evidence:decrypt`;
current loading requires `policy:read` and `evidence:decrypt`. Tenant scope comes
from the authenticated principal.

Record IDs bind the exact signed attestation. Repeated/concurrent identical
batches preserve the first receiver/time metadata; changed signed evidence gets
a distinct identity and cannot silently overwrite old evidence. A tenant
transaction makes each batch atomic. Current reads recompute the identity and
recheck signature, scope and freshness using the configured current trust store;
a removed key does not stay trusted just because its evidence was retained.

The service retains the signed fact and its evidence digest, not the underlying
source document. Receipt times are server observations, not independently signed
timestamps. Historical authority, source retention, policy activation and atomic
authorization remain open. The read path does not consume an authorization or
send counterparty messages.

Real PostgreSQL checks cover rollback on a second-record insertion failure,
concurrent duplicate deliveries, exact retention across reconnect/retry, current
loading, expiry, role and tenant isolation, key removal, invalid signatures,
ciphertext privacy and unchanged authorization consumption.
