# Registrar root approvals

`RootSnapshot` binds a root to a tenant, chain/registry, credential profile, root
kind, issuer (for issuance roots), tree depth, source evidence digest, revision,
predecessor and validity interval. `SignedRootSnapshot` contains an Ed25519
registrar signature over a domain prefix and the canonical snapshot bytes.
These signatures are verified outside the circuit.

Configure `RootTrustStore` with operator-pinned `RootAuthority` records. A record
scopes its public key to a tenant, deployment, allowed root kinds, exact issuance
issuer DIDs and a key-validity interval. Public keys supplied inside an evidence
bundle are not trust anchors. Snapshot validity must be contained within the key's
validity, last at most one day, and include the evaluation time. Retain explicitly
trusted old keys for historical evidence; removal causes old approvals to fail
verification. Key IDs derive from public-key bytes, not configurable labels.

`sign_root()` is a registrar utility, not an authorization policy. The registrar
must check the source tree, eligible enrolled credentials and issuer authorization
before signing. Signing an arbitrary caller root would defeat issuance membership.
`build_issuance_tree()` now constructs candidates from persisted eligible
enrollment. `PilotRegistrar.refresh()` now coordinates construction, local signing and
persistence in one tenant transaction. Independent current-head publication and
production registrar operations remain open. No production signing key or default trusted registrar is bundled.

`RootPublicationService.publish()` requires a tenant admin, encrypted-record read
access, and a valid scoped registrar signature. Issuance-root publication also
requires the exact issuer scope and credential issuance role. It appends a root
revision and checks the previous signed digest, revision, evaluation ordering and
tree depth atomically. Conflicting concurrent successors cannot both publish.
Audience-specific record IDs allow separate roots for each deployment. The
service currently has no public API route or automatic chain relay.

`verify_historical()` establishes that an approval was signed by a configured
in-scope key and valid at the supplied time. It does not establish that the root
was the accepted head then. `verify_current()` additionally requires an expected
head digest and context from an independently trusted current source. Never set
that expected digest from the caller's own snapshot. Database history is useful
for reconstruction but cannot independently detect a wholesale database rollback.
The chain/attestor head source and offline historical anchors remain activation
gates. Issuer and sanctions approvals here are records, not updates to deployed
oracles; deployed sanctions updates still require the existing all-chain relay.

The tests use actual Ed25519 signatures and isolated PostgreSQL schemas. They
cover scope, tampering, key retention, stale approval, concurrent successors,
predecessor mismatch, tenant isolation and pool reconnection. They do not claim
registrar operational independence, chain publication or real proof acceptance.


## Issuance tree candidates

`build_issuance_tree()` requires an issuer-scoped transaction with encrypted-read
access. It scans the tenant's enrollment IDs in deterministic order, checks the
issuer and enrollment deployment, re-verifies retained wallet signatures and
acceptance time, and excludes revoked, expired or screening-failed credentials.
Identity/commitment inconsistencies and malformed evidence stop construction.

The local pilot scan is capped at 256 total tenant enrollments; excess records
cause an explicit error, never a partial tree. This bound requires pagination and
incremental construction work before larger deployments. `PilotTree` uses sparse
Poseidon nodes with deterministic zero padding and supports depths 1–20 (default
issuance depth 8). It rejects duplicate IDs/leaves and capacity overflow. Its
membership witnesses are exercised by the actual credential WASM circuit tests.

The returned private source record binds tenant, issuer, audience, evaluation
time, depth and sorted credential IDs/commitments. Its canonical digest is the
snapshot's proposed `source_digest`; source records belong in encrypted evidence.
The candidate is not a signed approval. Hold the tenant lock through validation
and construction. Do not nest `RootPublicationService.publish()` inside that
transaction. Use `PilotRegistrar.refresh()`, which calls the shared transaction
persistence boundary after constructing and signing all roots.


## Atomic local registrar refresh

Provision `PilotRegistrar` with an authenticated tenant admin that also has exact
issuance scopes and encrypted-read access, an operator-configured set of 1–16
issuers, a local Ed25519 signer, and independently pinned verification authority.
Do not supply the issuer set, key or trust configuration from an API request.
`refresh(expected_revision=..., idempotency_key=..., now=...)` rebuilds every
configured issuer from current enrollment/revocation state, signs each issuance
root, constructs and signs the aggregate issuer root, and persists all revisions,
source records and the retry receipt in one tenant transaction. The first expected
aggregate revision is zero. Changed/stale expectations conflict. The configured
issuer set determines the aggregate membership; removing an issuer removes it
from the next aggregate even though its historical issuance approvals remain.

Migration 10 adds the immutable `root-source` record kind. Source records stay
encrypted and are addressed by their canonical digest. Any scope/signature,
predecessor, source or database failure rolls back the entire refresh. A revoked
credential cannot interleave between construction and commit. A revocation that
commits afterward still requires the current verifier's revocation check and a
subsequent refresh; this service does not broadcast chain updates automatically.

Matching retries return the original publication receipt, not an assertion that
its root is still current. The local refresh is not a production key-management
service. It neither publishes an independently trusted head nor provides a new
HTTP endpoint. Those integration gates and real composed proofs remain open.
