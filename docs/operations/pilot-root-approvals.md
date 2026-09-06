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
Automatic tree construction from enrollment and that policy enforcement are still
pending. No production signing key or default trusted registrar is bundled.

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
