# Development current-state registry

`PilotCurrentRegistry` composes the eight-signal pairing verifier with approved
statement bindings, versioned tenant checkpoints and receipt-bound audit mirrors.
PostgreSQL is the pilot's authorization and replay authority. The contract cannot
create another authorization. A local preparation service authenticates retained
receipts and current evidence; chain publication and complete shared adversarial
acceptance tests remain required work.

## Trust boundary

The administrator assigns a publisher per opaque tenant hash. Only that publisher
can publish current heads and statement bindings. This follows the trusted
attestation option in ADR 0006: private records cannot be reconstructed from a
prover-supplied projection commitment, so a trusted publisher must independently
validate and attest their binding. The contract does not parse private transfer
JSON or verify the Python services' Ed25519 source approvals. It cannot detect a
publisher lying about a private projection, credential association or policy result.
Do not give a proof submitter publication permission merely because pairing passes.

Each statement binds an opaque context digest, transfer digest, projection
commitment, evaluation time, expiry bound, designated consumer and eight pins.
Its ID is the keccak256 ABI encoding of the tenant hash and complete statement;
an existing ID cannot be overwritten. Its artifact scope is the constructor-fixed
pairing verifier and manifest digest, and that verifier's deployed code hash is
checked at inspection. A manifest digest remains operator metadata, not setup
approval. The constructor must be given the independently inspected verifier.

Pins identify typed checkpoint scopes, exact digests and exact revisions:

| Index | Kind | Required source validation before publication |
| --- | --- | --- |
| 0 | Issuance | Approved issuance root and exact credential binding |
| 1 | Issuers | Current authorized issuer tree and source authority |
| 2 | Sanctions | Current sanctions tree and source authority |
| 3 | Credential | Wallet enrollment, eligibility, subject binding and revocation |
| 4 | Policy | Current reviewed activation, units, jurisdiction and version |
| 5 | Valuation | Approved exact asset, amount conversion and current signed quote |
| 6 | Participants | Retained signed policy facts, evaluated under the selected policy |
| 7 | Authorization | Exact consumed receipt ID, signed ALLOW decision, information approval and recipient requirements |

Those are publisher obligations, not operations implemented by `publishHead`.
Heads record a digest, value, monotonically increasing revision, validity interval,
publisher epoch and enabled flag. Root heads carry field-element root values;
authorization carries 0 or 1; other head values are zero. Publication requires the
expected current revision and bounded current validity. Disabling a head or replacing
its revision invalidates statements pinned to the prior revision. Restoring the
same digest does not restore the old statement's revision. A publisher can issue
new heads/statements; it must still enforce source-specific rules such as permanent
credential revocation and correct policy reactivation times through the bridge.

Every `setPublisher` call increments the tenant's epoch, including reassigning the
same address. This invalidates old statements and heads until they are republished
under the new epoch. Setting zero disables publication and inspection. Epoch
changes do not clear recorded receipt mirrors. Choose these changes deliberately.

## Inspection and receipt mirroring

`inspect` is a view call. It checks the statement's tenant and publisher epoch,
current enabled heads 0–6, their exact pins, expected projection and issuer/sanctions
root values, exact evaluation time, future bounded proof expiry, nonzero nullifier,
actual chain ID and this registry's address. Heads 0–5 must cover evaluation and
remain current. Participant facts and receipt approvals may be produced after
proof evaluation and must cover the current block time. The pairing verifier
checks the constrained proof and canonical scalars. A successful view does not
require an ALLOW checkpoint or record a mirror.

`mirror` requires the designated caller, an as-yet unmirrored tenant/nullifier,
all inspection checks, successful pairing, and an exact current enabled ALLOW head
at index 7. Its scope is the statement context digest and its digest must equal
the caller's receipt ID. The contract records that ID and emits
`AuthorizationMirrored`; wrong receipt IDs and duplicate mirrors reject. Inspection
can remain valid after mirroring. No payment, delivery or settlement is executed.
This replaces the development `consume` ABI; regenerate clients from the current
contract. No deployed production compatibility is asserted.

`consumptionOwner()` returns `postgresql`. Only the Python authorization service
creates the authoritative consumption. A contract mirror is an audit record of that
existing receipt; applications must never treat it as a second executable grant.
The database and chain are not atomic. Failed or delayed mirroring does not undo
or repeat database authorization. The publisher remains trusted to attest truthfully
that the receipt exists and was consumed; Solidity cannot query PostgreSQL.

## Atomic publication and recovery

`publishBatch(tenant, expectedEpoch, updates, statement)` publishes all eight
checkpoint selections and their statement in one transaction. Each update names
the expected current revision and either replaces the head or reuses it unchanged.
The statement must pin the resulting exact scope, digest and revision. Reuse
checks every stored value and interval as well as the current publisher epoch.
Replacement uses the same validation and monotonic revision rules as `publishHead`.
A failure anywhere, including final statement validation, rolls back all changes.
The caller must still be the independently configured tenant publisher.

Writers should read heads and publisher epoch at one pinned block, revalidate the
source preparation, and use this batch operation. Reuse matching current heads to
avoid invalidating other statements unnecessarily. A stale epoch or revision
requires a fresh source/state review; it is not permission to replace newer heads
with an old preparation. Batch publication does not record a receipt mirror or
change PostgreSQL authorization.

`statementPublication(id)` returns existence and the epoch recorded at publication.
It enables read-back of the deterministic statement ID after an uncertain send.
Existence is historical: it does not prove current head validity, current publisher
epoch, finality or mirroring. Reconciliation must check the configured chain and
runtime, transaction inclusion/finality, current epoch and heads, and the exact
`mirroredReceipts(tenant, nullifier)` value before reporting the relevant outcome.
Retain the intended statement ID and transaction identity before broadcast. Do not
blindly resend a new transaction after a timeout. The durable writer and its
recovery orchestration remain unimplemented.

## Authenticated preparation

`AuthorizationMirrorService.prepare` requires independently configured trust,
consumer, server transfer/context and private information. It checks export,
decryption, inspection, policy-read and tenant-admin permissions. Within one tenant
transaction it verifies the retained receipt/proof/envelope identities, exact
nullifier-to-proof consumption, signed decision, information approval, recipient
binding and current enrollment, roots, policy, facts, valuation and real pairing.
The current result must still be ALLOW. A missing consumption or expired authorization
cannot produce a plan, even if a signed historical receipt exists.

The returned `clearproof-authorization-mirror-plan-v1` contains opaque digests,
proof/signals, eight head candidates and the pinned consumer. It includes no raw
information, source signatures or envelope. It writes no records, assigns no chain
revisions and makes no RPC calls. `publication_state` is `not-published` and
`contract_effect` is `audit-mirror-only`. This bounded profile requires at least
one retained external fact; the policy determines how true/false facts affect ALLOW.

Candidate validity is capped by proof and source expiry, policy source validity,
recipient validity and authenticated fact/quote observation-age limits. Age limits
are inclusive integer seconds, so their exclusive deadline is observation time
plus maximum age plus one. Signed evidence is never rewritten to shorten expiry.
`publish_before` is the earliest candidate deadline, not a promise that sources or
trust will remain unchanged. Preparation is an as-of snapshot: the eventual writer
must revalidate current trust and durable state immediately before publication,
reconcile exact chain revisions/epochs, and invalidate superseded checkpoints.
Known future changes to other authority inventories also require that revalidation;
the preparation service is not an authority revocation scheduler.

## Evidence and remaining work

`test/PilotCurrentRegistry.test.ts` generates a fresh proof for the actually
deployed registry address through `scripts/pilot_contract_fixture.py`. That helper
uses only public synthetic fixture material and validates the generated proof with
Python's current-statement inspection before returning it to the EVM test. It
reuses inspected unapproved artifacts; it does not perform a new trusted setup.

Participant and ALLOW heads in these tests are synthetic checkpoint labels. They
are not a demonstration of authenticated live participant facts or business-policy
approval. Tests exercise valid read-only inspection, missing/non-ALLOW approval,
caller/tenant/context rejection, changed proof material, replay, checkpoint
supersession and restoration, disabled credentials/approval, expiry and publisher
replacement. Batch tests additionally cover atomic rollback after late rejection,
exact head reuse, stale epochs/revisions and deterministic publication lookup. The fresh-artifact builder invokes this suite using its own Python
interpreter and artifact outputs.

The real PostgreSQL authorization test independently exercises preparation from an
actual consumed receipt, same-clock/reconnect stability, read-only counts, exact
consumption presence, source age cutoff, invalid information/signers, role denial
and expiry. With `CLEARPROOF_MIRROR_TEST_RPC` explicitly selecting a loopback
Hardhat node, that same authorization fixture deploys the matching verifier and
registry before proof generation. Its proof therefore binds the actual registry
address. It re-prepares the consumed receipt at the current clock while PostgreSQL
remains live, publishes all eight authenticated head candidates atomically, checks
real pairing, mirrors the exact receipt and reads it back through a fresh contract
client. Wrong receipt/caller and replay reject; disabling a checkpoint invalidates
inspection while preserving the mirror. The database's final checks still require
exactly one consumption and unchanged retained-record counts.

`scripts/test_pilot_mirror.py` runs the full durable pilot suite with its own fresh
loopback node, isolated test database schemas and cleanup of owned processes. The
fresh-artifact CI job uses this runner. This is a synthetic local integration gate:
it does not fetch live sources, implement a durable publisher process or establish
shared database/chain finality. Checkpoint invalidation is explicitly submitted by
the fixture; it does not demonstrate an automated source revocation relay.

To complete CP-007, implement the publication writer and join these gates with
shared adversarial tests against actual enrollment, facts, policy, valuation,
information and recipient authorities. Reconcile uncertain transaction outcomes
without creating another authorization. These contracts and tests remain unapproved
development infrastructure and establish no production or legal assurance.
