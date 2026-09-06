# Read-only current statement inspection

`src.prover.pilot_current.inspect_current_statement` connects independently pinned
artifacts, current root approvals, current policy selection and signed valuation
evidence to v2 pairing inspection. It reconstructs the expected public statement
from the exact transfer/context and credential rather than accepting an expected
signal vector from the caller. A disagreement rejects before cryptographic work.

The configured context, catalog, policy inventory, root pins/key authorities,
valuation authorities, credential and verifier clock must come from authenticated
server state. They are not proof-request fields or trust inferred from included
signatures. Root checks cover evaluation and current time; transfer freshness,
credential expiry, policy validity and valuation observation age are rechecked at
the current clock. The exact credential and approved issuance root determine the
outer v2 projection commitment.

The nullifier and requested expiry originate in public proof signals. Expiry must
still be future and bounded by credential/transfer expiry and evaluation plus
300 seconds. The pairing proves the nullifier's constrained derivation and expiry
limits. Current authorization must separately enforce nullifier consumption and
read credential revocation consistently with its transaction.

This function returns a `PairingInspection`, not an authorization. It does not
load durable enrollment, establish revocation history, authenticate business-policy
facts, decide Travel Rule acceptance, encrypt a payload, or consume an authorization.
Those service integrations remain required. The fixed circuit statement is also
not evidence that arbitrary policy rules have ZK coverage.

The synthetic development builder can now produce contexts carrying actual signed
root snapshot digests. Its deterministic root signing key is public test material,
never production trust. The real pairing gate reconstructs the simulator trust
independently and invokes this inspection boundary. Unit checks cover mismatched
credentials/issuers, policy replacement, forged quotes and time/expiry bounds;
substituting another valid credential changes the expected public commitment.

## Durable inspection service

`ProofInspectionService` accepts authenticated server configuration and a tenant
principal. It requires `proof:inspect` and `evidence:decrypt`. Its request selects
only a credential ID, proof and public signals; server configuration supplies the
transfer/context and trust inventories. The service loads and revalidates the
wallet-signed enrollment, current eligibility and revocation record, then checks
that the retained issuance/issuer/sanctions heads equal the configured approvals.
A newer retained revision invalidates an older configured pin.

All reads and pairing run inside the existing tenant transaction lock, serializing
with supported enrollment, revocation and root writers. This bounds a potential
revocation race at the local storage boundary, but does not create a policy
activation protocol or a cross-system snapshot. The service performs no writes and
returns cryptographic inspection only. It does not consume a nullifier or decide
business-policy authorization. Pairing holds the tenant lock for its bounded
runtime; this is acceptable for the bounded local pilot, not a throughput claim.

The PostgreSQL integration enrolls a synthetic EOA through `EnrollmentService`,
publishes signed roots, inspects a real development proof, reconnects, and repeats.
It rejects a foreign tenant, missing role, modified signal, newly replaced root
head and revoked credential. Read-only record and consumption counts are checked.
The circuit CI job runs this test with its own fresh artifacts and PostgreSQL
service. Standalone database tests without an artifact directory skip this gate;
set `CLEARPROOF_PILOT_TEST_ARTIFACTS` to a fresh generated pilot directory to enable
it. An enabled gate fails on missing or incompatible files.

The same real-proof database gate now exercises concurrent revocation. It pauses
inspection at the pairing-call boundary while the tenant transaction is held,
starts the normal revocation service, and observes an actual ungranted PostgreSQL
advisory lock for that tenant in the test database. Completion releases the lock,
allows revocation to commit, and makes the next inspection reject. Cancellation
at that boundary also releases the transaction and permits revocation. The
successful branch still performs actual pairing; no cryptographic result is
mocked. The cancellation branch does not claim to cancel a running prover process.

Exact record counts by kind show only the revocation and its idempotency receipt
were written; no authorization was consumed. This establishes the tested local
transaction ordering, not a guarantee that a credential remains unrevoked after
an inspection result is returned, and not an atomic authorization decision.
