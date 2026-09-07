# Development current-state registry

`PilotCurrentRegistry` composes the eight-signal pairing verifier with approved
statement bindings, versioned tenant checkpoints, caller restrictions and a local
nullifier consumption map. This implements contract-side checkpoint mechanics;
it does not yet establish complete acceptance parity with the authenticated Python
services. The bridge that validates real source evidence and publishes these
checkpoints remains required work.

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
| 6 | Participants | Independently authenticated participant/VASP state |
| 7 | Authorization | ALLOW decision, information approval and recipient requirements |

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
changes do not clear nullifier consumption. Choose these changes deliberately.

## Inspection and consumption

`inspect` is a view call. It checks the statement's tenant and publisher epoch,
current enabled heads 0–6, their exact pins and validity at evaluation/current time,
expected projection and issuer/sanctions root values, exact evaluation time,
future bounded proof expiry, nonzero nullifier, actual chain ID and this registry's
address. The pairing verifier checks the constrained proof and canonical scalars.
A successful view call does not require an ALLOW checkpoint or spend a nullifier.

`consume` requires the statement's designated caller, an unconsumed tenant/nullifier,
all inspection checks, successful pairing, and an exact current enabled ALLOW head
at index 7. That head's scope must be the statement context digest. Only then is
consumption written and an event emitted. Invalid pairing, stale state, wrong caller
or unavailable/non-ALLOW approval cannot consume. Subsequent consumption rejects,
while repeated inspection can remain valid. No payment, envelope delivery or
settlement is executed.

This map is local to the registry. It is not synchronized atomically with the
Python database's consumption map. The eventual integration must explicitly choose
and enforce an authoritative consumption path; it must not offer the same logical
authorization for independent consumption in both stores.

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
replacement. The fresh-artifact builder invokes this suite using its own Python
interpreter and artifact outputs.

To complete CP-007, implement the authenticated publisher/exporter and shared
adversarial tests against the Python service's actual enrollment, facts, policy,
valuation, information and recipient authorities. Resolve source freshness and
consumption ownership explicitly. These contracts and synthetic tests remain
unapproved development infrastructure and establish no production or legal assurance.
