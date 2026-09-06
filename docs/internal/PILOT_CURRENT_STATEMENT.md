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
