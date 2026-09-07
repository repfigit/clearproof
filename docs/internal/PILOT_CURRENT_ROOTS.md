# Current pilot root verification

`src.prover.pilot_roots.verify_pilot_roots` checks the issuance, authorized-issuer
and sanctions approvals required by the depth-eight pilot profile. Its
`CurrentRootPins` are independently supplied operator/current-state configuration,
not fields to accept from a proof request or derive from an included signature.
The exact snapshot digests in the verification context must equal those pins.

Every approval must have a valid registrar signature and independently scoped
key, match the tenant/deployment/kind/current digest, and be valid at both the
proof's evaluation time and the verifier's current time. Evaluation cannot be in
the future. Issuance must name the expected credential issuer; all three trees
must have depth eight. A pinned signature for another supported tree or issuer
is still insufficient for this pilot context.

The result contains authenticated snapshots and the check time. It is not a
transfer authorization, proof-validity result or revocation result. The eventual
current-verification service must bind these roots to the actual proof signals
and credential, load current enrollment/revocation, independently evaluate the
policy and valuation, and coordinate head reads with the transaction that
consumes an authorization. That service integration remains open. This function
has no database, network, state-changing or fund-movement operation.

Tests use real ephemeral Ed25519 signatures. They cover all three approved roots,
wrong tenant/deployment/profile, unsupported tree depth, a different issuer that
the signing authority is also allowed to approve, stale current pins, changed
context digests and distinct evaluation/current validity boundaries. These are
local trust checks, not live oracle or provider evidence.
