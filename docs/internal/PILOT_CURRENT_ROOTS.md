# Current pilot root verification

`src.prover.pilot_roots.verify_pilot_roots` checks the issuance, authorized-issuer
and sanctions approvals required by `pilot-transfer-v3`. Depths come from
`ROOT_TREE_DEPTHS` in `src/registry/pilot_tree.py`: issuance 32, authorized
issuers 20, and sanctions 20. Its `CurrentRootPins` are independently supplied
operator/current-state configuration, not fields to accept from a proof request
or derive from an included signature. The exact snapshot digests in the
verification context must equal those pins.

Every approval must have a valid registrar signature and independently scoped
key, match the tenant/deployment/kind/current digest, and be valid at both the
proof's evaluation time and the verifier's current time. Evaluation cannot be in
the future. Issuance must name the expected credential issuer; each tree must
have the depth fixed for its kind. A pinned signature for another supported tree
or issuer is still insufficient for this pilot context.

The result contains authenticated snapshots and the check time. It is not a
transfer authorization, proof-validity result or revocation result.
`verify_pilot_roots` has no database, network, state-changing or fund-movement
operation, and it does not check revocation or holder membership.

`expected_current_signals` in `src/prover/pilot_current.py` binds those roots
into the eight public signals, together with the credential commitment and the
transfer projection. `ProofInspectionService` loads the unrevoked enrollment and
compares the configured root approvals with the tenant's retained heads before
that reconstruction. `ProofAuthorizationService.authorize` runs that inspection
and an ALLOW decision in the same transaction that consumes the nullifier.
Read-only inspection does not consume an authorization. Pins and trust still
come from the authenticated server, not from the proof request.

Tests use real ephemeral Ed25519 signatures. They cover all three approved roots,
wrong tenant/deployment/profile, unsupported tree depth, a different issuer that
the signing authority is also allowed to approve, stale current pins, changed
context digests and distinct evaluation/current validity boundaries. These are
local trust checks, not live oracle or provider evidence.
