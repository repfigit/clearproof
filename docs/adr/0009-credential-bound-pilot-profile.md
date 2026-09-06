# ADR 0009: Bind the exact credential in pilot-transfer-v2

Status: development implementation; current authorization remains incomplete.

The v1 composed circuit proved possession of an issued credential for the
transfer's tenant, wallet and jurisdiction. Its public transfer commitment did
not identify that credential. If two credentials for the same wallet were in the
same approved tree, an external verifier could not tie its specific retained
credential/revocation lookup to the credential used by the proof.

The new `pilot-transfer-v2` profile retains the eight public signal positions,
but changes `projection_commitment` to:

```
Poseidon(204, transfer_projection_commitment, credential_commitment, issuance_root)
```

The former transfer projection becomes a constrained private input. The circuit
checks its original 48 fields and constrains the outer commitment to the same
credential and issuance root used in credential membership verification. Python
`credential_bound_projection` mirrors the composition. A current verifier must
compute this value from the authenticated transfer/context, its exact durable
credential and independently verified issuance root. Neither a prover's claimed
credential nor its supplied public commitment is an independent expectation.

The authorized-issuer and sanctions roots, nullifier, times and deployment remain
in their original positions. Nullifier derivation is unchanged: replacing a
credential or artifact must not grant a second spend for the same holder and
transfer authorization scope. There is no new public raw credential field, but
the commitment remains subject to the privacy limits of the surrounding inputs.

New artifact generation explicitly selects v2 and requires fresh matching
R1CS/WASM/proving and verification keys. Existing manifests that omitted their
profile still default to v1, preserving their original digest. Read-only artifact
and pairing inspection support explicitly pinned v1 files and report the actual
profile. Current artifact-context and pilot-root checking accept only v2. Old
keys are not relabeled and no development keys are committed or approved for
production. The policy structural schema is unchanged.

Adversarial tests construct two valid credentials with the same wallet, holder,
issuer, jurisdiction and issuance/aggregate roots. Either credential produces a
valid witness with its own v2 commitment; substituting it while retaining the
other public commitment fails circuit constraints. Real pairing also rejects the
original proof with the alternate credential's public commitment.

This resolves exact-credential statement binding. It does not complete API/SDK/
contract current-verifier parity, independent current trust selection, atomic
revocation/consumption, or the complete encrypted historical pilot workflow.
