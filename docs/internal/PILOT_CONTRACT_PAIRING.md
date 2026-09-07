# Development pilot contract pairing

`PilotGroth16Verifier` is a separate eight-public-signal verifier for
`pilot-transfer-v2`. It reuses the repository's MIT-licensed BN254 `Pairing`
library and the same Groth16 equation as the Apache-2.0 legacy verifier. The
sixteen-signal legacy contract and generated key constants are unchanged.

The constructor takes a verification key and an artifact manifest digest. It
checks nonzero key points, canonical coordinates, G1 curve membership and G2
precompile acceptance. It stores the key once, exposes the keccak256 ABI encoding
commitment as `verificationKeyCommitment`, and records `artifactManifestDigest`.
No setter or upgrade function can replace the key. Its assurance is explicitly
`development-unapproved`; a successful deployment does not approve a key or setup.

Key/proof G2 coordinate pairs use EVM precompile order, reversed relative to the
snarkjs verification-key/proof JSON representation. Each public signal must be a
canonical scalar below the BN254 scalar modulus. Proof coordinates must be below
the base-field modulus before point negation, preventing a noncanonical Y value
from being reduced silently. The ABI accepts exactly eight signals. Well-encoded
failed pairings return false; malformed curve encodings can revert. Both are
rejection outcomes.

The manifest digest is operator metadata, not an on-chain verification of a JSON
manifest, key file hash or setup ceremony. A deployment must independently inspect
the approved artifacts, derive the exact key encoding, and compare the deployed
key commitment. The development tests check local manifest/key file consistency
and the context's manifest pin. Their local pin is reproducibility material and
not an independent production authority.

Run the real development pairing gate against an existing isolated bundle:

```bash
CLEARPROOF_PILOT_TEST_ARTIFACTS=/absolute/path/to/pilot npm test --workspace=@clearproof/contracts -- --network hardhat --grep PilotGroth16Verifier
```

The same `proof.json` and `public.json` are used by the Python current-statement
gate and the EVM test. The EVM test also compares snarkjs on the valid proof,
every single-signal mutation and a changed valid curve point; it tests malformed
coordinates, scalar aliases, legacy ABI length, malformed key points and changed
key commitments. An explicitly configured missing or incompatible bundle fails.
Without the environment variable, these artifact-dependent tests are pending;
the isolated development builder enables the gate after generating fresh proofs.
No development key or generated verifier is copied into tracked source.

This is cryptographic pairing parity, not complete current authorization parity.
The contract does not reconstruct a transfer projection, authenticate policy or
valuation approvals, read current enrollment/revocation/root/policy state, enforce
proof expiry or deployment audience, or consume a nullifier. Those constraints
remain in the Python current inspection/authorization services until the scoped
contract integration is implemented and tested against shared adversarial cases.
Repeated view calls can succeed for the same proof and do not authorize execution.
The eight-signal layout exposes no separate SAR decision signal.
