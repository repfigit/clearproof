# Test Vectors

Committed, versioned cryptographic test vectors. These anchor the
**off-chain ≡ on-chain verifier parity** guarantee: the same proof must
verify in both environments.

## `compliance/`

A Groth16 proof for the `compliance` circuit with a fixed, deterministic
input (tier-2 US transfer, sanctions non-membership, valid credential):

| File | Content |
|------|---------|
| `input.json` | Full circuit input (public + private signals) |
| `proof.json` | snarkjs Groth16 proof (`pi_a`, `pi_b`, `pi_c`) |
| `public.json` | 16 public signals (see README "Public Signals") |
| `verification_key.json` | Verification key for the dev trusted setup |
| `MANIFEST.json` | Artifact hashes + toolchain provenance |

Consumed by:

- **Off-chain**: `packages/proof/test/parity.test.ts` (snarkjs verify + tamper cases)
- **On-chain**: `packages/contracts/test/Verifier.test.ts` (`Groth16Verifier.verifyProof`)

## Regenerating

snarkjs mixes OS randomness into every `zkey contribute` even when `-e` is
passed, so dev keys are **never byte-reproducible**. The vector,
`packages/contracts/contracts/Groth16Verifier.sol`, and the local
`artifacts/` directory therefore form one key set and **must be regenerated
and committed together** whenever `circuits/` or the proving toolchain
changes:

```bash
npm install
bash scripts/compile_circuits.sh   # downloads pinned Hermez ptau, fresh dev zkey
cd packages/content && npx tsc && cd ../proof && npx tsc && cd ../cli && npx tsc && cd ../..
node packages/cli/dist/index.js demo --export tests/vectors/compliance
```

CI enforces consistency: the `circuits` job smoke-tests proof generation from
a fresh build, `hardhat-tests` verifies the committed vector against the
committed verifier contract, and the TypeScript job verifies the same vector
off-chain against the committed verification key. A PR that changes one half
of the key set without the other fails these checks.

> ⚠️ These keys come from a **single-party dev trusted setup**. They are
> insecure by construction and exist for testing only. Production keys come
> from the MPC ceremony — see `docs/internal/CEREMONY_RUNBOOK.md`.
