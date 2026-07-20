# Production Trusted Setup Ceremony Runbook

**Status:** Planned — prerequisite for any production deployment (see ROADMAP "Security assurance").
**Scope:** Phase 2 (circuit-specific) MPC ceremony for the `compliance` circuit. Phase 1 reuses the audited Hermez/iden3 perpetual powers-of-tau (sha256-pinned in `scripts/compile_circuits.sh`), which is already an MPC artifact with hundreds of independent contributions — do NOT regenerate it.
**Companion docs:** `CIRCUIT_TRUSTED_SETUP.md` (background), `../adr/0001-groth16-verifier-licensing.md` (must be resolved before the verifier is regenerated here).

---

## 1. Security Model

Groth16 requires a circuit-specific structured reference string. If **all** ceremony participants collude (or are compromised), they can forge proofs. If **at least one** participant honestly destroys their toxic waste, the setup is sound. The ceremony is therefore designed to make single-party honesty sufficient and collusion impractical:

- ≥ 5 independent contributors from different organizations, jurisdictions, and infrastructure providers
- Sequential contribution chain (each builds on the previous zkey)
- Public, signed attestations so the transcript is auditable forever
- Coordinator orchestrates but is just one contributor; coordinator compromise alone does not break soundness

## 2. Roles

| Role | Responsibility |
|------|----------------|
| **Coordinator** | Sequences contributions, verifies each zkey before passing it on, publishes the transcript. One clearproof maintainer + one independent observer. |
| **Contributors** | Generate entropy on their own hardware, contribute, attest, destroy toxic waste. Target: 5–8 (auditors, partner VASPs, ecosystem orgs, academic ZK labs). |
| **Observers** | Reproduce every verification step independently and countersign the transcript. |

## 3. Pre-Ceremony Checklist

- [ ] Circuit code frozen and tagged (`circuits/` + `circomlib` version pinned); R1CS hash published
- [ ] Toolchain pinned and published: circom version, snarkjs version, ptau URL + sha256
- [ ] ADR 0001 (verifier licensing) decision recorded — the verifier generated in §6 ships its license
- [ ] Contributor instructions sent; each contributor confirms hardware/OS and air-gap/entropy plan
- [ ] Transcript repository (public git repo) initialized: `ceremony/compliance-phase2/`

## 4. Contribution Protocol (per contributor *i*)

Coordinator starts with:

```bash
circom circuits/compliance.circom --r1cs --wasm --sym -l node_modules -o build
snarkjs groth16 setup build/compliance.r1cs artifacts/pot18_final.ptau compliance_0000.zkey
sha256sum compliance_0000.zkey   # recorded in transcript
```

Then, sequentially, contributor *i* receives `compliance_{i-1}.zkey`:

```bash
# 1. Verify the previous state (must match the coordinator's published hash)
sha256sum compliance_{i-1}.zkey
snarkjs zkey verify build/compliance.r1cs artifacts/pot18_final.ptau compliance_{i-1}.zkey

# 2. Contribute — entropy generated locally, never transmitted, destroyed after
snarkjs zkey contribute compliance_{i-1}.zkey compliance_{i}.zkey \
    --name="<org> contribution <date>" \
    -e="<locally generated entropy>"
# (alternatively omit -e and paste entropy interactively)

# 3. Record the contribution hash printed by snarkjs, hash the output
sha256sum compliance_{i}.zkey

# 4. Produce attestation (template in §5), sign with the org's published key

# 5. Send compliance_{i}.zkey + attestation to the coordinator
# 6. Securely delete local entropy (and compliance_{i}.zkey after coordinator confirms)
```

The coordinator verifies each incoming zkey (`zkey verify` + contribution hash) **before** handing it to the next contributor, and commits every artifact hash + attestation to the transcript repo.

## 5. Attestation Template

Each contributor publishes a signed statement (e.g., GPG-clearsigned markdown) in the transcript repo:

```markdown
# Contribution Attestation — compliance phase 2

- Contributor: <legal org name>, <contact>
- Contribution index: <i>
- Date (UTC): <ISO-8601>
- Input zkey sha256:  <hash of compliance_{i-1}.zkey>
- Output zkey sha256: <hash of compliance_{i}.zkey>
- snarkjs contribution hash: <hash printed by zkey contribute>
- Toolchain: circom <ver>, snarkjs <ver>, ptau powersOfTau28_hez_final_18
- Environment: <OS/hardware>, entropy source: <e.g., /dev/urandom + keyboard + dice>
- Statement: "I generated my entropy independently, contributed exactly once,
  did not share it with any party, and securely destroyed it and all local
  copies of intermediate artifacts after the coordinator confirmed receipt."
- Signature: <GPG/clearsign block, key published in advance>
```

## 6. Finalization

After the last contribution:

```bash
# Apply a final public randomness beacon (e.g., a future block hash of a
# major chain, announced in advance) so even the coordinator cannot bias
# the final key:
snarkjs zkey beacon compliance_N.zkey compliance_final.zkey \
    <beacon-hash-hex> 10 --name="Final beacon"

# Verify the whole chain
snarkjs zkey verify build/compliance.r1cs artifacts/pot18_final.ptau compliance_final.zkey

# Export production artifacts
snarkjs zkey export verificationkey compliance_final.zkey verification_key.json
snarkjs zkey export solidityverifier compliance_final.zkey Groth16Verifier.sol  # see ADR 0001
```

Then:

- [ ] Publish `compliance_final.zkey` hash + full transcript + attestations
- [ ] Tag the repo; commit production `verification_key.json` and verifier contract (per repo policy: production artifacts only from documented ceremony)
- [ ] Update README Assurance Status (trusted setup: dev → MPC ceremony, link transcript)
- [ ] Regenerate `tests/vectors/compliance/` against the new key and bump the dev/prod key split (dev vector stays on dev keys; add a production-vkey parity vector)
- [ ] Schedule independent third-party verification of the transcript (one audit-firm pass)

## 7. Abort/Restart Conditions

- Any `zkey verify` failure → halt, publish findings, restart from the last good zkey
- Contributor dropout > 72h without handoff → skip and re-sequence; document in transcript
- Any evidence of entropy reuse or coordinator deviation → full restart with a new coordinator

## 8. Timeline Estimate

| Phase | Duration |
|-------|----------|
| Contributor recruitment + scheduling | 2–4 weeks |
| Sequential contributions (5–8 parties) | 1–2 weeks |
| Beacon + finalization + verification | 2–3 days |
| Transcript publication + third-party review | 1 week |
