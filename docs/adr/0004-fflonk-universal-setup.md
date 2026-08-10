# ADR 0004: fflonk universal setup — revisiting the ceremony blocker

## Status

Proposed (2026-07-31)

Supersedes the go/no-go framing of [ADR 0003](0003-proof-system.md) but not its conclusion about Noir/UltraHonk, which stands.

## Context

The per-circuit Groth16 MPC ceremony is the project's #1 stated production blocker (ROADMAP Phase 3). ADR 0003 evaluated one escape route — Noir/UltraHonk — and rejected it on gas: 4.4–8.8× the Groth16 baseline, against a stated threshold of ≤2×.

ADR 0003 did not evaluate **fflonk**. That omission matters, because fflonk is the only candidate that eliminates the per-circuit ceremony *without changing anything else*: same Circom source, same R1CS, same BN254 curve, same snarkjs toolchain, same 16-signal interface, same audit surface. There is no circuit rewrite and no new proving stack to learn or audit.

Two things prompted revisiting this now:

1. **The ceremony is not a one-time cost, and ADR 0003's mitigation assumes it is.** ADR 0003 mitigation #3 says "design the circuit to accommodate foreseeable compliance rule changes without structural changes that would require re-compilation." Self Protocol runs this exact stack (Circom / Groth16 / Hermez ptau) for sanctions and nationality checks and has grown to **253 `.circom` files, 83 instance circuits and 87 Solidity verifiers**. Compliance logic is jurisdiction-shaped and it multiplies. The assumption that one ceremony can cover foreseeable change is not supported by the closest available comparable.

2. **A dated regulatory change is already scheduled.** AMLR Art. 40(2)(b) requires AMLA to issue guidelines on verifying self-hosted address ownership **by 10 July 2027**. Committing to a ceremony for logic with a known expiry date is a poor trade.

Full measurements: [`docs/internal/FFLONK_BENCHMARK.md`](../internal/FFLONK_BENCHMARK.md).

## Decision

**No decision yet — this ADR is Proposed, not Accepted.** The benchmark resolves the question ADR 0003 was designed to answer, and inverts its expected direction, but it surfaces a new binding constraint that is a product call rather than an engineering one.

### The gas question is settled, in fflonk's favour

| System | `verifyProof` gas | Ratio to Groth16 | Ceremony |
|---|---:|---:|---|
| Groth16 BN254 (baseline) | 341,467 | 1.00× | **Per circuit** |
| Groth16 BLS12-381 (ADR 0002) | 363,588 | 1.06× | **Per circuit** |
| **fflonk BN254** | **232,646** | **0.68×** | **None** |
| Noir/UltraHonk (ADR 0003 estimate) | 1.5–3.0 M | 4.4–8.8× | None |

fflonk verification is **32% cheaper than Groth16**, not more expensive. ADR 0003's ≤2× threshold is met with enormous margin.

The reason is specific to us and worth recording: Groth16's verifier cost scales with public-input count (~one `ecMul` + `ecAdd` per signal), and clearproof has an unusually wide 16-signal interface. Roughly a third of the Groth16 verifier's gas is public-input accumulation. fflonk's cost does not scale the same way. **Our signal design is what makes fflonk win — this result would not transfer to a narrow-interface circuit.**

### The new binding constraint is proving time

| | Groth16 | fflonk |
|---|---:|---:|
| Proving (mean of 3) | 1.83 s | **37.44 s** (20.5×) |
| Peak RSS | 1.21 GB | 5.79 GB (4.8×) |

And the gap is understated: **Groth16 has a production native prover (rapidsnark, typically 10–50× faster than snarkjs); fflonk has none.** A realistic production Groth16 deployment could be sub-second where fflonk stays in the tens of seconds.

### The second real cost is licensing

`snarkjs zkey export solidityverifier` emits a **GPL-3.0** fflonk verifier. ADR 0001 deliberately replaced the GPL Groth16 template with our own Apache-2.0 implementation so the licence and patent-grant story works for enterprise adoption. Adopting fflonk reintroduces that problem, and the fix is far more expensive: our Apache Groth16 verifier is ~300 lines; the fflonk template is **1,566 lines** of hand-optimised, Yul-heavy Solidity. Re-implementing it is a security-critical project in its own right, not a port.

## The question this leaves for a human

**Is ~37 s of proof generation per transfer acceptable?**

- If **yes** — fflonk is the better system on every axis we have historically optimised for. It is cheaper on-chain, it deletes the ceremony from the critical path permanently, and it makes regulatory rule changes a recompile rather than a 6–12 month, $100k+ coordination exercise. Proving happens VASP-local and ahead of settlement; Travel Rule is not an interactive sub-second path.
- If **no** — Groth16 stands, the ceremony must be scheduled, and the mitigation in ADR 0003 needs replacing with something more honest than "design for foreseeable change," because the Self Protocol evidence says that does not hold.

Two constraints shape the answer, and neither is cryptographic:

1. **The API shape.** `POST /proof/generate` is request/response. A 37 s synchronous handler is not viable; it would need to become a job queue with polling or callbacks. That is a real but bounded amount of work, and it is arguably needed regardless for a production gateway.
2. **Throughput.** 37 s per proof caps a single prover at ~97 proofs/hour. A pilot VASP will not notice. A mid-size exchange would need horizontal proving capacity, and at 5.8 GB peak RSS per proof that is a meaningful hardware bill.

## Recommendation

**Do not schedule the MPC ceremony yet.** The benchmark has removed the reason to believe the ceremony is unavoidable, and a ceremony is the single most expensive, least reversible item on the roadmap. Deciding it before the proving-latency question is answered would be committing in the wrong order.

Concretely, in priority order:

1. **Answer the latency question** with the product owner. It is the only real blocker to a decision.
2. **Measure L2 gas before committing either way.** fflonk's proof is 3× larger in calldata (768 B vs 256 B), and on L2s calldata dominates. This could reverse the gas conclusion for an L2-first deployment. Currently unmeasured.
3. **If fflonk is chosen**, budget the Apache-2.0 fflonk verifier re-implementation as a first-class project with its own audit, and re-pin CI to `powersOfTau28_hez_final_19.ptau` (2^18 is silently insufficient — see the benchmark).
4. **Adopt a versioned verifier registry regardless of the outcome.** A router mapping `(scheme, jurisdiction) → vkey` behind a timelock, with a kill switch, makes any future proof-system or rule change a governed configuration change rather than a redeploy that strands every proof bound to the retired `domain_contract_hash`. RISC Zero's [version-management-design](https://github.com/risc0/risc0-ethereum/blob/main/contracts/version-management-design.md) is the reference implementation. **This is worth doing on its own merits and is not contingent on the fflonk decision.**

## Consequences

### If fflonk is adopted

- No per-circuit ceremony, ever. Circuit changes become a recompile.
- 32% cheaper on-chain verification.
- 20× slower proving; `/proof/generate` must become asynchronous.
- A GPL-3.0 verifier must be re-implemented under Apache-2.0 (~1,566 lines, security-critical) or the ADR 0001 licensing position must be revisited.
- CI ptau re-pinned to 2^19 (577 MB).
- ADR 0002 (BLS12-381) interacts and would need re-measuring; the two migrations were evaluated independently.

### If Groth16 is retained

- The ceremony must be scheduled and funded, and it recurs on every circuit change.
- ADR 0003's "design for foreseeable change" mitigation should be replaced with an explicit budget for repeat ceremonies, or an explicit acceptance that jurisdiction-specific logic will live off-circuit.
- The 16-signal interface is leaving ~110k gas per verification on the table, which is worth revisiting independently.

## References

- [`docs/internal/FFLONK_BENCHMARK.md`](../internal/FFLONK_BENCHMARK.md) — full measurements and reproduction steps
- [ADR 0001](0001-groth16-verifier-licensing.md) — why the verifier is Apache-2.0 and not the GPL snarkjs template
- [ADR 0002](0002-bls12381-migration.md) — BLS12-381 migration, unmeasured in combination with this
- [ADR 0003](0003-proof-system.md) — Noir/UltraHonk evaluation; its conclusion stands, its framing is superseded
- AIF-86 (this spike), AIF-89 (parity vector regeneration — blocked on this decision)
