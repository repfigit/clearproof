# ADR 0004: Versioned legacy verifier registry

Status: implemented in source; deployment and key approval remain separate.
Scope: 16-signal legacy Groth16 interface, not `pilot-transfer-v3` authorization.

Previously, changing the direct immutable verifier required a new registry and
stranded proofs bound to its address. The legacy registry now pins an immutable
router, retaining its own address, records and replay protection across compatible
verifier changes. The router binds each scheme/version selector to one permanent
address and runtime hash. Pending and retired bindings cannot be overwritten.

Registration, default selection and retirement each require the appropriate
administrator and a real positive timelock. Delay changes themselves are delayed
and cannot cross the deployment's immutable floor. An emergency role can disable
one verifier immediately or pause all routing; recovery cannot reactivate a
disabled binding or bypass default-selection delays.

Default selection and router retirement each grant a bounded, inclusive 24-hour
window to older statements. Only actual former registry defaults can use the
explicit-selector submission path; it retains the complete normal acceptance
checks and shares records/nullifiers with the default path. The earlier applicable
grace deadline and existing proof expiry apply. Declared transfer timestamps must
precede cutover/retirement; they do not attest proof-creation time.

`domain_contract_hash` continues to commit to the **ComplianceRegistry address**,
using packed-address keccak reduced modulo BN254's scalar field. It never commits
to the router or verifier. Adversarial tests cover wrong chain, router-address
substitution and transfer mismatch through both submission paths. Fresh
unapproved-artifact E2E exercises actual pairing before and after a delayed swap,
retirement grace, tampered-statement rejection and retained records.

This is a compatible Groth16 rotation facility, not an arbitrary proof-system
ABI dispatcher. A different proof system requires a reviewed adapter/router and
its own domain/profile analysis. Old deployed immutable contracts cannot be
upgraded by changing source. The historical Sepolia record contains no router;
a one-time reviewed migration is required before subsequent swaps retain state.

See [the decommissioning runbook](../VERIFIER_DECOMMISSIONING.md) for exact calls,
restart behavior, emergency recovery and historical-address end-state evidence.
The additional lifecycle state and calls add gas and operational complexity.

Reference: [RISC Zero version-management design](https://github.com/risc0/risc0-ethereum/blob/main/contracts/version-management-design.md).
