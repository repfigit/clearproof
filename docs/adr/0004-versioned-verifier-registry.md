# ADR 0004: Versioned Verifier Registry

## Context

The `ComplianceRegistry.verifier` is currently `immutable`, which means that every verifier change forces a new registry deployment. Because the registry address is part of `domain_contract_hash`, each redeploy strands every proof bound to the retired address.

We've already done this once (ADR 0001, the Apache verifier redeploy) and have at least one more coming. This approach:
- Forces VASPs to refresh all in-flight proofs generated against the retired registry
- Incurs downtime during deployment
- Risks losing proofs in-flight during the redeployment window
- Requires updating contract addresses across all systems
- Breaks replay protection during the transition period

## Decision

Introduce a `VerifierRouter` contract that allows verifiers to be swapped without redeploying `ComplianceRegistry`.

### Implementation

1. **VerifierRouter**: A new contract that routes proof verification to registered verifiers
2. **Selector-based routing**: `mapping(bytes32 selector => address verifier)` where the selector identifies the proof system and version
3. **Timelock mechanism**: Registration and retirement of verifiers are timelocked
4. **Emergency kill switch**: Ability to disable a verifier immediately without waiting out the timelock
5. **Grace period**: Retired verifiers remain resolvable but non-default for a documented grace period
6. **ComplianceRegistry modification**: Resolves through the router instead of holding an `immutable` address

### Benefits

- **No downtime**: Verifiers can be swapped without redeploying `ComplianceRegistry`
- **No proof stranding**: In-flight proofs bound to an older verifier remain verifiable
- **Gradual migration**: VASPs can continue using old proofs while generating new ones with the new verifier
- **Reversible decisions**: The decision about which verifier to use can be changed later
- **Enhanced security**: Emergency stop functionality for problematic verifiers

### Requirements

- **Domain binding preservation**: The router must preserve domain binding under the new architecture
- **Adversarial testing**: The domain binding under the router needs thorough adversarial testing
- **Decommissioning runbook**: Retired verifiers need a documented decommissioning path

## Consequences

### Positive

- Verifier changes no longer require `ComplianceRegistry` redeployment
- Swaps are timelocked with an immediate kill switch
- Domain binding under the router is covered by adversarial tests
- Retired verifiers have a documented decommissioning path
- Proofs bound to older verifiers remain verifiable during grace period

### Negative

- Increased contract complexity with the new router layer
- Additional gas costs for verification through the router
- Need for careful management of verifier lifecycle

## Implementation Plan

1. Deploy `VerifierRouter` contract
2. Modify `ComplianceRegistry` to use the router instead of direct verifier reference
3. Add timelock and emergency stop functionality
4. Create decommissioning runbook for retired verifiers
5. Implement adversarial tests for domain binding
6. Update deployment scripts and documentation
7. Batch any deployment with related issues (AIF-79/88/92/95)

## Reference Implementation

RISC Zero's [version-management-design](https://github.com/risc0/risc0-ethereum/blob/main/contracts/version-management-design.md).