// Noir port of the clearproof compliance circuit
// Mirrors the Circom circuit logic for benchmarking purposes
//
// Subcircuits:
//   - merkle: Poseidon-based Merkle proof verification
//   - sanctions_nonmembership: sorted-tree gap proof
//   - credential_validity: credential commitment + expiry + issuer membership
//   - amount_tier: tier assignment + SAR flag
//   - compliance: main orchestrator

mod merkle;
mod sanctions_nonmembership;
mod credential_validity;
mod amount_tier;
mod compliance;

pub use compliance::ComplianceProof;
pub use compliance::ComplianceInputs;
pub use compliance::ComplianceOutputs;
