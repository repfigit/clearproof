const path = require("path");

/**
 * @clearproof/circuits: Circom source for the clearproof proof profiles.
 *
 * Source only. This package contains no compiled WASM, proving keys or verification keys:
 * all current keys are development-only, and the production setup path is still an open
 * decision (docs/adr/0004 in the repository). Compile with circom and your own setup.
 *
 *   circom node_modules/@clearproof/circuits/circuits/pilot_compliance.circom \
 *     -l node_modules --r1cs --wasm
 */

const dir = path.join(__dirname, "circuits");

module.exports = {
  /** Directory containing the .circom sources (and MANIFEST.json with source hashes). */
  dir,
  /** Current pilot profile. Public signals are in this exact order. */
  pilot: {
    profile: "pilot-transfer-v3",
    main: path.join(dir, "pilot_compliance.circom"),
    template: "PilotCompliance(32, 20, 20)",
    treeDepths: { issuance: 32, authorizedIssuers: 20, sanctions: 20 },
    publicSignals: [
      "projection_commitment",
      "authorized_issuer_root",
      "sanctions_root",
      "authorization_nullifier",
      "evaluated_at",
      "proof_expires_at",
      "domain_chain_id",
      "domain_registry",
    ],
  },
  /** Legacy 16-signal demo profile. Never valid as current pilot authorization. */
  legacy: {
    profile: "legacy-compliance-16",
    main: path.join(dir, "compliance.circom"),
    template: "ComplianceProof(20, 10)",
    publicSignals: [
      "is_compliant",
      "sar_review_flag",
      "sanctions_tree_root",
      "issuer_tree_root",
      "amount_tier",
      "transfer_timestamp",
      "jurisdiction_code",
      "credential_commitment",
      "tier2_threshold",
      "tier3_threshold",
      "tier4_threshold",
      "domain_chain_id",
      "domain_contract_hash",
      "transfer_id_hash",
      "credential_nullifier",
      "proof_expires_at",
    ],
  },
  /** Circom include path to pass with -l, relative to the directory containing node_modules. */
  includePath: "node_modules",
};
