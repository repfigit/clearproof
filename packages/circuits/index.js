const path = require("path");

/**
 * @clearproof/circuits — ZK compliance circuit artifacts
 *
 * Usage:
 *   const { artifacts, circuitSrc } = require("@clearproof/circuits");
 *   // artifacts.wasmPath — compiled circuit WASM
 *   // artifacts.zkeyPath — Groth16 proving key
 *   // artifacts.vkeyPath — verification key JSON
 *   // circuitSrc.compliance — path to compliance.circom
 *
 * To use circuits in your own Circom project:
 *   circom my-circuit.circom -l node_modules/@clearproof/circuits/src -l node_modules/circomlib/circuits
 */

const artifactsDir = path.join(__dirname, "artifacts");
const srcDir = path.join(__dirname, "src");

module.exports = {
  artifacts: {
    wasmPath: path.join(artifactsDir, "compliance.wasm"),
    zkeyPath: path.join(artifactsDir, "compliance_final.zkey"),
    vkeyPath: path.join(artifactsDir, "verification_key.json"),
    dir: artifactsDir,
  },
  circuitSrc: {
    compliance: path.join(srcDir, "compliance.circom"),
    sanctionsNonmembership: path.join(srcDir, "sanctions_nonmembership.circom"),
    credentialValidity: path.join(srcDir, "credential_validity.circom"),
    amountTier: path.join(srcDir, "amount_tier.circom"),
    dir: srcDir,
  },
  /** Number of public signals in the compliance circuit */
  PUBLIC_SIGNAL_COUNT: 15,
  /** Public signal indices */
  signals: {
    IS_COMPLIANT: 0,
    SAR_REVIEW_FLAG: 1,
    SANCTIONS_TREE_ROOT: 2,
    ISSUER_TREE_ROOT: 3,
    AMOUNT_TIER: 4,
    TRANSFER_TIMESTAMP: 5,
    JURISDICTION_CODE: 6,
    CREDENTIAL_COMMITMENT: 7,
    TIER2_THRESHOLD: 8,
    TIER3_THRESHOLD: 9,
    TIER4_THRESHOLD: 10,
    DOMAIN_CHAIN_ID: 11,
    DOMAIN_CONTRACT_HASH: 12,
    TRANSFER_ID_HASH: 13,
    CREDENTIAL_NULLIFIER: 14,
  },
};
