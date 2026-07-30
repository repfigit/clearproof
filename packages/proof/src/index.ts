export { generateProof } from './prover.js';
export { verifyProof } from './verifier.js';
export { discoverVASP, supportsChain, clearDiscoveryCache } from './discovery.js';
export {
  JURISDICTION_THRESHOLDS,
  DEFAULT_THRESHOLDS,
  getThresholds,
  decodeJurisdiction,
  thresholdsMatchJurisdiction,
} from './thresholds.js';
export type { Thresholds } from './thresholds.js';
export type { ComplianceInput, ProofResult, VerifyResult } from './types.js';
export type { ClearproofDiscoveryInfo, DiscoveryOptions } from './discovery.js';
