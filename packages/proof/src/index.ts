export { generateProof } from './prover.js';
export { canonicalBytes, recordDigest } from './canonical.js';
export { verifyProof } from './verifier.js';
export { discoverVASP, supportsChain, clearDiscoveryCache, DiscoveryClient, DiscoveryError, EgressPolicy } from './discovery.js';
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

export { reportEndpoint, requestReport } from './api-client.js';
export type { ReportPath } from './api-client.js';
export { inspectCurrentProof } from './current-inspection.js';
export type { CurrentInspectionRequest, CurrentInspectionReport } from './current-inspection.js';

export { createObservation, readObservation } from './observation.js';
export type { ObservationRequest, ObservationReport, ObservedPolicy } from './observation.js';
