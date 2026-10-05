/** Public release facts. Update only after publication has been verified. */
export const PROJECT_STATUS = Object.freeze({
  schemaVersion: 1,
  checkedAt: '2026-10-05',
  npmVersion: '0.7.0',
  proofProfile: 'pilot-transfer-v3',
  stage: 'Development pilot. The workflow runs locally with synthetic data, real proofs, a disposable database and a test chain. No customer deployment is established.',
  assurance: 'Circuits and contracts have not been independently audited. Proving keys are development-only.',
  capacity: 'Circuit capacity: 2^32 credential leaves per issuance root, 2^20 issuer leaves and 2^20 minus two sanctions addresses. The current software refresh scans at most 256 enrollments and configures 1–16 issuers; production throughput has not been demonstrated.',
});
