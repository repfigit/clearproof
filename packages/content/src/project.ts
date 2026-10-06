/** Public release facts. Update only after publication has been verified. */
export const PROJECT_STATUS = Object.freeze({
  schemaVersion: 1,
  checkedAt: '2026-10-06',
  npmVersion: '0.7.0',
  sourceVersion: '0.7.0',
  proofProfile: 'pilot-transfer-v3',
  stage: 'Development pilot. The workflow runs locally with synthetic data, real proofs, a disposable database and a test chain. No customer deployment is established.',
  assurance: 'Circuits and contracts have not been independently audited. Proving keys are development-only.',
  capacity: 'Circuit capacity: 2^32 credential leaves per issuance root, 2^20 issuer leaves and 2^20 minus two sanctions addresses. The software refresh scans at most 1,024 enrollments across its configured 1–16 issuers, within a 30-second tenant transaction. Encrypted inventories are paged; the measured synthetic root-build median at 1,024 leaves was 16.73 seconds. Production throughput has not been demonstrated.',
});
