import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/contract-scripts/**/*.test.ts'],
    coverage: {
      include: ['packages/contracts/scripts/*.ts'],
      reportsDirectory: 'coverage/contract-scripts',
      reporter: ['text', 'json', 'json-summary', 'lcov'],
      thresholds: {
        'packages/contracts/scripts/update-sanctions-root.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/redeploy-verifier.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/deploy-verifier-bls.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/deploy.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/deploy-multichain.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/deploy-relay.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/gas-bench.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/check-transfer.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/verify-onchain.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/networks.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'packages/contracts/scripts/legacy-verifier.ts': { statements: 100, branches: 100, functions: 100, lines: 100 },
      },
    },
  },
});
