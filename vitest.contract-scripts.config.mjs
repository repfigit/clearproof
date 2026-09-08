import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
const contractRequire = createRequire(new URL('./packages/contracts/package.json', import.meta.url));

export default defineConfig({
  resolve: { alias: { ethers: contractRequire.resolve('ethers') } },
  test: {
    include: ['tests/contract-scripts/**/*.test.ts'],
    coverage: {
      include: ['packages/contracts/scripts/*.ts'],
      reportsDirectory: 'coverage/contract-scripts',
      reporter: ['text', 'json', 'json-summary', 'lcov'],
      thresholds: {
        perFile: true,
        statements: 100, branches: 100, functions: 100, lines: 100,
      },
    },
  },
});
