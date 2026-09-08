import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/scripts/**/*.test.mjs'],
    coverage: {
      include: ['scripts/*.js', 'scripts/*.mjs'],
      reportsDirectory: 'coverage/scripts',
      reporter: ['text', 'json', 'json-summary', 'lcov'],
      thresholds: {
        perFile: true,
        statements: 100, branches: 100, functions: 100, lines: 100,
      },
    },
  },
});
