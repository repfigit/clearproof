import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/scripts/**/*.test.mjs'],
    coverage: {
      include: ['scripts/*.js', 'scripts/*.mjs'],
      reportsDirectory: 'coverage/scripts',
      reporter: ['text', 'json', 'json-summary', 'lcov'],
      thresholds: {
        'scripts/check_eip2537.mjs': { statements: 100, branches: 100, functions: 100, lines: 100 },
        'scripts/generate_verifier*.mjs': { statements: 100, branches: 100, functions: 100, lines: 100 },
      },
    },
  },
});
