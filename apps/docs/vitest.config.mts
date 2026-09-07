import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      // Authored TS/TSX unit coverage; MDX rendering/browser checks are separate.
      include: ['app/**/*.ts', 'app/**/*.tsx', 'mdx-components.tsx'],
      exclude: ['**/*.d.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      thresholds: { statements: 100, branches: 100, functions: 100, lines: 100 },
    },
  },
});
