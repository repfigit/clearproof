import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      // Include every authored TS/TSX module. Rendering gaps remain visible.
      include: ['app/**/*.ts', 'app/**/*.tsx', 'mdx-components.tsx'],
      exclude: ['**/*.d.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
    },
  },
});
