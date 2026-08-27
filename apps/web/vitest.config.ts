import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: {
    jsx: {
      runtime: 'automatic',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['**/*.test.ts', '**/*.test.tsx'],
    exclude: ['e2e/**', 'node_modules/**', '.next/**'],
    pool: 'threads',
    fileParallelism: false,
    setupFiles: ['./vitest.setup.ts'],
  },
});
