import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', '.next/**'],
    pool: 'threads',
    fileParallelism: false,
  },
});
