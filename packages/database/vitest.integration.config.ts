import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.integration.test.ts'],
    pool: 'threads',
    fileParallelism: false,
    testTimeout: 30_000,
  },
});
