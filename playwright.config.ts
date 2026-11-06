import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './apps/web/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  outputDir: 'test-results/playwright',
  globalTeardown: './apps/web/e2e/global-teardown.ts',
  use: {
    baseURL: 'http://127.0.0.1:3000',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'pnpm --filter @patchpilot/api exec tsx ../../scripts/release-smoke-serve.mjs',
      url: 'http://127.0.0.1:3001/health/live',
      reuseExistingServer: false,
      timeout: 180_000,
    },
    {
      command: 'pnpm --filter @patchpilot/web dev',
      url: 'http://127.0.0.1:3000/login',
      reuseExistingServer: false,
      timeout: 180_000,
    },
  ],
});
