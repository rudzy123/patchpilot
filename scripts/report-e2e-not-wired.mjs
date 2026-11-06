#!/usr/bin/env node

process.stdout.write(
  [
    'The release smoke is pnpm test:e2e.',
    'It runs the one Playwright Chromium journey in apps/web/e2e/release-smoke.spec.ts.',
    'See docs/development/testing.md.',
    '',
  ].join('\n'),
);
