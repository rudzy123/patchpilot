import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('integration tests generate the Prisma client once before any package task imports it', () => {
  const rootPackage = JSON.parse(readFileSync(path.join(rootDirectory, 'package.json'), 'utf8'));
  const databasePackage = JSON.parse(
    readFileSync(path.join(rootDirectory, 'packages', 'database', 'package.json'), 'utf8'),
  );
  const turbo = JSON.parse(readFileSync(path.join(rootDirectory, 'turbo.json'), 'utf8'));
  const workflow = readFileSync(
    path.join(rootDirectory, '.github', 'workflows', 'integration.yml'),
    'utf8',
  );

  for (const scriptName of ['test:integration', 'test:integration:serial']) {
    const script = rootPackage.scripts[scriptName];
    const generateAt = script.indexOf('pnpm db:generate');
    const turboAt = script.indexOf('turbo run test:integration');

    assert.ok(generateAt >= 0, scriptName);
    assert.ok(turboAt > generateAt, scriptName);
  }

  assert.equal(
    databasePackage.scripts['test:integration'],
    'vitest run --config vitest.integration.config.ts',
  );
  assert.equal(databasePackage.scripts.generate, 'prisma generate');
  assert.equal(databasePackage.scripts.build, 'prisma generate && tsc -p tsconfig.build.json');
  assert.deepEqual(turbo.tasks['test:integration'].dependsOn, [
    '^build',
    '@patchpilot/database#build',
  ]);

  const generateStep = workflow.indexOf('pnpm db:generate');
  const integrationStep = workflow.indexOf('pnpm test:integration');
  const browserStep = workflow.indexOf('pnpm exec playwright install --with-deps chromium');
  const smokeStep = workflow.indexOf('pnpm test:e2e');

  assert.ok(generateStep >= 0);
  assert.ok(integrationStep > generateStep);
  assert.ok(browserStep > integrationStep);
  assert.ok(smokeStep > browserStep);
});
