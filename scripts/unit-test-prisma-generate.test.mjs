import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('unit tests generate the Prisma client before package tests import it', () => {
  const rootPackage = JSON.parse(readFileSync(path.join(rootDirectory, 'package.json'), 'utf8'));
  const databasePackage = JSON.parse(
    readFileSync(path.join(rootDirectory, 'packages', 'database', 'package.json'), 'utf8'),
  );
  const turbo = JSON.parse(readFileSync(path.join(rootDirectory, 'turbo.json'), 'utf8'));
  const unitTestScript = rootPackage.scripts['test:unit'];
  const generateAt = unitTestScript.indexOf('pnpm db:generate');
  const turboAt = unitTestScript.indexOf('turbo run test:unit');

  assert.ok(generateAt >= 0);
  assert.ok(turboAt > generateAt);
  assert.equal(databasePackage.scripts['test:unit'], 'vitest run --config vitest.config.ts');
  assert.equal(databasePackage.scripts.generate, 'prisma generate');
  assert.deepEqual(turbo.tasks['test:unit'].dependsOn, ['^build', '@patchpilot/database#build']);
});
