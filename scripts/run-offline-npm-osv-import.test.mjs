import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('offline npm OSV import script is an explicit dist entrypoint', () => {
  const source = readFileSync(
    path.join(rootDirectory, 'scripts/run-offline-npm-osv-import.mjs'),
    'utf8',
  );
  assert.match(source, /packages\/database\/dist\/offline-npm-osv-import-command-main\.js/);
  assert.match(source, /offline_npm_osv_import_not_built/);
  assert.doesNotMatch(source, /apps\/api/);
  assert.doesNotMatch(source, /apps\/web/);
  assert.doesNotMatch(source, /apps\/worker/);
  assert.doesNotMatch(source, /postgresql:\/\//);
  assert.doesNotMatch(source, /INTELLIGENCE_OSV_ENABLED/);
  const packageJson = JSON.parse(readFileSync(path.join(rootDirectory, 'package.json'), 'utf8'));
  assert.equal(
    packageJson.scripts['offline-npm-osv-import'],
    'node scripts/run-offline-npm-osv-import.mjs',
  );
  for (const name of ['dev', 'build', 'test', 'test:unit', 'test:integration', 'postinstall']) {
    assert.equal(String(packageJson.scripts[name] ?? '').includes('offline-npm-osv-import'), false);
  }
});
