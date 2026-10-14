import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('instance advisory authority command script is an explicit dist entrypoint', () => {
  const source = readFileSync(
    path.join(rootDirectory, 'scripts/run-instance-advisory-authority.mjs'),
    'utf8',
  );
  assert.match(source, /packages\/database\/dist\/instance-advisory-authority-command-main\.js/);
  assert.doesNotMatch(source, /apps\/api/);
  assert.doesNotMatch(source, /apps\/web/);
  assert.doesNotMatch(source, /apps\/worker/);
  assert.doesNotMatch(source, /postgresql:\/\//);
  const packageJson = JSON.parse(readFileSync(path.join(rootDirectory, 'package.json'), 'utf8'));
  assert.equal(
    packageJson.scripts['instance-advisory-authority'],
    'node scripts/run-instance-advisory-authority.mjs',
  );
  for (const name of ['dev', 'build', 'test', 'test:unit', 'test:integration', 'postinstall']) {
    assert.equal(
      String(packageJson.scripts[name] ?? '').includes('instance-advisory-authority'),
      false,
    );
  }
});
