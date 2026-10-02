import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const currentStatePath = 'docs/project/current-state.md';

/**
 * @param {string} relativePath
 * @returns {string}
 */
function readRepositoryFile(relativePath) {
  return readFileSync(path.join(rootDirectory, relativePath), 'utf8');
}

test('current-state document exists and the router and README link to it', () => {
  assert.equal(existsSync(path.join(rootDirectory, currentStatePath)), true);
  assert.match(readRepositoryFile('AGENTS.md'), /docs\/project\/current-state\.md/);
  assert.match(readRepositoryFile('README.md'), /docs\/project\/current-state\.md/);
});

test('current frozen migration count agrees with the registry and migration directories', () => {
  const registry = readRepositoryFile('packages/database/src/integration-database.ts');
  const registryStart = registry.indexOf('export const FROZEN_MIGRATIONS');
  const registryEnd = registry.indexOf('] as const;', registryStart);
  assert.ok(registryStart >= 0 && registryEnd > registryStart);
  const registeredDirectories = [
    ...registry.slice(registryStart, registryEnd).matchAll(/directory:\s*'([^']+)'/g),
  ].map((match) => match[1]);
  const migrationRoot = path.join(rootDirectory, 'packages/database/prisma/migrations');
  const directoriesOnDisk = readdirSync(migrationRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => existsSync(path.join(migrationRoot, name, 'migration.sql')))
    .sort();

  assert.deepEqual([...registeredDirectories].sort(), directoriesOnDisk);
  assert.match(readRepositoryFile(currentStatePath), /Frozen migrations:\s*19\b/);
  assert.equal(registeredDirectories.length, 19);
});

test('checkpoint documents do not enable production OSV, Findings, or real product eligibility', () => {
  const currentState = readRepositoryFile(currentStatePath);
  const readme = readRepositoryFile('README.md');
  const agents = readRepositoryFile('AGENTS.md');

  assert.match(currentState, /Production OSV acquisition:\s*disabled/);
  assert.match(currentState, /Finding creation from match evidence:\s*unavailable/);
  assert.match(currentState, /Real product-eligible evaluation count:\s*0\b/);

  for (const text of [currentState, readme, agents]) {
    assert.doesNotMatch(text, /Production OSV acquisition:\s*enabled/);
    assert.doesNotMatch(text, /Finding creation from match evidence:\s*operational/);
    assert.doesNotMatch(text, /Real product-eligible evaluation count:\s*[1-9]/);
    assert.doesNotMatch(text, /INTELLIGENCE_OSV_ENABLED=true`?\s+is accepted/);
  }
});
