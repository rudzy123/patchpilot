/**
 * Starts the API for the release smoke after the fixture database exists.
 * Environment assignment stays in this script. The fixture does not read
 * process.env. The worker is not started, and KEV acquisition stays disabled.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testUtilsUrl = new URL('../packages/test-utils/dist/index.js', import.meta.url);
const loadedTestUtils = await import(testUtilsUrl.href);
if (
  typeof loadedTestUtils !== 'object' ||
  loadedTestUtils === null ||
  typeof loadedTestUtils.createFoundationTestEnv !== 'function'
) {
  process.stderr.write('release smoke could not load the foundation test environment\n');
  process.exit(1);
}
const createFoundationTestEnv = loadedTestUtils.createFoundationTestEnv;

const incomingDatabaseUrl = process.env['DATABASE_URL'];
const foundation = createFoundationTestEnv();
if (typeof foundation !== 'object' || foundation === null) {
  process.stderr.write('release smoke foundation environment was empty\n');
  process.exit(1);
}
for (const [key, value] of Object.entries(foundation)) {
  if (typeof value === 'string' && process.env[key] === undefined) {
    process.env[key] = value;
  }
}
process.env['INTELLIGENCE_KEV_ENABLED'] = 'false';
process.env['INTELLIGENCE_OSV_ENABLED'] = 'false';
if (incomingDatabaseUrl !== undefined && incomingDatabaseUrl.length > 0) {
  process.env['DATABASE_URL'] = incomingDatabaseUrl;
}

const prepared = spawnSync(
  'pnpm',
  [
    '--filter',
    '@patchpilot/api',
    'exec',
    'tsx',
    '../../packages/database/src/release-smoke-fixture.ts',
    'prepare',
  ],
  {
    cwd: root,
    stdio: 'inherit',
    env: process.env,
  },
);
if (prepared.status !== 0) {
  process.exit(prepared.status ?? 1);
}

const statePath = path.join(root, 'apps/web/e2e/.state.json');
const state = JSON.parse(readFileSync(statePath, 'utf8'));
if (typeof state.databaseUrl !== 'string' || state.databaseUrl.length === 0) {
  process.stderr.write('release smoke fixture did not record a database\n');
  process.exit(1);
}
process.env['DATABASE_URL'] = state.databaseUrl;

const serverEntry = path.join(root, 'apps/api/src/server.ts');
await import(pathToFileURL(serverEntry).href);
