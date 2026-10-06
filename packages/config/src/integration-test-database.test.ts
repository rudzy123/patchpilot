import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { DatabaseCommandSafetyError } from './database-safety.js';
import * as productionConfig from './index.js';
import {
  publishDisposableIntegrationDatabase,
  readDisposableIntegrationDatabaseUrl,
  readIntegrationDatabaseStateFile,
  readIntegrationServerDatabaseUrl,
  rememberIntegrationServerTemplate,
  setIntegrationDatabaseStateFile,
} from './integration-test-database.js';

const KEYS = [
  'PATCHPILOT_INTEGRATION_SERVER_URL',
  'PATCHPILOT_INTEGRATION_DATABASE_URL',
  'PATCHPILOT_INTEGRATION_DATABASE_STATE_FILE',
  'DATABASE_URL',
] as const;

const previous = new Map<string, string | undefined>();

for (const key of KEYS) {
  previous.set(key, process.env[key]);
}

afterEach(() => {
  for (const key of KEYS) {
    const value = previous.get(key);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

describe('integration test database environment', () => {
  it('refuses a missing disposable database and the persistent database', () => {
    delete process.env['PATCHPILOT_INTEGRATION_DATABASE_URL'];
    expect(() => readDisposableIntegrationDatabaseUrl()).toThrow(DatabaseCommandSafetyError);
    expect(() => readDisposableIntegrationDatabaseUrl()).toThrow(/do not fall back/);

    process.env['PATCHPILOT_INTEGRATION_DATABASE_URL'] =
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot';
    expect(() => readDisposableIntegrationDatabaseUrl()).toThrow(/refuse the persistent/);
  });

  it('publishes only a disposable database url', () => {
    const databaseUrl =
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_api_1735689600_abcdef012345';
    publishDisposableIntegrationDatabase(databaseUrl);
    expect(readDisposableIntegrationDatabaseUrl()).toBe(databaseUrl);
    expect(process.env['DATABASE_URL']).toBe(databaseUrl);
    expect(() =>
      publishDisposableIntegrationDatabase(
        'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot',
      ),
    ).toThrow(/refuse the persistent|Refusing to publish/);
  });

  it('keeps the server template distinct from the disposable database url', () => {
    process.env['DATABASE_URL'] = 'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot';
    rememberIntegrationServerTemplate(undefined);
    publishDisposableIntegrationDatabase(
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_worker_1735689600_abcdef012345',
    );
    expect(readIntegrationServerDatabaseUrl(undefined)).toBe(
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot',
    );
  });

  it('requires the cleanup state file', () => {
    delete process.env['PATCHPILOT_INTEGRATION_DATABASE_STATE_FILE'];
    expect(() => readIntegrationDatabaseStateFile()).toThrow(/state file/);
    setIntegrationDatabaseStateFile('/tmp/patchpilot-it-state/database.json');
    expect(readIntegrationDatabaseStateFile()).toBe('/tmp/patchpilot-it-state/database.json');
  });

  it('refuses the lifecycle when the process environment is production', () => {
    const disposable =
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_api_1735689600_abcdef012345';
    const previousNodeEnv = process.env['NODE_ENV'];
    const previousDeployment = process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'];

    try {
      process.env['NODE_ENV'] = 'production';
      process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] = 'test';
      expect(() => publishDisposableIntegrationDatabase(disposable)).toThrow(
        /disabled when PATCHPILOT_DEPLOYMENT_ENVIRONMENT or NODE_ENV is production/,
      );
      expect(() => readDisposableIntegrationDatabaseUrl()).toThrow(DatabaseCommandSafetyError);

      process.env['NODE_ENV'] = 'test';
      process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] = 'production';
      expect(() => readIntegrationServerDatabaseUrl(disposable)).toThrow(
        DatabaseCommandSafetyError,
      );
    } finally {
      restoreEnv('NODE_ENV', previousNodeEnv);
      restoreEnv('PATCHPILOT_DEPLOYMENT_ENVIRONMENT', previousDeployment);
    }
  });

  it('keeps lifecycle helpers off the production config entry and production startup', () => {
    expect('publishDisposableIntegrationDatabase' in productionConfig).toBe(false);
    expect('readDisposableIntegrationDatabaseUrl' in productionConfig).toBe(false);
    expect('readIntegrationServerDatabaseUrl' in productionConfig).toBe(false);
    expect('assertIntegrationTestProcessAllowed' in productionConfig).toBe(false);

    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    const productionFiles = [
      'apps/api/src/server.ts',
      'apps/api/src/app.ts',
      'apps/worker/src/main.ts',
      'packages/database/src/client.ts',
      'packages/database/src/index.ts',
      'packages/database/src/seed/run.ts',
    ];
    for (const relativePath of productionFiles) {
      const source = readFileSync(path.join(repoRoot, relativePath), 'utf8');
      expect(source).not.toContain('@patchpilot/config/integration-test');
      expect(source).not.toContain('publishDisposableIntegrationDatabase');
      expect(source).not.toContain('readDisposableIntegrationDatabaseUrl');
    }
  });
});

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}
