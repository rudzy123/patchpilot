import { describe, expect, it } from 'vitest';

import {
  assertDestructiveDatabaseCommandAllowed,
  assertDevelopmentSeedAllowed,
  cloneProcessEnv,
  DatabaseCommandSafetyError,
  redactDatabaseUrl,
} from './database-safety.js';

describe('database command safety', () => {
  it('rejects development seed in production regardless of NODE_ENV', () => {
    expect(() =>
      assertDevelopmentSeedAllowed({
        PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
        NODE_ENV: 'development',
      }),
    ).toThrow(DatabaseCommandSafetyError);
  });

  it('rejects destructive commands without an explicit confirmation variable', () => {
    expect(() =>
      assertDestructiveDatabaseCommandAllowed(
        {
          PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'development',
        },
        'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot',
      ),
    ).toThrow(/PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE/);
  });

  it('allows a confirmed destructive command against the local patchpilot database', () => {
    const inspected = assertDestructiveDatabaseCommandAllowed(
      {
        PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'test',
        PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE: 'true',
      },
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot',
    );
    expect(inspected.databaseName).toBe('patchpilot');
    expect(inspected.host).toBe('127.0.0.1');
  });

  it('does not include credentials in redacted URLs', () => {
    const redacted = redactDatabaseUrl(
      'postgresql://patchpilot:super-secret@127.0.0.1:55432/patchpilot',
    );
    expect(redacted).not.toContain('super-secret');
    expect(redacted).toContain('REDACTED');
  });

  it('overrides DATABASE_URL when cloning process env for subprocesses', () => {
    const cloned = cloneProcessEnv({
      DATABASE_URL: 'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_example',
    });
    expect(cloned['DATABASE_URL']).toBe(
      'postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_example',
    );
  });
});
