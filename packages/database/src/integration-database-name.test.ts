import { describe, expect, it } from 'vitest';

import { DatabaseCommandSafetyError } from '@patchpilot/config';

import {
  assertDatabaseOwnedByScope,
  createEphemeralDatabaseName,
  MAX_STALE_EPHEMERAL_DATABASES_PER_RUN,
  selectStaleEphemeralDatabases,
  STALE_EPHEMERAL_DATABASE_AGE_MS,
} from './integration-database-name.js';

describe('ephemeral database names', () => {
  it('creates collision-resistant names within PostgreSQL identifier limits', () => {
    const names = new Set<string>();
    for (let index = 0; index < 100; index += 1) {
      const databaseName = createEphemeralDatabaseName('it', {
        scope: 'api',
        nowMs: 1_735_689_600_000,
      });
      names.add(databaseName);
      expect(databaseName.length).toBeLessThanOrEqual(63);
      expect(databaseName.startsWith('patchpilot_it_api_')).toBe(true);
      expect(databaseName).not.toContain('"');
      expect(databaseName).not.toContain(';');
    }

    expect(names.size).toBe(100);
  });

  it('keeps the longest scoped migrate name inside the PostgreSQL identifier limit', () => {
    const databaseName = createEphemeralDatabaseName('migrate', {
      scope: 'abcdefghijkl',
      nowMs: 1_735_689_600_000,
    });
    expect(databaseName.startsWith('patchpilot_migrate_abcdefghijkl_1735689600_')).toBe(true);
    expect(databaseName.length).toBeLessThanOrEqual(63);
    expect(databaseName).toMatch(/^[a-z0-9_]+$/);
  });

  it('rejects scopes that are not safe identifiers', () => {
    expect(() => createEphemeralDatabaseName('it', { scope: 'API' })).toThrow(
      DatabaseCommandSafetyError,
    );
    expect(() => createEphemeralDatabaseName('it', { scope: 'api-worker' })).toThrow(
      DatabaseCommandSafetyError,
    );
    expect(() => createEphemeralDatabaseName('it', { scope: '";drop' })).toThrow(
      DatabaseCommandSafetyError,
    );
  });

  it('selects only old timestamped databases and stays bounded', () => {
    const nowMs = 1_800_000_000_000;
    const fresh = createEphemeralDatabaseName('it', { scope: 'worker', nowMs });
    const stale = Array.from({ length: 10 }, (_unused, index) =>
      createEphemeralDatabaseName('it', {
        scope: 'api',
        nowMs: nowMs - STALE_EPHEMERAL_DATABASE_AGE_MS - (index + 1) * 1000,
      }),
    );
    const selected = selectStaleEphemeralDatabases(
      ['patchpilot', 'postgres', fresh, 'patchpilot_it_not_a_timestamp', ...stale],
      nowMs,
    );

    expect(selected).toHaveLength(MAX_STALE_EPHEMERAL_DATABASES_PER_RUN);
    expect(selected).not.toContain('patchpilot');
    expect(selected).not.toContain(fresh);
    expect(selected.every((name) => stale.includes(name))).toBe(true);
  });

  it('refuses to treat another scope as owned', () => {
    const workerName = createEphemeralDatabaseName('it', {
      scope: 'worker',
      nowMs: 1_735_689_600_000,
    });
    expect(() => assertDatabaseOwnedByScope('api', workerName)).toThrow(DatabaseCommandSafetyError);
    expect(() => assertDatabaseOwnedByScope('worker', workerName)).not.toThrow();
    expect(() => assertDatabaseOwnedByScope('api', 'patchpilot')).toThrow(
      DatabaseCommandSafetyError,
    );
  });
});
