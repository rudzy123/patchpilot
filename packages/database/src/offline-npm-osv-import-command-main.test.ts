import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  OFFLINE_NPM_OSV_IMPORT_STDERR,
  OFFLINE_NPM_OSV_IMPORT_USAGE,
} from '@patchpilot/vulnerability-intelligence';

import {
  OfflineNpmOsvImportCommandConfigurationError,
  loadOfflineNpmOsvImportCommandDatabaseUrl,
  requireOfflineNpmOsvImportCommandDatabaseUrl,
  runOfflineNpmOsvImportCommand,
  type OfflineNpmOsvImportCommandIO,
  type OfflineNpmOsvImportCommandPort,
  type OfflineNpmOsvImportCommandSession,
} from './offline-npm-osv-import-command-main.js';
import { readOfflineNpmImportDirectory } from './offline-npm-osv-import-directory.js';

const CORRELATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const BATCH_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const DATABASE_URL = 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot';
const DIRECTORY = '/var/lib/patchpilot/offline-import-path-token';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');

class MemoryStream {
  public text = '';

  public write(chunk: string): void {
    this.text += chunk;
  }
}

function commandArgv(directory = DIRECTORY): string[] {
  return ['--directory', directory, '--correlation-id', CORRELATION_ID];
}

function admitted(
  name: string,
  text: string,
): { readonly name: string; readonly bytes: Uint8Array } {
  return { name, bytes: new TextEncoder().encode(text) };
}

async function run(
  input: Partial<OfflineNpmOsvImportCommandIO> & Pick<OfflineNpmOsvImportCommandIO, 'argv'>,
): Promise<{ readonly exitCode: number; readonly stdout: string; readonly stderr: string }> {
  const stdout = new MemoryStream();
  const stderr = new MemoryStream();
  const exitCode = await runOfflineNpmOsvImportCommand({
    stdout,
    stderr,
    loadDatabaseUrl: () => {
      throw new Error(DATABASE_URL);
    },
    openBoundary: () => {
      throw new Error(DATABASE_URL);
    },
    readDirectory: () => Promise.resolve({ ok: true, files: [], unreadable: [] }),
    ...input,
  });
  return { exitCode, stdout: stdout.text, stderr: stderr.text };
}

function port(
  overrides: Partial<OfflineNpmOsvImportCommandPort> = {},
): OfflineNpmOsvImportCommandPort {
  return {
    beginBatch: () =>
      Promise.resolve({
        kind: 'started',
        batchId: BATCH_ID,
        retrievedAt: '2026-11-02T18:00:00.000Z',
      }),
    resolveSupersession: () => Promise.resolve({ kind: 'ready', supersedesRevisionDigest: 'none' }),
    persistFile: () => Promise.reject(new Error('persist should not run')),
    completeBatch: () => Promise.resolve({ kind: 'recorded' }),
    ...overrides,
  };
}

function session(
  commandPort: OfflineNpmOsvImportCommandPort,
  closed: { value: boolean },
): OfflineNpmOsvImportCommandSession {
  return {
    port: commandPort,
    close() {
      closed.value = true;
      return Promise.resolve();
    },
  };
}

describe('offline npm OSV import command runner', () => {
  it('prints help without reading a directory or the database', async () => {
    let read = false;
    let loaded = false;
    const result = await run({
      argv: ['help'],
      readDirectory: () => {
        read = true;
        return Promise.resolve({ ok: false, reason: 'directory_rejected' });
      },
      loadDatabaseUrl: () => {
        loaded = true;
        return DATABASE_URL;
      },
    });
    expect(read).toBe(false);
    expect(loaded).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_USAGE}\n`);
    expect(result.stderr).not.toContain('postgresql://');
  });

  it('rejects an enabling flag before opening persistence', async () => {
    let opened = false;
    const result = await run({
      argv: ['--directory', DIRECTORY, '--enable-osv', '--correlation-id', CORRELATION_ID],
      openBoundary: () => {
        opened = true;
        throw new Error('boundary should not open');
      },
    });
    expect(opened).toBe(false);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_STDERR.directoryRejected}\n`);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'invalid_command',
    });
    const body = JSON.parse(result.stdout) as {
      rejected: { reasonCodes: string[] };
    };
    expect(body.rejected.reasonCodes).toEqual(['invalid_command']);
    expect(result.stdout).not.toContain('enable-osv');
    expect(result.stdout).not.toContain(DATABASE_URL);
  });

  it('rejects a symlink directory before loading the database', async () => {
    const parent = mkdtempSync(path.join(tmpdir(), 'offline-import-path-token-'));
    const real = path.join(parent, 'real');
    const link = path.join(parent, 'link');
    mkdirSync(real);
    writeFileSync(path.join(real, 'a.json'), '{"secret":"document-text"}');
    symlinkSync(real, link);
    let loaded = false;
    try {
      const result = await run({
        argv: commandArgv(link),
        readDirectory: readOfflineNpmImportDirectory,
        loadDatabaseUrl: () => {
          loaded = true;
          return DATABASE_URL;
        },
      });
      expect(loaded).toBe(false);
      expect(result.exitCode).toBe(3);
      expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_STDERR.directoryRejected}\n`);
      expect(`${result.stdout}${result.stderr}`).not.toContain('document-text');
      expect(`${result.stdout}${result.stderr}`).not.toContain(link);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('writes nothing when database configuration fails', async () => {
    let opened = false;
    const result = await run({
      argv: commandArgv(),
      loadDatabaseUrl: () => {
        throw new Error(`missing ${DATABASE_URL}`);
      },
      openBoundary: () => {
        opened = true;
        throw new Error('boundary should not open');
      },
    });
    expect(opened).toBe(false);
    expect(result.exitCode).toBe(7);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'database_unavailable',
      correlationId: CORRELATION_ID,
    });
    expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_STDERR.databaseUnavailable}\n`);
    expect(`${result.stdout}${result.stderr}`).not.toContain('operator-secret');
    expect(`${result.stdout}${result.stderr}`).not.toContain(DIRECTORY);
  });

  it('records one normalized file and closes the boundary', async () => {
    const calls: unknown[] = [];
    const closed = { value: false };
    const document =
      '{"id":"GHSA-SYN0-CMD-0001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}';
    const result = await run({
      argv: commandArgv(),
      readDirectory: () =>
        Promise.resolve({
          ok: true,
          files: [admitted('cmd-secret-segment.json', document)],
          unreadable: [],
        }),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () =>
        Promise.resolve(
          session(
            port({
              persistFile(command) {
                calls.push(command);
                return Promise.resolve({
                  kind: 'recorded',
                  familyId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
                  projections: [],
                  counts: {
                    inserts: 1,
                    updates: 0,
                    deletes: 0,
                    timestampChanges: 0,
                    stateChanges: 0,
                    parserCalls: 0,
                    providerCalls: 0,
                  },
                  auditEventAdded: true,
                });
              },
            }),
            closed,
          ),
        ),
    });
    expect(closed.value).toBe(true);
    expect(calls).toHaveLength(1);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    const body = JSON.parse(result.stdout) as {
      schemaVersion: string;
      batchId: string;
      accepted: { count: number; advisoryIds: string[] };
    };
    expect(body.schemaVersion).toBe('offline_npm_osv_import_summary_v1');
    expect(body.batchId).toBe(BATCH_ID);
    expect(body.accepted).toEqual({
      count: 1,
      advisoryIds: ['GHSA-SYN0-CMD-0001'],
      reasonCodes: [],
    });
    expect(result.stdout).not.toContain('left-pad');
    expect(result.stdout).not.toContain('cmd-secret-segment');
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stdout).not.toContain(DIRECTORY);
  });

  it('rejects one unreadable file and still records the readable sibling', async () => {
    let persisted = 0;
    const document =
      '{"id":"GHSA-SYN0-CMD-0002","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}';
    const result = await run({
      argv: commandArgv(),
      readDirectory: () =>
        Promise.resolve({
          ok: true,
          files: [admitted('readable.json', document)],
          unreadable: ['locked.json'],
        }),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () =>
        Promise.resolve(
          session(
            port({
              persistFile() {
                persisted += 1;
                return Promise.resolve({
                  kind: 'recorded',
                  familyId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
                  projections: [],
                  counts: {
                    inserts: 1,
                    updates: 0,
                    deletes: 0,
                    timestampChanges: 0,
                    stateChanges: 0,
                    parserCalls: 0,
                    providerCalls: 0,
                  },
                  auditEventAdded: true,
                });
              },
            }),
            { value: false },
          ),
        ),
    });
    expect(persisted).toBe(1);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'completed',
      accepted: { count: 1, advisoryIds: ['GHSA-SYN0-CMD-0002'] },
      rejected: { count: 1, advisoryIds: [], reasonCodes: ['unreadable_file'] },
    });
    expect(result.stdout).not.toContain('locked.json');
    expect(result.stdout).not.toContain('readable.json');
  });

  it('keeps a record rejection in rejected and still completes', async () => {
    let completed = false;
    let persisted = false;
    const result = await run({
      argv: commandArgv(),
      readDirectory: () =>
        Promise.resolve({ ok: true, files: [admitted('bad.json', '{]')], unreadable: [] }),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () =>
        Promise.resolve(
          session(
            port({
              persistFile() {
                persisted = true;
                return Promise.reject(new Error('persist should not run'));
              },
              completeBatch() {
                completed = true;
                return Promise.resolve({ kind: 'recorded' });
              },
            }),
            { value: false },
          ),
        ),
    });
    expect(persisted).toBe(false);
    expect(completed).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'completed',
      rejected: { count: 1, reasonCodes: ['malformed_json'] },
    });
  });

  it('stops after a failed file transaction and skips the terminal audit', async () => {
    let completed = false;
    const result = await run({
      argv: commandArgv(),
      readDirectory: () =>
        Promise.resolve({
          ok: true,
          files: [
            admitted(
              'a.json',
              '{"id":"GHSA-SYN0-CMD-0001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}',
            ),
          ],
          unreadable: [],
        }),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () =>
        Promise.resolve(
          session(
            port({
              persistFile: () =>
                Promise.resolve({
                  kind: 'rejected',
                  code: 'transaction_aborted',
                  counts: {
                    inserts: 0,
                    updates: 0,
                    deletes: 0,
                    timestampChanges: 0,
                    stateChanges: 0,
                    parserCalls: 0,
                    providerCalls: 0,
                  },
                }),
              completeBatch() {
                completed = true;
                return Promise.resolve({ kind: 'recorded' });
              },
            }),
            { value: false },
          ),
        ),
    });
    expect(completed).toBe(false);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_STDERR.failed}\n`);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'failed',
      failed: {
        count: 1,
        advisoryIds: ['GHSA-SYN0-CMD-0001'],
        reasonCodes: ['transaction_aborted'],
      },
    });
    expect(result.stdout).not.toContain('left-pad');
  });

  it('does not process files when the correlation belongs to another batch', async () => {
    let persisted = false;
    const result = await run({
      argv: commandArgv(),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () =>
        Promise.resolve(
          session(
            port({
              beginBatch: () => Promise.resolve({ kind: 'immutable_conflict' }),
              persistFile() {
                persisted = true;
                return Promise.reject(new Error('persist should not run'));
              },
            }),
            { value: false },
          ),
        ),
    });
    expect(persisted).toBe(false);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toBe(`${OFFLINE_NPM_OSV_IMPORT_STDERR.directoryRejected}\n`);
    expect(JSON.parse(result.stdout)).toMatchObject({
      rejected: { reasonCodes: ['immutable_conflict'] },
      batchId: null,
    });
  });

  it('hides a database location that leaks into the summary', async () => {
    const result = await run({
      argv: commandArgv(DATABASE_URL),
      readDirectory: () => Promise.resolve({ ok: false, reason: 'directory_rejected' }),
    });
    expect(result.exitCode).toBe(3);
    expect(result.stdout).not.toContain('operator-secret');
  });
});

describe('offline npm OSV import command registration', () => {
  it('stays out of application startup, seed, migrations, and package barrels', () => {
    const needles = [
      'offline-npm-osv-import-command-main',
      'run-offline-npm-osv-import',
      'runOfflineNpmOsvImportCommand',
      'openOfflineNpmOsvImportCommandBoundary',
    ];
    const roots = [
      'apps/api/src',
      'apps/web',
      'apps/worker/src',
      'packages/database/src/seed',
      'packages/database/prisma',
      '.github',
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(path.join(repoRoot, root))) {
        if (!/\.(ts|tsx|mjs|js|yml|yaml|sql)$/.test(filePath)) {
          continue;
        }
        const source = readFileSync(filePath, 'utf8');
        if (needles.some((needle) => source.includes(needle))) {
          offenders.push(path.relative(repoRoot, filePath));
        }
      }
    }
    expect(offenders).toEqual([]);
    const databaseIndex = readFileSync(path.join(here, 'index.ts'), 'utf8');
    expect(databaseIndex).not.toContain('offline-npm-osv-import-command');
    const packageJson = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts['offline-npm-osv-import']).toBe(
      'node scripts/run-offline-npm-osv-import.mjs',
    );
    for (const name of [
      'dev',
      'build',
      'test',
      'test:unit',
      'test:integration',
      'postinstall',
      'db:seed',
      'db:migrate',
      'db:migrate:deploy',
    ]) {
      expect(packageJson.scripts[name] ?? '').not.toContain('offline-npm-osv-import');
    }
    const build = readFileSync(path.join(here, '..', 'tsconfig.build.json'), 'utf8');
    expect(build).not.toContain('offline-npm-osv-import-command-main');
    const databasePackage = JSON.parse(
      readFileSync(path.join(here, '..', 'package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(databasePackage.exports['./offline-npm-osv-import']).toBeUndefined();
  });

  it('delegates writes and does not read the process environment', () => {
    const source = readFileSync(path.join(here, 'offline-npm-osv-import-command-main.ts'), 'utf8');
    expect(source).toContain('normalizeOfflineNpmGhsaBytes');
    expect(source).toContain('persistOfflineNpmAdvisoryFile');
    expect(source).toContain('inspectDatabaseUrl');
    expect(source).toContain('loadServerConfig');
    expect(source).not.toContain('process.env');
    expect(source).not.toContain('auditEvent');
    expect(source).not.toContain('$executeRaw');
    expect(source).not.toContain('node:fs');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
    expect(source).not.toContain('node:net');
    expect(source).not.toContain('osv.dev');
    expect(source).not.toContain('storage.googleapis.com');
    expect(source).not.toContain('INTELLIGENCE_OSV_ENABLED');
    expect(source).not.toContain('intelligence.osv.sync');
    expect(source).not.toContain('console.');
    expect(source).not.toContain('postgresql://');
    expect(source).not.toContain('readFile');
    expect(source).not.toContain('finding.');
    expect(source).not.toContain('productMatch');
    expect(source).not.toContain('outbox');
    const persistence = readFileSync(
      path.join(here, 'offline-npm-osv-import-persistence.ts'),
      'utf8',
    );
    expect(persistence).toContain('clock_timestamp');
    expect(persistence).toContain('intelligence.offline_npm_osv_import_started');
    expect(persistence).toContain('intelligence.offline_npm_osv_import_completed');
    expect(persistence).not.toContain('process.env');
    expect(persistence).not.toContain('node:http');
    expect(persistence).not.toContain('finding.create');
    expect(persistence).not.toContain('outboxEvent');
    expect(persistence).not.toContain('vulnerability.create');
  });

  it('maps a malformed database location to a fixed error', () => {
    expect(() => requireOfflineNpmOsvImportCommandDatabaseUrl('')).toThrow(
      'database_configuration_invalid',
    );
    expect(() =>
      requireOfflineNpmOsvImportCommandDatabaseUrl(
        'http://patchpilot:operator-secret@db/patchpilot',
      ),
    ).toThrow(OfflineNpmOsvImportCommandConfigurationError);
    try {
      loadOfflineNpmOsvImportCommandDatabaseUrl();
    } catch (error) {
      expect(error).toBeInstanceOf(OfflineNpmOsvImportCommandConfigurationError);
      expect(error instanceof Error ? error.message : '').toBe('database_configuration_invalid');
      expect(String(error)).not.toContain('postgresql://');
    }
  });

  it('is absent from application start scripts', () => {
    for (const relative of [
      'apps/api/package.json',
      'apps/web/package.json',
      'apps/worker/package.json',
    ]) {
      const appPackage = JSON.parse(readFileSync(path.join(repoRoot, relative), 'utf8')) as {
        scripts: Record<string, string>;
      };
      for (const script of Object.values(appPackage.scripts)) {
        expect(script).not.toContain('offline-npm-osv-import');
      }
    }
  });
});

function walk(directory: string, files: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(directory);
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '.next') {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else {
      files.push(fullPath);
    }
  }
  return files;
}
