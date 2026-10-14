import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { InstanceAdvisoryAuthorityCommand } from '@patchpilot/domain/instance-advisory-authority';

import {
  InstanceAdvisoryAuthorityCommandConfigurationError,
  loadInstanceAdvisoryAuthorityCommandDatabaseUrl,
  requireInstanceAdvisoryAuthorityCommandDatabaseUrl,
  runInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandIO,
  type InstanceAdvisoryAuthorityCommandSession,
} from './instance-advisory-authority-command-main.js';

const USER_ID = 'abcdefab-cdef-4abc-8def-abcdefabcdef';
const CORRELATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const GRANT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const DATABASE_URL = 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');

class MemoryStream {
  public text = '';

  public write(chunk: string): void {
    this.text += chunk;
  }
}

function grantArgv(authority = 'advisory_submit_local'): string[] {
  return [
    'grant',
    '--user-id',
    USER_ID,
    '--authority',
    authority,
    '--correlation-id',
    CORRELATION_ID,
  ];
}

async function run(
  input: Partial<InstanceAdvisoryAuthorityCommandIO> &
    Pick<InstanceAdvisoryAuthorityCommandIO, 'argv'>,
): Promise<{ readonly exitCode: number; readonly stdout: string; readonly stderr: string }> {
  const stdout = new MemoryStream();
  const stderr = new MemoryStream();
  const exitCode = await runInstanceAdvisoryAuthorityCommand({
    stdout,
    stderr,
    loadDatabaseUrl: () => {
      throw new Error(DATABASE_URL);
    },
    openBoundary: () => {
      throw new Error(DATABASE_URL);
    },
    ...input,
  });
  return { exitCode, stdout: stdout.text, stderr: stderr.text };
}

describe('instance advisory authority command runner', () => {
  it('rejects an invalid target before opening persistence', async () => {
    let opened = false;
    const result = await run({
      argv: [
        'grant',
        '--user-id',
        'person@example.com',
        '--authority',
        'advisory_submit_local',
        '--correlation-id',
        CORRELATION_ID,
      ],
      loadDatabaseUrl: () => {
        throw new Error('loader should not run');
      },
      openBoundary: () => {
        opened = true;
        throw new Error('boundary should not open');
      },
    });
    expect(opened).toBe(false);
    expect(result.exitCode).toBe(3);
    expect(JSON.parse(result.stdout)).toMatchObject({ outcome: 'invalid_command' });
    expect(result.stdout).not.toContain('person@example.com');
    expect(result.stderr).toContain('advisory_submit_local');
    expect(result.stderr).not.toContain(DATABASE_URL);
  });

  it('writes nothing when database configuration fails', async () => {
    let opened = false;
    const result = await run({
      argv: grantArgv(),
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
    const body = JSON.parse(result.stdout) as { acknowledgement: string; outcome: string };
    expect(body).toMatchObject({
      outcome: 'database_unavailable',
      acknowledgement: 'uncertain',
      targetUserId: USER_ID,
    });
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stdout).not.toContain('operator-secret');
    expect(result.stderr).not.toContain('operator-secret');
  });

  it('invokes the narrow boundary once and presents a grant', async () => {
    const calls: InstanceAdvisoryAuthorityCommand[] = [];
    let closed = false;
    const result = await run({
      argv: grantArgv(),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: () => {
        const session: InstanceAdvisoryAuthorityCommandSession = {
          port: {
            execute(command) {
              calls.push(command);
              return Promise.resolve({ outcome: 'granted', grantId: GRANT_ID });
            },
          },
          close() {
            closed = true;
            return Promise.resolve();
          },
        };
        return Promise.resolve(session);
      },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      operation: 'grant',
      targetUserId: USER_ID,
      authority: 'advisory_submit_local',
      issuanceClassification: 'deployment_local_command',
    });
    expect(closed).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      schemaVersion: 'instance_advisory_authority_command_result_v1',
      operation: 'grant',
      outcome: 'granted',
      targetUserId: USER_ID,
      authority: 'advisory_submit_local',
      grantId: GRANT_ID,
      acknowledgement: 'committed',
    });
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stderr).toBe('');
  });

  it('presents exact replay and active-grant conflict from the boundary', async () => {
    const replay = await run({
      argv: grantArgv(),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: { execute: () => Promise.resolve({ outcome: 'already_applied' }) },
        close: () => Promise.resolve(),
      }),
    });
    expect(replay.exitCode).toBe(2);
    expect(JSON.parse(replay.stdout)).toMatchObject({
      outcome: 'already_applied',
      acknowledgement: 'replayed',
      grantId: null,
    });

    const conflict = await run({
      argv: grantArgv('advisory_approve_for_product_evaluation'),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: { execute: () => Promise.resolve({ outcome: 'active_grant_conflict' }) },
        close: () => Promise.resolve(),
      }),
    });
    expect(conflict.exitCode).toBe(5);
    expect(JSON.parse(conflict.stdout)).toMatchObject({
      outcome: 'active_grant_conflict',
      authority: 'advisory_approve_for_product_evaluation',
      acknowledgement: 'unchanged',
    });
  });

  it('supports a safe manual rerun after lost acknowledgement', async () => {
    const calls: string[] = [];
    const result = await run({
      argv: grantArgv(),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: {
          execute(command) {
            calls.push(command.correlationId);
            if (calls.length === 1) {
              return Promise.reject(new Error(`ack lost ${DATABASE_URL}\n    at command-main.ts`));
            }
            return Promise.resolve({ outcome: 'already_applied' });
          },
        },
        close: () => Promise.resolve(),
      }),
    });
    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'internal_failure',
      acknowledgement: 'uncertain',
    });
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stdout).not.toContain('at command-main.ts');
    expect(result.stderr).not.toContain('operator-secret');

    const retry = await run({
      argv: grantArgv(),
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: {
          execute() {
            return Promise.resolve({ outcome: 'already_applied' });
          },
        },
        close: () => Promise.resolve(),
      }),
    });
    expect(retry.exitCode).toBe(2);
    expect(JSON.parse(retry.stdout)).toMatchObject({ outcome: 'already_applied' });
  });

  it('hides a disconnect error that contains the database location', async () => {
    const result = await run({
      argv: ['disable-user', '--user-id', USER_ID, '--correlation-id', CORRELATION_ID],
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: { execute: () => Promise.resolve({ outcome: 'user_disabled' }) },
        close: () => Promise.reject(new Error(DATABASE_URL)),
      }),
    });
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      operation: 'disable_user',
      outcome: 'user_disabled',
      authority: null,
      grantId: null,
    });
    expect(`${result.stdout}${result.stderr}`).not.toContain('postgresql://');
  });

  it('does not describe enable as granting authority', async () => {
    const result = await run({
      argv: ['enable-user', '--user-id', USER_ID, '--correlation-id', CORRELATION_ID],
      loadDatabaseUrl: () => DATABASE_URL,
      openBoundary: async () => ({
        port: { execute: () => Promise.resolve({ outcome: 'user_enabled' }) },
        close: () => Promise.resolve(),
      }),
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).not.toContain('advisory_submit_local');
    expect(result.stdout).not.toContain('"granted"');
  });

  it('rejects a malformed database location before persistence', async () => {
    let opened = false;
    const result = await run({
      argv: grantArgv(),
      loadDatabaseUrl: () =>
        requireInstanceAdvisoryAuthorityCommandDatabaseUrl(
          'http://patchpilot:operator-secret@db.internal/patchpilot',
        ),
      openBoundary: () => {
        opened = true;
        throw new Error('boundary should not open');
      },
    });
    expect(opened).toBe(false);
    expect(result.exitCode).toBe(7);
    expect(JSON.parse(result.stdout)).toMatchObject({
      outcome: 'database_unavailable',
      acknowledgement: 'uncertain',
    });
    expect(`${result.stdout}${result.stderr}`).not.toContain('operator-secret');
    expect(`${result.stdout}${result.stderr}`).not.toContain('http://');
  });

  it('prints help without loading configuration', async () => {
    let loaded = false;
    const result = await run({
      argv: ['help'],
      loadDatabaseUrl: () => {
        loaded = true;
        return DATABASE_URL;
      },
    });
    expect(loaded).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('disable-user');
    expect(result.stderr).not.toContain('postgresql://');
  });
});

describe('instance advisory authority command registration', () => {
  it('stays out of application startup, seed, migrations, and package barrels', () => {
    const needles = [
      'instance-advisory-authority-command-main',
      'run-instance-advisory-authority',
      'runInstanceAdvisoryAuthorityCommand',
      'openInstanceAdvisoryAuthorityCommandBoundary',
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
    expect(databaseIndex).not.toContain('instance-advisory-authority-command');
    const packageJson = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts['instance-advisory-authority']).toBe(
      'node scripts/run-instance-advisory-authority.mjs',
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
      expect(packageJson.scripts[name] ?? '').not.toContain('instance-advisory-authority');
    }
    const build = readFileSync(path.join(here, '..', 'tsconfig.build.json'), 'utf8');
    expect(build).not.toContain('instance-advisory-authority-command-main');
    const databasePackage = JSON.parse(
      readFileSync(path.join(here, '..', 'package.json'), 'utf8'),
    ) as { exports: Record<string, unknown>; files: string[] };
    expect(databasePackage.exports['./instance-advisory-authority']).toBeUndefined();
    expect(databasePackage.files).toContain('dist');
  });

  it('delegates to the committed persistence boundary and inserts no audit event', () => {
    const source = readFileSync(
      path.join(here, 'instance-advisory-authority-command-main.ts'),
      'utf8',
    );
    expect(source).toContain('executeInstanceAdvisoryAuthorityDeploymentCommand');
    expect(source).toContain('return persistence.execute(command)');
    expect(source).not.toContain('process.env');
    expect(source).not.toContain('auditEvent');
    expect(source).not.toContain('$executeRaw');
    expect(source).not.toContain('organization.');
    expect(source).not.toContain('membership.');
    expect(source).not.toContain('finding.');
    expect(source).not.toContain('advisoryRevision');
    expect(source).not.toContain('productMatch');
    expect(source).not.toContain('createInstanceAdvisoryAuthorizationRead');
    expect(source).toContain('inspectDatabaseUrl');
    expect(source).toContain('loadServerConfig');
    expect(source).not.toContain('console.');
    expect(source).not.toContain('postgresql://');
    expect(source).not.toContain('while (');
    expect(source).not.toContain('readFile');
    expect(source).not.toContain('stdin');
  });

  it('maps a malformed database location to a fixed error', () => {
    expect(() => requireInstanceAdvisoryAuthorityCommandDatabaseUrl('')).toThrow(
      'database_configuration_invalid',
    );
    expect(() => requireInstanceAdvisoryAuthorityCommandDatabaseUrl('   ')).toThrow(
      'database_configuration_invalid',
    );
    expect(() => requireInstanceAdvisoryAuthorityCommandDatabaseUrl('not-a-url')).toThrow(
      'database_configuration_invalid',
    );
    const rejected = DATABASE_URL.replace('postgresql:', 'http:');
    expect(() => requireInstanceAdvisoryAuthorityCommandDatabaseUrl(rejected)).toThrow(
      'database_configuration_invalid',
    );
    try {
      loadInstanceAdvisoryAuthorityCommandDatabaseUrl();
    } catch (error) {
      expect(error).toBeInstanceOf(InstanceAdvisoryAuthorityCommandConfigurationError);
      expect(error instanceof Error ? error.message : '').toBe('database_configuration_invalid');
      expect(String(error)).not.toContain('postgresql://');
      expect(String(error)).not.toContain('operator-secret');
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
        expect(script).not.toContain('instance-advisory-authority');
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
