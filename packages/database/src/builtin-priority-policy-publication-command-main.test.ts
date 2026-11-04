import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ADMITTED_PRIORITY_POLICY_PAIRS } from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
} from '@patchpilot/policy-engine';
import { describe, expect, it } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
  productionPublicationAdmitsCurrentBuiltin,
} from './builtin-priority-policy-publication.js';
import {
  BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT,
  loadBuiltinPriorityPolicyPublication,
  runBuiltinPriorityPolicyPublicationCommand,
  type BuiltinPriorityPolicyPublicationCommandIO,
  type BuiltinPriorityPolicyPublicationSession,
} from './builtin-priority-policy-publication-command-main.js';
import { developmentSeedIds } from './seed/development.js';

const CORRELATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const DATABASE_URL = 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot';
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');

class MemoryStream {
  public text = '';

  public write(chunk: string): void {
    this.text += chunk;
  }
}

describe('builtin priority policy publication command', () => {
  it('refuses the unsigned builtin before opening a database', async () => {
    let opened = false;
    const result = await runCommand({
      argv: ['--correlation-id', CORRELATION_ID],
      loadPublication: loadBuiltinPriorityPolicyPublication,
      loadDatabaseUrl() {
        opened = true;
        return DATABASE_URL;
      },
      openBoundary() {
        opened = true;
        throw new Error('database opened');
      },
    });
    expect(ADMITTED_PRIORITY_POLICY_PAIRS).toEqual([]);
    expect(
      productionPublicationAdmitsCurrentBuiltin(
        canonicalJson,
        BUILTIN_PRIORITY_POLICY_DEFINITION,
        POLICY_ENGINE_VERSION,
      ),
    ).toBe(false);
    expect(opened).toBe(false);
    expect(result.exitCode).toBe(BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.unvalidated);
    expect(result.stdout).toContain('"outcome":"unvalidated"');
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stdout).not.toMatch(/[a-f0-9]{64}/);
  });

  it('writes help to stderr and no JSON', async () => {
    const result = await runCommand({
      argv: ['help'],
      loadDatabaseUrl() {
        throw new Error('database');
      },
      openBoundary() {
        throw new Error('database');
      },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('--correlation-id');
  });

  it('rejects an unknown flag', async () => {
    const result = await runCommand({
      argv: ['--definition', 'override'],
      loadDatabaseUrl() {
        throw new Error('database');
      },
      openBoundary() {
        throw new Error('database');
      },
    });
    expect(result.exitCode).toBe(BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.invalidCommand);
    expect(result.stdout).toContain('invalid_command');
  });

  it('uses the same policy id as the development seed and reports exact replay without a second audit', async () => {
    expect(BUILTIN_PRIORITY_POLICY_PUBLICATION_ID).toBe(
      developmentSeedIds.builtinPriorityPolicyVersion2,
    );
    const encoded = canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) {
      return;
    }
    const hash = createHash('sha256').update(encoded.value, 'utf8').digest('hex');
    let publishes = 0;
    const result = await runCommand({
      argv: ['--correlation-id', CORRELATION_ID],
      loadPublication() {
        return {
          definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
          engineVersion: POLICY_ENGINE_VERSION,
          canonicalJson,
          admittedPairs: [
            {
              engineVersion: POLICY_ENGINE_VERSION,
              policyDefinitionSha256: hash,
              validationEntryId: 'fixture',
            },
          ],
        };
      },
      loadDatabaseUrl() {
        return DATABASE_URL;
      },
      async openBoundary() {
        const session: BuiltinPriorityPolicyPublicationSession = {
          async publish() {
            publishes += 1;
            return {
              outcome: 'already_applied',
              riskPolicyId: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
            };
          },
          async close() {
            return undefined;
          },
        };
        return session;
      },
    });
    expect(publishes).toBe(1);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('"outcome":"already_applied"');
    expect(result.stdout).not.toContain(DATABASE_URL);
    expect(result.stdout).not.toContain(hash);
  });
});

describe('builtin priority policy publication registration', () => {
  it('stays out of application startup, seed, migrations, and package barrels', () => {
    const needles = [
      'builtin-priority-policy-publication-command-main',
      'run-publish-builtin-priority-policy',
      'runBuiltinPriorityPolicyPublicationCommand',
      'openBuiltinPriorityPolicyPublicationBoundary',
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
    expect(databaseIndex).not.toContain('builtin-priority-policy-publication');
    const packageJson = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts['publish-builtin-priority-policy']).toBe(
      'node scripts/run-publish-builtin-priority-policy.mjs',
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
      expect(packageJson.scripts[name] ?? '').not.toContain('publish-builtin-priority-policy');
    }
    const databasePackage = JSON.parse(
      readFileSync(path.join(here, '..', 'package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(databasePackage.exports['./builtin-priority-policy-publication']).toBeUndefined();
  });
});

async function runCommand(
  input: Partial<BuiltinPriorityPolicyPublicationCommandIO> &
    Pick<BuiltinPriorityPolicyPublicationCommandIO, 'argv'>,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const stdout = new MemoryStream();
  const stderr = new MemoryStream();
  const exitCode = await runBuiltinPriorityPolicyPublicationCommand({
    stdout,
    stderr,
    loadDatabaseUrl() {
      throw new Error('database');
    },
    openBoundary() {
      throw new Error('database');
    },
    ...input,
  });
  return { exitCode, stdout: stdout.text, stderr: stderr.text };
}

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
    const filePath = path.join(directory, entry);
    if (statSync(filePath).isDirectory()) {
      walk(filePath, files);
      continue;
    }
    files.push(filePath);
  }
  return files;
}
