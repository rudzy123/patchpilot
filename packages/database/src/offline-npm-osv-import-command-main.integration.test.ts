/**
 * Disposable PostgreSQL proof for the deployment-local offline npm OSV import.
 * Synthetic documents only. No real GHSA body is stored.
 */

import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { PrismaClient } from '@prisma/client';
import { OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER } from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { disconnectPrisma } from './client.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { readOfflineNpmImportDirectory } from './offline-npm-osv-import-directory.js';
import {
  openOfflineNpmOsvImportCommandBoundary,
  runOfflineNpmOsvImportCommand,
} from './offline-npm-osv-import-command-main.js';

const PATH_TOKEN = 'offline-import-path-token';
const FILE_NAME = 'cmd-secret-segment.json';
const CLIENT_ORGANIZATION_ID = '11111111-1111-4111-8111-111111111111';

class MemoryStream {
  public text = '';

  public write(chunk: string): void {
    this.text += chunk;
  }
}

function document(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    modified: '2026-01-01T00:00:00Z',
    published: '2025-12-01T00:00:00Z',
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: 'left-pad',
          purl: 'pkg:npm/left-pad@1.2.3',
        },
        ranges: [
          { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] },
          { type: 'SEMVER', events: [{ introduced: '0.1.0' }] },
        ],
        versions: ['1.2.3', '1.0.0'],
      },
    ],
    ...overrides,
  };
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

describe('offline npm OSV import deployment command', () => {
  let databaseName = '';
  let databaseUrl = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  const directories: string[] = [];

  beforeAll(async () => {
    await disconnectPrisma();
    const ephemeral = await createEphemeralDatabase('it', { scope: 'osvcmd' });
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    await disconnectPrisma();
    for (const directory of directories) {
      rmSync(directory, { recursive: true, force: true });
    }
    if (databaseName !== '') {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('imports one file, replays it, and keeps product tables empty', async () => {
    const advisoryId = 'GHSA-SYN0-CMD-1001';
    const directory = writeDirectory({ [FILE_NAME]: document(advisoryId) });
    const correlationId = randomUUID();
    const first = await invoke(databaseUrl, directory, correlationId);
    expect(first.exitCode).toBe(0);
    expect(first.stderr).toBe('');
    expect(first.body).toMatchObject({
      schemaVersion: 'offline_npm_osv_import_summary_v1',
      correlationId,
      outcome: 'completed',
      registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
      accepted: { count: 1, advisoryIds: [advisoryId], reasonCodes: [] },
      skipped: { count: 0, advisoryIds: [], reasonCodes: [] },
      rejected: { count: 0 },
      failed: { count: 0 },
    });
    expect(secretFree(first.stdout, directory)).toBe(true);
    const batchId = first.body['batchId'];
    expect(typeof batchId).toBe('string');
    const batch = await prisma.offlineAdvisoryImportBatch.findUniqueOrThrow({
      where: { id: String(batchId) },
    });
    expect(batch.manifestSha256).toBe(first.body['manifestSha256']);
    expect(batch.sourceLicenseRegistryVersion).toBe(OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER);
    const revision = await prisma.advisoryRevision.findFirstOrThrow({
      where: { advisoryId },
    });
    expect(revision.retrievalClassification).toBe('local_not_retrieved');
    expect(revision.providerGeneration).toBe('offline-import-v1');
    expect(revision.supersedesAdvisoryRevisionId).toBeNull();
    expect(revision.packageName).toBe('left-pad');
    const events = await prisma.advisoryRevisionRangeEvent.findMany({
      where: { advisoryRevisionId: revision.id },
      orderBy: [{ rangeOrdinal: 'asc' }, { eventOrdinal: 'asc' }],
    });
    expect(events.map((event) => `${event.eventName}:${event.eventValue}`).sort()).toEqual([
      'fixed:1.2.0',
      'introduced:0.1.0',
      'introduced:1.0.0',
    ]);
    const introducedFixed = events.filter(
      (event) => event.eventValue === '1.0.0' || event.eventValue === '1.2.0',
    );
    expect(new Set(introducedFixed.map((event) => event.rangeOrdinal)).size).toBe(1);
    const versions = await prisma.advisoryRevisionExplicitVersion.findMany({
      where: { advisoryRevisionId: revision.id },
      orderBy: { ordinal: 'asc' },
    });
    expect(versions.map((version) => version.versionText)).toEqual(['1.0.0', '1.2.3']);
    const provenance = await prisma.advisoryRevisionSourceProvenance.findUniqueOrThrow({
      where: { advisoryRevisionId: revision.id },
    });
    const raw = new TextEncoder().encode(JSON.stringify(document(advisoryId)));
    expect(provenance.rawContentSha256).toBe(sha256(raw));
    expect(provenance.source).toBe('github_advisory_database');
    expect(provenance.sourceLicenseRegistryVersion).toBe(OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER);
    expect(provenance.licenseAdmissionReason).toBe('approved_source_license');
    expect(provenance.purl).toBe('pkg:npm/left-pad@1.2.3');
    expect(provenance.offlineAdvisoryImportBatchId).toBe(batch.id);
    expect(provenance.retrievedAt.toISOString()).toBe(batch.retrievedAt.toISOString());
    expect(provenance.modifiedAt.toISOString()).toBe('2026-01-01T00:00:00.000Z');
    expect(provenance.publishedAt?.toISOString()).toBe('2025-12-01T00:00:00.000Z');
    await expectAuditShape(prisma, correlationId, batch.id, 1, 1, 1);
    expect(await productWrites(prisma)).toEqual({
      findings: 0,
      vulnerabilities: 0,
      bindings: 0,
      evidence: 0,
      outbox: 0,
      risk: 0,
      syncRuns: 0,
    });

    const replay = await invoke(databaseUrl, directory, correlationId);
    expect(replay.exitCode).toBe(0);
    expect(replay.stderr).toBe('');
    expect(replay.body).toMatchObject({
      outcome: 'completed',
      batchId,
      skipped: { count: 1, advisoryIds: [advisoryId], reasonCodes: ['already_applied'] },
      accepted: { count: 0 },
    });
    expect(await prisma.advisoryRevision.count({ where: { advisoryId } })).toBe(1);
    await expectAuditShape(prisma, correlationId, batch.id, 1, 1, 1);

    const again = await invoke(databaseUrl, directory, randomUUID());
    expect(again.exitCode).toBe(0);
    expect(again.body).toMatchObject({
      batchId,
      skipped: { count: 1, reasonCodes: ['already_applied'] },
    });
    expect(await prisma.offlineAdvisoryImportBatch.count({ where: { id: batch.id } })).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.offline_npm_osv_import_started', subjectId: batch.id },
      }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.offline_npm_osv_file_imported', correlationId },
      }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.offline_npm_osv_import_completed', subjectId: batch.id },
      }),
    ).toBe(2);
  });

  it('inserts a successor when modified changes and does not move the tip on older replay', async () => {
    const advisoryId = 'GHSA-SYN0-CMD-1002';
    const original = writeDirectory({ [FILE_NAME]: document(advisoryId) });
    const first = await invoke(databaseUrl, original, randomUUID());
    expect(first.exitCode).toBe(0);
    expect(first.body['accepted']).toMatchObject({ count: 1 });
    const changed = writeDirectory({
      [FILE_NAME]: document(advisoryId, { modified: '2026-06-01T00:00:00Z' }),
    });
    const second = await invoke(databaseUrl, changed, randomUUID());
    expect(second.exitCode).toBe(0);
    expect(second.body['accepted']).toMatchObject({ count: 1, advisoryIds: [advisoryId] });
    const rows = await prisma.advisoryRevision.findMany({
      where: { advisoryId },
      select: { id: true, supersedesAdvisoryRevisionId: true },
    });
    expect(rows).toHaveLength(2);
    const tip = rows.find((row) => row.supersedesAdvisoryRevisionId !== null);
    const prior = rows.find((row) => row.supersedesAdvisoryRevisionId === null);
    expect(tip?.supersedesAdvisoryRevisionId).toBe(prior?.id);
    const replay = await invoke(databaseUrl, original, randomUUID());
    expect(replay.exitCode).toBe(0);
    expect(replay.body['skipped']).toMatchObject({
      count: 1,
      reasonCodes: ['already_applied'],
    });
    expect(await prisma.advisoryRevision.count({ where: { advisoryId } })).toBe(2);
    const after = await prisma.advisoryRevision.findMany({
      where: { advisoryId },
      select: { id: true, supersedesAdvisoryRevisionId: true },
    });
    expect(after.find((row) => row.id === tip?.id)?.supersedesAdvisoryRevisionId).toBe(prior?.id);
  });

  it('commits an admitted file when another file in the directory is rejected', async () => {
    const advisoryId = 'GHSA-SYN0-CMD-1003';
    const directory = writeDirectory({
      'aaaa-bad.json': '{]',
      'zzzz-good.json': document(advisoryId),
    });
    const result = await invoke(databaseUrl, directory, randomUUID());
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.body).toMatchObject({
      outcome: 'completed',
      accepted: { count: 1, advisoryIds: [advisoryId] },
      rejected: { count: 1, reasonCodes: ['malformed_json'] },
    });
    expect(await prisma.advisoryRevision.count({ where: { advisoryId } })).toBe(1);
    expect(secretFree(result.stdout, directory)).toBe(true);
  });

  it('stores nothing from a client organization id inside the document', async () => {
    const advisoryId = 'GHSA-SYN0-CMD-1004';
    const organizations = await prisma.organization.count();
    const directory = writeDirectory({
      [FILE_NAME]: document(advisoryId, {
        database_specific: { organizationId: CLIENT_ORGANIZATION_ID },
      }),
    });
    const result = await invoke(databaseUrl, directory, randomUUID());
    expect(result.exitCode).toBe(0);
    expect(result.body['accepted']).toMatchObject({ count: 1 });
    expect(result.stdout).not.toContain(CLIENT_ORGANIZATION_ID);
    expect(await prisma.organization.count()).toBe(organizations);
    const revision = await prisma.advisoryRevision.findFirstOrThrow({ where: { advisoryId } });
    const provenance = await prisma.advisoryRevisionSourceProvenance.findUniqueOrThrow({
      where: { advisoryRevisionId: revision.id },
    });
    expect(JSON.stringify(provenance)).not.toContain(CLIENT_ORGANIZATION_ID);
    const audits = await prisma.auditEvent.findMany({
      where: { correlationId: String(result.body['correlationId']) },
    });
    expect(JSON.stringify(audits)).not.toContain(CLIENT_ORGANIZATION_ID);
    expect(secretFree(JSON.stringify(audits), directory)).toBe(true);
  });

  it('rejects a second directory that reuses the correlation before writing another batch', async () => {
    const firstDirectory = writeDirectory({
      [FILE_NAME]: document('GHSA-SYN0-CMD-1005'),
    });
    const correlationId = randomUUID();
    const first = await invoke(databaseUrl, firstDirectory, correlationId);
    expect(first.exitCode).toBe(0);
    const batches = await prisma.offlineAdvisoryImportBatch.count();
    const secondDirectory = writeDirectory({
      [FILE_NAME]: document('GHSA-SYN0-CMD-1006'),
    });
    const second = await invoke(databaseUrl, secondDirectory, correlationId);
    expect(second.exitCode).toBe(3);
    expect(second.stderr).toBe('offline_npm_osv_import_directory_rejected\n');
    expect(second.body).toMatchObject({
      outcome: 'directory_rejected',
      batchId: null,
      rejected: { reasonCodes: ['immutable_conflict'] },
    });
    expect(await prisma.offlineAdvisoryImportBatch.count()).toBe(batches);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-CMD-1006' } }),
    ).toBe(0);
    expect(secretFree(`${second.stdout}${second.stderr}`, secondDirectory)).toBe(true);
  });

  it('appends a later file for the same advisory in one directory', async () => {
    const advisoryId = 'GHSA-SYN0-CMD-2001';
    const directory = writeDirectory({
      'a-first.json': document(advisoryId, { modified: '2026-01-01T00:00:00Z' }),
      'b-second.json': document(advisoryId, { modified: '2026-02-01T00:00:00Z' }),
    });
    const correlationId = randomUUID();
    const result = await invoke(databaseUrl, directory, correlationId);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.body).toMatchObject({
      outcome: 'completed',
      accepted: { count: 2, advisoryIds: [advisoryId], reasonCodes: [] },
      skipped: { count: 0 },
      rejected: { count: 0 },
      failed: { count: 0 },
    });
    const revisions = await prisma.advisoryRevision.findMany({
      where: { advisoryId },
      select: { id: true, supersedesAdvisoryRevisionId: true },
    });
    expect(revisions).toHaveLength(2);
    const prior = revisions.find((row) => row.supersedesAdvisoryRevisionId === null);
    const tip = revisions.find((row) => row.supersedesAdvisoryRevisionId !== null);
    expect(tip?.supersedesAdvisoryRevisionId).toBe(prior?.id);
    const batchId = String(result.body['batchId']);
    await expectAuditShape(prisma, correlationId, batchId, 1, 1, 1);
    expect(secretFree(result.stdout, directory)).toBe(true);
  });

  it('accepts an empty directory as a zero-file batch', async () => {
    const directory = writeDirectory({});
    const result = await invoke(databaseUrl, directory, randomUUID());
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.body).toMatchObject({
      outcome: 'completed',
      accepted: { count: 0, advisoryIds: [] },
      skipped: { count: 0 },
      rejected: { count: 0 },
      failed: { count: 0 },
    });
    const batch = await prisma.offlineAdvisoryImportBatch.findUniqueOrThrow({
      where: { manifestSha256: String(result.body['manifestSha256']) },
    });
    expect(
      await prisma.auditEvent.count({
        where: {
          subjectId: batch.id,
          action: {
            in: [
              'intelligence.offline_npm_osv_import_started',
              'intelligence.offline_npm_osv_import_completed',
            ],
          },
        },
      }),
    ).toBe(2);
    expect(
      await prisma.advisoryRevisionSourceProvenance.count({
        where: { offlineAdvisoryImportBatchId: batch.id },
      }),
    ).toBe(0);
  });

  function writeDirectory(files: Record<string, unknown>): string {
    const directory = mkdtempSync(path.join(tmpdir(), `${PATH_TOKEN}-`));
    directories.push(directory);
    for (const [name, value] of Object.entries(files)) {
      const text = typeof value === 'string' ? value : JSON.stringify(value);
      writeFileSync(path.join(directory, name), text);
    }
    return directory;
  }
});

async function invoke(
  databaseUrl: string,
  directory: string,
  correlationId: string,
): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly body: Record<string, unknown>;
}> {
  const stdout = new MemoryStream();
  const stderr = new MemoryStream();
  const exitCode = await runOfflineNpmOsvImportCommand({
    argv: ['--directory', directory, '--correlation-id', correlationId],
    stdout,
    stderr,
    loadDatabaseUrl: () => databaseUrl,
    openBoundary: openOfflineNpmOsvImportCommandBoundary,
    readDirectory: readOfflineNpmImportDirectory,
  });
  return {
    exitCode,
    stdout: stdout.text,
    stderr: stderr.text,
    body: JSON.parse(stdout.text) as Record<string, unknown>,
  };
}

async function expectAuditShape(
  prisma: PrismaClient,
  correlationId: string,
  batchId: string,
  started: number,
  files: number,
  completed: number,
): Promise<void> {
  const audits = await prisma.auditEvent.findMany({
    where: { correlationId },
  });
  expect(
    audits.every((audit) => audit.actorType === 'system' && audit.organizationId === null),
  ).toBe(true);
  expect(audits.filter((audit) => audit.action.endsWith('_started'))).toHaveLength(started);
  expect(audits.filter((audit) => audit.action.endsWith('_imported'))).toHaveLength(files);
  expect(audits.filter((audit) => audit.action.endsWith('_completed'))).toHaveLength(completed);
  expect(audits.filter((audit) => audit.subjectId === batchId).length).toBeGreaterThan(0);
  expect(JSON.stringify(audits)).not.toContain('left-pad');
  expect(JSON.stringify(audits)).not.toContain(PATH_TOKEN);
  expect(JSON.stringify(audits)).not.toContain(FILE_NAME);
}

async function productWrites(prisma: PrismaClient): Promise<{
  readonly findings: number;
  readonly vulnerabilities: number;
  readonly bindings: number;
  readonly evidence: number;
  readonly outbox: number;
  readonly risk: number;
  readonly syncRuns: number;
}> {
  return {
    findings: await prisma.finding.count(),
    vulnerabilities: await prisma.vulnerability.count(),
    bindings: await prisma.advisoryVulnerabilityBinding.count(),
    evidence: await prisma.productMatchEvaluationEvidence.count(),
    outbox: await prisma.outboxEvent.count(),
    risk: await prisma.riskCalculation.count(),
    syncRuns: await prisma.vulnerabilitySyncRun.count(),
  };
}

function secretFree(text: string, directory: string): boolean {
  return (
    !text.includes(PATH_TOKEN) &&
    !text.includes(FILE_NAME) &&
    !text.includes(directory) &&
    !text.includes('left-pad')
  );
}
