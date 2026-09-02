import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  CATALOG_VERSION,
  KEV_NORMALIZATION_VERSION,
  KEV_PARSER_VERSION,
  KEV_SHA,
  NOW,
  createFetchingSyncRun,
  createRequestedSyncRun,
  createSnapshot,
  createStagingGeneration,
  failInflightSyncRuns,
  uniqueKevSha,
} from './intelligence-test-fixture.js';

describe('session 9 KEV intelligence SQL constraints', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  beforeEach(async () => {
    await failInflightSyncRuns(prisma);
  });

  it('accepts a valid requested sync-run', async () => {
    await expect(createRequestedSyncRun(prisma)).resolves.toMatchObject({ state: 'requested' });
  });

  it('rejects requested with startedAt', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'requested',
          requestedAt: NOW,
          startedAt: NOW,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-1',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects fetching without startedAt', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'fetching',
          stage: 'fetch',
          requestedAt: NOW,
          executionAttempt: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-2',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects fetching attempt zero', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'fetching',
          stage: 'fetch',
          requestedAt: NOW,
          startedAt: NOW,
          executionAttempt: 0,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-3',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects retry_wait without nextAttemptAt', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'retry_wait',
          stage: 'fetch',
          requestedAt: NOW,
          startedAt: NOW,
          executionAttempt: 1,
          failureCategory: 'timeout',
          failureCode: 'connection_timeout',
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-4',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects retry_wait without failure pair', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'retry_wait',
          stage: 'fetch',
          requestedAt: NOW,
          startedAt: NOW,
          nextAttemptAt: NOW,
          executionAttempt: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-5',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects stored without snapshot', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'stored',
          stage: 'store_snapshot',
          requestedAt: NOW,
          startedAt: NOW,
          executionAttempt: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-6',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects staging without generation', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id);
    await expect(
      prisma.vulnerabilitySyncRun.update({
        where: { id: run.id },
        data: {
          state: 'staging',
          stage: 'stage_generation',
          snapshotId: snapshot.id,
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects completed without counts', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id);
    const generation = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
    });
    await expect(
      prisma.vulnerabilitySyncRun.update({
        where: { id: run.id },
        data: {
          state: 'completed',
          stage: 'finalize',
          snapshotId: snapshot.id,
          generationId: generation.id,
          completedAt: NOW,
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects completed with failure metadata', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id);
    const generation = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
    });
    await expect(
      prisma.vulnerabilitySyncRun.update({
        where: { id: run.id },
        data: {
          state: 'completed',
          stage: 'finalize',
          snapshotId: snapshot.id,
          generationId: generation.id,
          completedAt: NOW,
          acceptedEntryCount: 1,
          warningCount: 0,
          failureCategory: 'internal',
          failureCode: 'processing_failed',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects not_modified without prior generation', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'not_modified',
          stage: 'finalize',
          requestedAt: NOW,
          startedAt: NOW,
          completedAt: NOW,
          executionAttempt: 1,
          notModifiedReason: 'content_sha256_unchanged',
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-7',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects not_modified with a new snapshot', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
    const generation = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
    });
    await expect(
      prisma.vulnerabilitySyncRun.update({
        where: { id: run.id },
        data: {
          state: 'not_modified',
          stage: 'finalize',
          completedAt: NOW,
          snapshotId: snapshot.id,
          priorAcceptedGenerationId: generation.id,
          notModifiedReason: 'content_sha256_unchanged',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects failed without failure metadata', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'failed',
          requestedAt: NOW,
          startedAt: NOW,
          completedAt: NOW,
          executionAttempt: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-8',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects quarantined without failure metadata', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'quarantined',
          requestedAt: NOW,
          startedAt: NOW,
          completedAt: NOW,
          executionAttempt: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-9',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects completedAt before startedAt', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'failed',
          requestedAt: NOW,
          startedAt: NOW,
          completedAt: new Date('2026-08-01T00:00:00.000Z'),
          executionAttempt: 1,
          failureCategory: 'internal',
          failureCode: 'processing_failed',
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-10',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid parser labels', async () => {
    await expect(
      prisma.vulnerabilitySyncRun.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          state: 'requested',
          requestedAt: NOW,
          parserVersion: '../escape',
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          correlationId: 'corr-11',
        },
      }),
    ).rejects.toThrow();
  });

  it('accepts a valid snapshot and rejects uppercase, malformed, zero-length, and URL object keys', async () => {
    const run = await createRequestedSyncRun(prisma);
    await expect(createSnapshot(prisma, run.id, { sha256: KEV_SHA })).resolves.toMatchObject({
      responseSha256: KEV_SHA,
    });
    await expect(createSnapshot(prisma, run.id, { sha256: 'A'.repeat(64) })).rejects.toThrow();
    await expect(createSnapshot(prisma, run.id, { sha256: 'abc' })).rejects.toThrow();
    await expect(createSnapshot(prisma, run.id, { byteLength: 0 })).rejects.toThrow();
    await expect(
      createSnapshot(prisma, run.id, { objectKey: 'https://example.invalid/object' }),
    ).rejects.toThrow();
  });

  it('reuses the snapshot natural key and rejects UPDATE and DELETE', async () => {
    const firstRun = await createRequestedSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, firstRun.id, {
      sha256: 'c'.repeat(64),
    });
    await failInflightSyncRuns(prisma);
    const secondRun = await createRequestedSyncRun(prisma);
    await expect(
      createSnapshot(prisma, secondRun.id, { sha256: 'c'.repeat(64) }),
    ).rejects.toThrow();
    await expect(
      prisma.vulnerabilityProviderSnapshot.update({
        where: { id: snapshot.id },
        data: { byteLength: 9 },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.vulnerabilityProviderSnapshot.delete({ where: { id: snapshot.id } }),
    ).rejects.toThrow();
  });

  it('enforces generation state timestamps, counts, and the 8192 ceiling', async () => {
    const stagingRun = await createFetchingSyncRun(prisma);
    const stagingSnapshot = await createSnapshot(prisma, stagingRun.id, {
      sha256: uniqueKevSha(),
    });
    const staging = await createStagingGeneration(prisma, {
      syncRunId: stagingRun.id,
      snapshotId: stagingSnapshot.id,
    });
    await expect(
      prisma.kevGeneration.update({
        where: { id: staging.id },
        data: { state: 'complete' },
      }),
    ).rejects.toThrow();

    await failInflightSyncRuns(prisma);
    const mismatchRun = await createFetchingSyncRun(prisma);
    const mismatchSnapshot = await createSnapshot(prisma, mismatchRun.id, {
      sha256: uniqueKevSha(),
    });
    const mismatch = await createStagingGeneration(prisma, {
      syncRunId: mismatchRun.id,
      snapshotId: mismatchSnapshot.id,
    });
    await expect(
      prisma.kevGeneration.update({
        where: { id: mismatch.id },
        data: {
          state: 'complete',
          completedAt: NOW,
          catalogVersion: CATALOG_VERSION,
          catalogReleasedAt: NOW,
        },
      }),
    ).rejects.toThrow();

    await failInflightSyncRuns(prisma);
    const activeRun = await createFetchingSyncRun(prisma);
    const activeSnapshot = await createSnapshot(prisma, activeRun.id, {
      sha256: uniqueKevSha(),
    });
    const active = await createStagingGeneration(prisma, {
      syncRunId: activeRun.id,
      snapshotId: activeSnapshot.id,
    });
    await expect(
      prisma.kevGeneration.update({
        where: { id: active.id },
        data: {
          state: 'active',
          completedAt: NOW,
          stagedEntryCount: 1,
          catalogVersion: CATALOG_VERSION,
          catalogReleasedAt: NOW,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevGeneration.update({
        where: { id: active.id },
        data: {
          state: 'active',
          completedAt: NOW,
          activatedAt: NOW,
          supersededAt: NOW,
          stagedEntryCount: 1,
          catalogVersion: CATALOG_VERSION,
          catalogReleasedAt: NOW,
        },
      }),
    ).rejects.toThrow();

    await failInflightSyncRuns(prisma);
    const supersededRun = await createFetchingSyncRun(prisma);
    const supersededSnapshot = await createSnapshot(prisma, supersededRun.id, {
      sha256: uniqueKevSha(),
    });
    const superseded = await createStagingGeneration(prisma, {
      syncRunId: supersededRun.id,
      snapshotId: supersededSnapshot.id,
    });
    await expect(
      prisma.kevGeneration.update({
        where: { id: superseded.id },
        data: { state: 'superseded', completedAt: NOW, stagedEntryCount: 1 },
      }),
    ).rejects.toThrow();

    await failInflightSyncRuns(prisma);
    const abandonedRun = await createFetchingSyncRun(prisma);
    const abandonedSnapshot = await createSnapshot(prisma, abandonedRun.id, {
      sha256: uniqueKevSha(),
    });
    const abandoned = await createStagingGeneration(prisma, {
      syncRunId: abandonedRun.id,
      snapshotId: abandonedSnapshot.id,
    });
    await expect(
      prisma.kevGeneration.update({
        where: { id: abandoned.id },
        data: { state: 'abandoned' },
      }),
    ).rejects.toThrow();

    await failInflightSyncRuns(prisma);
    const ceilingRun = await createFetchingSyncRun(prisma);
    const ceilingSnapshot = await createSnapshot(prisma, ceilingRun.id, {
      sha256: uniqueKevSha(),
    });
    await expect(
      createStagingGeneration(prisma, {
        syncRunId: ceilingRun.id,
        snapshotId: ceilingSnapshot.id,
        expectedEntryCount: 8193,
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevGeneration.create({
        data: {
          providerKey: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          syncRunId: ceilingRun.id,
          snapshotId: ceilingSnapshot.id,
          parserVersion: '../bad',
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          expectedEntryCount: 1,
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces entry CVE, date, text, ransomware, and uniqueness rules', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
    const generation = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
      expectedEntryCount: 2,
    });
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 0,
          normalizedCve: 'CVE-2024-12345',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).resolves.toMatchObject({ normalizedCve: 'CVE-2024-12345' });
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-12',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'cve-2024-1',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-99999',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-13-40',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-99998',
          vendorProject: 'x'.repeat(20000),
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-11111',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'known',
          rawKnownRansomwareCampaignUse: 'Known',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-11112',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
          rawKnownRansomwareCampaignUse: 'Unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-11113',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'other',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 0,
          normalizedCve: 'CVE-2024-22222',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: generation.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-12345',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).rejects.toThrow();
    await failInflightSyncRuns(prisma);
    const other = await createFetchingSyncRun(prisma);
    const otherSnapshot = await createSnapshot(prisma, other.id, { sha256: uniqueKevSha() });
    const otherGeneration = await createStagingGeneration(prisma, {
      syncRunId: other.id,
      snapshotId: otherSnapshot.id,
    });
    await expect(
      prisma.kevEntry.create({
        data: {
          generationId: otherGeneration.id,
          ordinal: 0,
          normalizedCve: 'CVE-2024-12345',
          vendorProject: 'Vendor',
          product: 'Product',
          vulnerabilityName: 'Name',
          dateAdded: '2024-01-15',
          shortDescription: 'desc',
          requiredAction: 'patch',
          dueDate: '2024-02-15',
          knownRansomwareCampaignUse: 'unknown',
        },
      }),
    ).resolves.toMatchObject({ normalizedCve: 'CVE-2024-12345' });
  });

  it('enforces CWE canonical form, ordinal bound, and uniqueness', async () => {
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
    const generation = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
    });
    const entry = await prisma.kevEntry.create({
      data: {
        generationId: generation.id,
        ordinal: 0,
        normalizedCve: 'CVE-2024-33333',
        vendorProject: 'Vendor',
        product: 'Product',
        vulnerabilityName: 'Name',
        dateAdded: '2024-01-15',
        shortDescription: 'desc',
        requiredAction: 'patch',
        dueDate: '2024-02-15',
        knownRansomwareCampaignUse: 'unknown',
      },
    });
    await expect(
      prisma.kevEntryCwe.create({
        data: { entryId: entry.id, ordinal: 0, normalizedCwe: 'CWE-79' },
      }),
    ).resolves.toMatchObject({ normalizedCwe: 'CWE-79' });
    await expect(
      prisma.kevEntryCwe.create({
        data: { entryId: entry.id, ordinal: 1, normalizedCwe: 'cwe-79' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntryCwe.create({
        data: { entryId: entry.id, ordinal: 16, normalizedCwe: 'CWE-89' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntryCwe.create({
        data: { entryId: entry.id, ordinal: 1, normalizedCwe: 'CWE-79' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.kevEntryCwe.create({
        data: { entryId: entry.id, ordinal: 0, normalizedCwe: 'CWE-89' },
      }),
    ).rejects.toThrow();
  });

  it('allows a null active pointer and rejects non-active KEV or OSV pointers', async () => {
    const kev = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(kev.activeGenerationId).toBeNull();
    const run = await createFetchingSyncRun(prisma);
    const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
    const staging = await createStagingGeneration(prisma, {
      syncRunId: run.id,
      snapshotId: snapshot.id,
    });
    await expect(
      prisma.intelligenceSource.update({
        where: { id: kev.id },
        data: { activeGenerationId: staging.id },
      }),
    ).rejects.toThrow();
    await prisma.kevEntry.create({
      data: {
        generationId: staging.id,
        ordinal: 0,
        normalizedCve: 'CVE-2024-44444',
        vendorProject: 'Vendor',
        product: 'Product',
        vulnerabilityName: 'Name',
        dateAdded: '2024-01-15',
        shortDescription: 'desc',
        requiredAction: 'patch',
        dueDate: '2024-02-15',
        knownRansomwareCampaignUse: 'unknown',
      },
    });
    await prisma.kevGeneration.update({
      where: { id: staging.id },
      data: {
        state: 'complete',
        completedAt: NOW,
        stagedEntryCount: 1,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
      },
    });
    await expect(
      prisma.intelligenceSource.update({
        where: { id: kev.id },
        data: { activeGenerationId: staging.id },
      }),
    ).rejects.toThrow();
    await failInflightSyncRuns(prisma);
    const abandonRun = await createFetchingSyncRun(prisma);
    const abandonSnapshot = await createSnapshot(prisma, abandonRun.id, {
      sha256: uniqueKevSha(),
    });
    const abandoned = await createStagingGeneration(prisma, {
      syncRunId: abandonRun.id,
      snapshotId: abandonSnapshot.id,
    });
    await prisma.kevGeneration.update({
      where: { id: abandoned.id },
      data: { state: 'abandoned', abandonedAt: NOW },
    });
    await expect(
      prisma.intelligenceSource.update({
        where: { id: kev.id },
        data: { activeGenerationId: abandoned.id },
      }),
    ).rejects.toThrow();
    await prisma.kevGeneration.update({
      where: { id: staging.id },
      data: { state: 'active', activatedAt: NOW },
    });
    await expect(
      prisma.intelligenceSource.update({
        where: { id: kev.id },
        data: { activeGenerationId: staging.id },
      }),
    ).resolves.toMatchObject({ activeGenerationId: staging.id });
    const osv = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'osv' },
    });
    await expect(
      prisma.intelligenceSource.update({
        where: { id: osv.id },
        data: { activeGenerationId: staging.id },
      }),
    ).rejects.toThrow();
  });
});
