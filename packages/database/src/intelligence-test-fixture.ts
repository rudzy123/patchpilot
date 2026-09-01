import { randomUUID } from 'node:crypto';

import type { PrismaClient } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  parseIntelligenceSnapshotObjectKey,
  type CalendarDate,
  type CanonicalCve,
  type KevNormalizedEntryRecord,
} from '@patchpilot/domain';

import {
  SHA_A,
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
} from './sbom-test-fixture.js';

export const KEV_PARSER_VERSION = '0.1.0';
export const KEV_NORMALIZATION_VERSION = '1';
export const KEV_OBJECT_KEY = 'kev-snapshot-opaque-internal-1';
export const KEV_SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const KEV_SHA_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
export const NOW = new Date('2026-09-01T12:00:00.000Z');
export const CATALOG_VERSION = '2026.09.01';

export function uniqueKevSha(): string {
  return `${randomUUID().replaceAll('-', '')}${randomUUID().replaceAll('-', '').slice(0, 32)}`;
}

export function kevObjectKey() {
  const parsed = parseIntelligenceSnapshotObjectKey(KEV_OBJECT_KEY);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export async function failInflightSyncRuns(prisma: PrismaClient): Promise<void> {
  const inflight = await prisma.vulnerabilitySyncRun.findMany({
    where: {
      state: { notIn: ['completed', 'not_modified', 'failed', 'quarantined'] },
    },
  });
  for (const run of inflight) {
    await prisma.vulnerabilitySyncRun.update({
      where: { id: run.id },
      data: {
        state: 'failed',
        startedAt: run.startedAt ?? NOW,
        completedAt: NOW,
        executionAttempt: Math.max(run.executionAttempt, 1),
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
  }
}

export async function createRequestedSyncRun(
  prisma: PrismaClient,
  input?: { id?: string; requestedAt?: Date },
) {
  return prisma.vulnerabilitySyncRun.create({
    data: {
      ...(input?.id === undefined ? {} : { id: input.id }),
      providerKey: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      state: 'requested',
      requestedAt: input?.requestedAt ?? NOW,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      correlationId: `corr-${randomUUID().slice(0, 8)}`,
    },
  });
}

export async function createFetchingSyncRun(prisma: PrismaClient, input?: { id?: string }) {
  return prisma.vulnerabilitySyncRun.create({
    data: {
      ...(input?.id === undefined ? {} : { id: input.id }),
      providerKey: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      state: 'fetching',
      stage: 'fetch',
      requestedAt: NOW,
      startedAt: NOW,
      executionAttempt: 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      correlationId: `corr-${randomUUID().slice(0, 8)}`,
    },
  });
}

export async function createSnapshot(
  prisma: PrismaClient,
  creatingSyncRunId: string,
  input?: { sha256?: string; byteLength?: number; objectKey?: string },
) {
  return prisma.vulnerabilityProviderSnapshot.create({
    data: {
      providerKey: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      responseSha256: input?.sha256 ?? uniqueKevSha(),
      byteLength: input?.byteLength ?? 2048,
      declaredContentType: 'application/json',
      detectedContentType: 'application/json',
      objectKey: input?.objectKey ?? KEV_OBJECT_KEY,
      retrievedAt: NOW,
      storedAt: NOW,
      creatingSyncRunId,
    },
  });
}

export async function createStagingGeneration(
  prisma: PrismaClient,
  input: { syncRunId: string; snapshotId: string; expectedEntryCount?: number },
) {
  return prisma.kevGeneration.create({
    data: {
      providerKey: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId: input.syncRunId,
      snapshotId: input.snapshotId,
      state: 'staging',
      expectedEntryCount: input.expectedEntryCount ?? 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      createdAt: NOW,
    },
  });
}

export async function seedZeroFindingBaseline(prisma: PrismaClient) {
  const org = await createOrg(prisma, `kev-find-${randomUUID().slice(0, 8)}`);
  const asset = await createAsset(prisma, org.id, 'baseline-asset');
  const sbom = await createSbom(prisma, {
    organizationId: org.id,
    assetId: asset.id,
    sha256: SHA_A,
    receivedAt: NOW,
  });
  const ingestion = await createProcessingIngestion(prisma, {
    organizationId: org.id,
    sbomId: sbom.id,
    assetId: asset.id,
  });
  const vulnerability = await prisma.vulnerability.create({
    data: { osvId: `PATCHPILOT-KEV-${randomUUID().slice(0, 8)}` },
  });
  const component = await prisma.component.create({
    data: {
      organizationId: org.id,
      identityKey: `npm|kev-${randomUUID().slice(0, 8)}`,
      ecosystem: 'npm',
      name: 'kev-baseline',
    },
  });
  const finding = await prisma.finding.create({
    data: {
      organizationId: org.id,
      assetId: asset.id,
      vulnerabilityId: vulnerability.id,
      componentId: component.id,
      firstObservedAt: NOW,
      lastObservedAt: NOW,
    },
  });
  const observation = await prisma.findingObservation.create({
    data: {
      organizationId: org.id,
      findingId: finding.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      result: 'present',
      method: 'exact_purl',
      observedAt: NOW,
      evidence: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
    },
  });
  return { org, finding, observation, vulnerability };
}

export function syntheticKevEntry(input: {
  generationId: string;
  snapshotId: string;
  ordinal: number;
  normalizedCve: string;
  knownRansomwareCampaignUse?: 'known' | 'unknown' | 'other';
  rawKnownRansomwareCampaignUse?: string | null;
  cwes?: readonly string[];
}): KevNormalizedEntryRecord {
  return {
    id: randomUUID(),
    generationId: input.generationId,
    snapshotId: input.snapshotId,
    ordinal: input.ordinal,
    normalizedCve: input.normalizedCve as CanonicalCve,
    vendorProject: 'Synthetic Vendor',
    product: 'Synthetic Product',
    vulnerabilityName: 'Synthetic KEV entry',
    dateAdded: '2024-01-15' as CalendarDate,
    shortDescription: 'Synthetic short description',
    requiredAction: 'Apply the vendor patch',
    dueDate: '2024-02-15' as CalendarDate,
    knownRansomwareCampaignUse: input.knownRansomwareCampaignUse ?? 'unknown',
    rawKnownRansomwareCampaignUse: input.rawKnownRansomwareCampaignUse ?? null,
    notes: null,
    cwes: input.cwes ?? ['CWE-79'],
    createdAt: NOW,
  };
}
