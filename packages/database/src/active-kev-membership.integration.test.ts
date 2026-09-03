import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  createQueryActiveKevMembershipUseCase,
  parseExactCanonicalCve,
  type ActiveKevMembershipReadPort,
  type CanonicalCve,
  type Result,
} from '@patchpilot/domain';

import { createActiveKevMembershipPersistence } from './active-kev-membership.js';
import type { PrismaClientLike } from './guards.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  CATALOG_VERSION,
  NOW,
  createFetchingSyncRun,
  createSnapshot,
  createStagingGeneration,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
  uniqueKevSha,
} from './intelligence-test-fixture.js';
import { SHA_A, SHA_B } from './sbom-test-fixture.js';

const CVE_A = 'CVE-1900-00001';
const CVE_B = 'CVE-1900-00002';
const CVE_C = 'CVE-1900-00003';
const PREFIX_NEAR = 'CVE-1900-000011';
const THRESHOLD = 259_200;

const FORBIDDEN_PUBLIC_FIELDS = [
  'generationId',
  'entryId',
  'snapshotId',
  'syncRunId',
  'objectKey',
  'bucket',
  'providerUrl',
  'sourceUrl',
  'etag',
  'etagHash',
  'responseSha256',
  'parserVersion',
  'normalizationVersion',
  'ordinal',
  'vendorProject',
  'product',
  'vulnerabilityName',
  'shortDescription',
  'requiredAction',
  'notes',
  'cwes',
  'rawKnownRansomwareCampaignUse',
  'title',
  'Synthetic Vendor',
];

function requireCve(value: string): CanonicalCve {
  const parsed = parseExactCanonicalCve(value);
  if (!parsed.ok) {
    throw new Error(`expected ${value} to be canonical`);
  }
  return parsed.value;
}

function requireOk<T>(result: Result<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.error.code} ${result.error.message}`);
  }
  return result.value;
}

async function createKevEntry(
  prisma: PrismaClient,
  input: { generationId: string; ordinal: number; normalizedCve: string },
) {
  return prisma.kevEntry.create({
    data: {
      generationId: input.generationId,
      ordinal: input.ordinal,
      normalizedCve: input.normalizedCve,
      vendorProject: 'Synthetic Vendor',
      product: 'Synthetic Product',
      vulnerabilityName: 'Synthetic KEV entry',
      dateAdded: '2024-01-15',
      shortDescription: 'Synthetic short description',
      requiredAction: 'Apply the vendor patch',
      dueDate: '2024-02-15',
      knownRansomwareCampaignUse: 'known',
    },
  });
}

async function completeGeneration(
  prisma: PrismaClient,
  generationId: string,
  input: { catalogVersion: string; expectedEntryCount: number; catalogReleasedAt?: Date },
) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: {
      state: 'complete',
      completedAt: NOW,
      stagedEntryCount: input.expectedEntryCount,
      catalogVersion: input.catalogVersion,
      catalogReleasedAt: input.catalogReleasedAt ?? NOW,
    },
  });
}

async function activateGeneration(prisma: PrismaClient, generationId: string) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: { state: 'active', activatedAt: NOW },
  });
}

async function supersedeGeneration(prisma: PrismaClient, generationId: string) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: { state: 'superseded', supersededAt: NOW },
  });
}

async function clearActivePointer(prisma: PrismaClient) {
  await prisma.intelligenceSource.update({
    where: { providerKey: 'cisa_kev' },
    data: {
      activeGenerationId: null,
      lastSuccessfulSyncAt: null,
      lastAttemptAt: null,
    },
  });
}

async function pointAtGeneration(
  prisma: PrismaClient,
  generationId: string,
  lastSuccessfulSyncAt: Date,
) {
  await prisma.intelligenceSource.update({
    where: { providerKey: 'cisa_kev' },
    data: {
      activeGenerationId: generationId,
      lastSuccessfulSyncAt,
      lastAttemptAt: lastSuccessfulSyncAt,
    },
  });
}

async function seedCatalog(
  prisma: PrismaClient,
  input: {
    state: 'staging' | 'complete' | 'active';
    catalogVersion?: string;
    cves: readonly string[];
    lastSuccessfulSyncAt?: Date;
  },
) {
  const run = await createFetchingSyncRun(prisma);
  const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
  const generation = await createStagingGeneration(prisma, {
    syncRunId: run.id,
    snapshotId: snapshot.id,
    expectedEntryCount: input.cves.length,
  });
  for (const [ordinal, normalizedCve] of input.cves.entries()) {
    await createKevEntry(prisma, {
      generationId: generation.id,
      ordinal,
      normalizedCve,
    });
  }
  if (input.state !== 'staging') {
    await completeGeneration(prisma, generation.id, {
      catalogVersion: input.catalogVersion ?? CATALOG_VERSION,
      expectedEntryCount: input.cves.length,
    });
  }
  if (input.state === 'active') {
    await activateGeneration(prisma, generation.id);
    await pointAtGeneration(prisma, generation.id, input.lastSuccessfulSyncAt ?? NOW);
  }
  await prisma.vulnerabilitySyncRun.update({
    where: { id: run.id },
    data: {
      state: 'failed',
      startedAt: NOW,
      completedAt: NOW,
      executionAttempt: 1,
      failureCategory: 'internal',
      failureCode: 'processing_failed',
      nextAttemptAt: null,
    },
  });
  return generation;
}

type CountSnapshot = {
  vulnerability: number;
  alias: number;
  sourceRecord: number;
  identity: number;
  link: number;
  finding: number;
  observation: number;
  evidence: number;
  riskCalculation: number;
  component: number;
  occurrence: number;
  asset: number;
  sbom: number;
  outbox: number;
  job: number;
  audit: number;
};

async function captureCounts(prisma: PrismaClient): Promise<CountSnapshot> {
  return {
    vulnerability: await prisma.vulnerability.count(),
    alias: await prisma.vulnerabilityAlias.count(),
    sourceRecord: await prisma.vulnerabilitySourceRecord.count(),
    identity: await prisma.cveIdentity.count(),
    link: await prisma.vulnerabilityCveIdentityLink.count(),
    finding: await prisma.finding.count(),
    observation: await prisma.findingObservation.count(),
    evidence: await prisma.evidence.count(),
    riskCalculation: await prisma.riskCalculation.count(),
    component: await prisma.component.count(),
    occurrence: await prisma.componentOccurrence.count(),
    asset: await prisma.asset.count(),
    sbom: await prisma.sbom.count(),
    outbox: await prisma.outboxEvent.count(),
    job: await prisma.backgroundJob.count(),
    audit: await prisma.auditEvent.count(),
  };
}

describe('active KEV membership persistence', { timeout: 120_000 }, () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let port: ActiveKevMembershipReadPort;
  let baseline: {
    vulnerabilityId: string;
    findingId: string;
    identityCount: number;
  };

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    port = createActiveKevMembershipPersistence(prisma);
    const seeded = await seedZeroFindingBaseline(prisma);
    await prisma.vulnerabilityAlias.create({
      data: {
        vulnerabilityId: seeded.vulnerability.id,
        alias: `PATCHPILOT-ALIAS-${randomUUID().slice(0, 8)}`,
      },
    });
    await prisma.vulnerabilitySourceRecord.create({
      data: {
        vulnerabilityId: seeded.vulnerability.id,
        source: 'osv',
        sourceIdentity: seeded.vulnerability.osvId,
        retrievedAt: NOW,
        payloadSha256: SHA_A,
        normalizationVersion: 'test-1',
        normalized: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          summary: 'synthetic',
          severity: null,
          affectedPackages: [],
        },
      },
    });
    await prisma.componentOccurrence.create({
      data: {
        organizationId: seeded.org.id,
        assetId: seeded.finding.assetId,
        sbomId: seeded.observation.sbomId,
        sbomIngestionId: seeded.observation.sbomIngestionId,
        componentId: seeded.finding.componentId,
        version: '1.0.0',
      },
    });
    const policy = await prisma.riskPolicy.create({
      data: {
        organizationId: seeded.org.id,
        scope: 'organization',
        policyKey: `patchpilot.synthetic.kev-mem.${randomUUID().slice(0, 8)}`,
        name: 'Synthetic membership baseline',
        version: 1,
        status: 'draft',
        policySchemaVersion: 1,
        definition: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          policyKey: 'synthetic',
          factorCatalog: [],
          weights: {},
        },
      },
    });
    await prisma.riskCalculation.create({
      data: {
        organizationId: seeded.org.id,
        findingId: seeded.finding.id,
        riskPolicyId: policy.id,
        policyVersion: 1,
        policyDefinitionSha256: SHA_A,
        calculatedAt: NOW,
        factors: { schemaVersion: JSON_SCHEMA_VERSION_V1, factors: [] },
        result: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          priority: 10,
          priorityBand: 'P4',
          dueDateRecommendationDays: 180,
          escalationRecommendation: false,
        },
        calculationEngineVersion: 'test-1',
        calculationReason: 'initial',
        inputFingerprint: SHA_B,
      },
    });
    await prisma.evidence.create({
      data: {
        organizationId: seeded.org.id,
        kind: 'compensating_control',
        findingId: seeded.finding.id,
        metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
      },
    });
    await prisma.outboxEvent.create({
      data: {
        organizationId: seeded.org.id,
        aggregateType: 'asset',
        aggregateId: seeded.finding.assetId,
        eventType: 'asset.created',
        eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
        payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, ids: {}, metadata: {} },
        dedupeKey: `kev-membership-baseline:${randomUUID()}`,
      },
    });
    await prisma.backgroundJob.create({
      data: {
        organizationId: seeded.org.id,
        jobType: 'sbom.ingest',
        status: 'pending',
      },
    });
    baseline = {
      vulnerabilityId: seeded.vulnerability.id,
      findingId: seeded.finding.id,
      identityCount: await prisma.cveIdentity.count(),
    };
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
    await clearActivePointer(prisma);
    await prisma.kevGeneration.updateMany({
      where: { state: 'active' },
      data: { state: 'superseded', supersededAt: NOW },
    });
  });

  async function expectZeroFinding(before: CountSnapshot): Promise<void> {
    expect(await captureCounts(prisma)).toEqual(before);
    expect(
      await prisma.vulnerability.findUnique({ where: { id: baseline.vulnerabilityId } }),
    ).toMatchObject({
      id: baseline.vulnerabilityId,
    });
    expect(await prisma.finding.findUnique({ where: { id: baseline.findingId } })).toMatchObject({
      id: baseline.findingId,
    });
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
    expect(await prisma.cveIdentity.count()).toBe(baseline.identityCount);
  }

  it('returns source_missing when the CISA IntelligenceSource row is absent', async () => {
    await prisma.intelligenceSource.delete({ where: { providerKey: 'cisa_kev' } });
    try {
      const before = await captureCounts(prisma);
      const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
      expect(result).toEqual({ ok: true, value: { kind: 'source_missing' } });
      await expectZeroFinding(before);
    } finally {
      await prisma.intelligenceSource.create({
        data: {
          providerKey: 'cisa_kev',
          state: 'disabled',
          config: { schemaVersion: 1, refreshIntervalSeconds: null, endpointAllowlist: [] },
        },
      });
    }
  });

  it('returns no_active_generation when the pointer is null', async () => {
    const before = await captureCounts(prisma);
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(result).toEqual({ ok: true, value: { kind: 'no_active_generation' } });
    await expectZeroFinding(before);
  });

  it('returns absent for an active generation without a matching entry', async () => {
    await seedCatalog(prisma, { state: 'active', cves: [CVE_B] });
    const before = await captureCounts(prisma);
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(result.ok && result.value.kind).toBe('absent');
    await expectZeroFinding(before);
  });

  it('returns present for an exact matching active entry and omits provider text', async () => {
    await seedCatalog(prisma, { state: 'active', cves: [CVE_A] });
    const before = await captureCounts(prisma);
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    const snapshot = requireOk(result, 'listed');
    expect(snapshot.kind).toBe('present');
    if (snapshot.kind === 'present') {
      expect(snapshot.knownRansomwareCampaignUse).toBe('known');
      const serialized = JSON.stringify(snapshot);
      for (const field of FORBIDDEN_PUBLIC_FIELDS) {
        expect(serialized).not.toContain(field);
      }
    }
    const useCase = createQueryActiveKevMembershipUseCase({
      membership: port,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const listed = requireOk(
      await useCase.queryActiveKevMembership({ cve: CVE_A }),
      'public listed',
    );
    expect(listed.status).toBe('listedInActiveKev');
    if (listed.status === 'listedInActiveKev') {
      expect(listed.freshness).toBe('current');
      expect(JSON.stringify(listed)).not.toContain('Synthetic Vendor');
      expect(listed).not.toHaveProperty('requiredAction');
      expect(listed).not.toHaveProperty('generationId');
    }
    await expectZeroFinding(before);
  });

  it('rejects lowercase and whitespace CVEs before SQL', async () => {
    await seedCatalog(prisma, { state: 'active', cves: [CVE_A] });
    const before = await captureCounts(prisma);
    const lowercase = await port.loadActiveKevMembershipSnapshot('cve-1900-00001' as CanonicalCve);
    expect(lowercase.ok).toBe(false);
    if (!lowercase.ok) {
      expect(lowercase.error.code).toBe('validation');
    }
    const whitespace = await port.loadActiveKevMembershipSnapshot(` ${CVE_A}` as CanonicalCve);
    expect(whitespace.ok).toBe(false);
    await expectZeroFinding(before);
  });

  it('ignores matching entries in staging, complete, and superseded generations', async () => {
    await seedCatalog(prisma, { state: 'staging', cves: [CVE_A] });
    await seedCatalog(prisma, { state: 'complete', cves: [CVE_A], catalogVersion: '2099.02.02' });
    const superseded = await seedCatalog(prisma, { state: 'active', cves: [CVE_A] });
    await clearActivePointer(prisma);
    await supersedeGeneration(prisma, superseded.id);
    await seedCatalog(prisma, { state: 'active', cves: [CVE_B], catalogVersion: '2099.03.03' });
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(result.ok && result.value.kind).toBe('absent');
    const listedB = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_B));
    expect(listedB.ok && listedB.value.kind).toBe('present');
  });

  it('switches reader authority to the newly activated generation', async () => {
    const first = await seedCatalog(prisma, { state: 'active', cves: [CVE_A, CVE_C] });
    const listedFirst = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(listedFirst.ok && listedFirst.value.kind).toBe('present');
    const second = await seedCatalog(prisma, {
      state: 'complete',
      cves: [CVE_B],
      catalogVersion: '2099.04.04',
    });
    const before = await captureCounts(prisma);
    await clearActivePointer(prisma);
    await supersedeGeneration(prisma, first.id);
    await activateGeneration(prisma, second.id);
    await pointAtGeneration(prisma, second.id, NOW);
    const removed = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(removed.ok && removed.value.kind).toBe('absent');
    if (removed.ok && removed.value.kind === 'absent') {
      expect(removed.value.catalogVersion).toBe('2099.04.04');
    }
    const listedSecond = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_B));
    expect(listedSecond.ok && listedSecond.value.kind).toBe('present');
    await expectZeroFinding(before);
  });

  it('uses exact equality rather than prefix matching', async () => {
    await seedCatalog(prisma, { state: 'active', cves: [CVE_A] });
    const near = await port.loadActiveKevMembershipSnapshot(requireCve(PREFIX_NEAR));
    expect(near.ok && near.value.kind).toBe('absent');
    const exact = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(exact.ok && exact.value.kind).toBe('present');
  });

  it('fails closed when the pointed generation is no longer active', async () => {
    const generation = await seedCatalog(prisma, { state: 'active', cves: [CVE_A] });
    await supersedeGeneration(prisma, generation.id);
    const before = await captureCounts(prisma);
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(result).toEqual({
      ok: true,
      value: { kind: 'inconsistent_active_generation' },
    });
    await expectZeroFinding(before);
  });

  it('keeps the query bounded and does not scan or count all entries', async () => {
    const source = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'active-kev-membership.ts'),
      'utf8',
    );
    expect(source).toContain('take: 2');
    expect(source).toContain('where: { normalizedCve: parsed.value }');
    expect(source).not.toContain('listActiveEntries');
    expect(source).not.toContain('.count(');
    expect(source).not.toContain('.aggregate(');
    await seedCatalog(prisma, { state: 'active', cves: [CVE_A, CVE_B, CVE_C] });
    const result = await port.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(result.ok && result.value.kind).toBe('present');
  });

  it('maps stale and disabled-with-history through the use case without Finding writes', async () => {
    await seedCatalog(prisma, { state: 'active', cves: [CVE_A], lastSuccessfulSyncAt: NOW });
    const before = await captureCounts(prisma);
    const stale = createQueryActiveKevMembershipUseCase({
      membership: port,
      kevEnabled: true,
      staleThresholdSeconds: 60,
      now: () => new Date(NOW.getTime() + 60_001),
    });
    const staleResult = requireOk(await stale.queryActiveKevMembership({ cve: CVE_A }), 'stale');
    expect(staleResult.status).toBe('listedInActiveKev');
    if (staleResult.status === 'listedInActiveKev') {
      expect(staleResult.freshness).toBe('stale');
    }
    const disabled = createQueryActiveKevMembershipUseCase({
      membership: port,
      kevEnabled: false,
      staleThresholdSeconds: 60,
      now: () => NOW,
    });
    const disabledResult = requireOk(
      await disabled.queryActiveKevMembership({ cve: CVE_B }),
      'disabled absent',
    );
    expect(disabledResult).toMatchObject({
      status: 'absent',
      freshness: 'disabled_with_history',
    });
    await expectZeroFinding(before);
  });

  it('does not mutate persistence on invalid input or sanitized failures', async () => {
    const before = await captureCounts(prisma);
    const invalid = createQueryActiveKevMembershipUseCase({
      membership: port,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const invalidResult = await invalid.queryActiveKevMembership({ cve: 'cve-1900-00001' });
    expect(invalidResult.ok).toBe(false);
    const broken = createActiveKevMembershipPersistence({
      intelligenceSource: {
        findUnique: async () => {
          throw new Error('connect ECONNREFUSED postgresql://secret');
        },
      },
    } as unknown as PrismaClientLike);
    const failed = await broken.loadActiveKevMembershipSnapshot(requireCve(CVE_A));
    expect(failed.ok).toBe(false);
    if (!failed.ok) {
      expect(failed.error.message).toBe('Active KEV membership is temporarily unavailable.');
      expect(failed.error.message).not.toMatch(/ECONNREFUSED|postgresql|secret/i);
    }
    await expectZeroFinding(before);
  });
});
