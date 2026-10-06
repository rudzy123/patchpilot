import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  CURRENT_SBOM_NORMALIZATION_VERSION,
  HISTORICAL_SBOM_NORMALIZATION_VERSION,
} from '@patchpilot/domain';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createSbomPersistence } from './sbom-persistence.js';
import {
  PARSER_VERSION,
  SHA_A,
  SHA_B,
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  graphOf,
  newCorrelationId,
  resolvedComponent,
} from './sbom-test-fixture.js';

describe('multi-version component occurrence persistence', () => {
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

  it('preserves distinct versions, replays exactly, and leaves historical graphs unchanged', async () => {
    const org = await createOrg(prisma, `mv-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'mv-asset');
    const historicalSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-10-05T12:00:00.000Z'),
    });
    const historical = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: historicalSbom.id,
      assetId: asset.id,
    });
    const versionOne = resolvedComponent({
      name: 'left-pad',
      bomRef: 'pad-1',
      version: '1.0.0',
    });
    const adapters = createSbomPersistence(prisma);
    const historicalPersist = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: historicalSbom.id,
      sbomIngestionId: historical.id,
      graph: graphOf([versionOne], [], 'no_dependencies'),
      correlationId: newCorrelationId(),
    });
    expect(historicalPersist.ok).toBe(true);

    const historicalRow = await prisma.sbomIngestion.findUniqueOrThrow({
      where: { id: historical.id },
    });
    const historicalOccurrence = await prisma.componentOccurrence.findFirstOrThrow({
      where: { organizationId: org.id, sbomIngestionId: historical.id },
    });
    expect(historicalRow.normalizationVersion).toBe(HISTORICAL_SBOM_NORMALIZATION_VERSION);
    expect(historicalRow.state).toBe('completed');
    expect(historicalOccurrence.version).toBe('1.0.0');
    expect(historicalOccurrence.versionKnown).toBe(true);

    const versionTwo = resolvedComponent({
      name: 'left-pad',
      bomRef: 'pad-2',
      version: '2.0.0',
    });
    const ignoredRewrite = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: historicalSbom.id,
      sbomIngestionId: historical.id,
      graph: graphOf(
        [versionOne, versionTwo],
        [{ fromBomRef: 'pad-2', toBomRef: 'pad-1', relationshipType: 'depends_on' }],
        'complete',
      ),
      correlationId: newCorrelationId(),
    });
    expect(ignoredRewrite.ok).toBe(true);
    const historicalAfter = await prisma.sbomIngestion.findUniqueOrThrow({
      where: { id: historical.id },
    });
    const historicalOccurrenceAfter = await prisma.componentOccurrence.findFirstOrThrow({
      where: { id: historicalOccurrence.id },
    });
    expect(historicalAfter.normalizationVersion).toBe(HISTORICAL_SBOM_NORMALIZATION_VERSION);
    expect(historicalAfter.completedAt).toEqual(historicalRow.completedAt);
    expect(historicalAfter.updatedAt).toEqual(historicalRow.updatedAt);
    expect(historicalAfter.componentCount).toBe(1);
    expect(historicalOccurrenceAfter.version).toBe('1.0.0');
    expect(historicalOccurrenceAfter.createdAt).toEqual(historicalOccurrence.createdAt);
    expect(
      await prisma.componentOccurrence.count({
        where: { organizationId: org.id, sbomIngestionId: historical.id },
      }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: org.id, action: 'sbom.ingestion.completed' },
      }),
    ).toBe(1);

    const currentSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_B,
      receivedAt: new Date('2026-10-05T13:00:00.000Z'),
    });
    const current = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: currentSbom.id,
        assetId: asset.id,
        parserVersion: PARSER_VERSION,
        normalizationVersion: CURRENT_SBOM_NORMALIZATION_VERSION,
        state: 'processing',
        stage: 'persist_graph',
        startedAt: new Date('2026-10-05T13:00:00.000Z'),
      },
    });
    const currentGraph = graphOf(
      [versionOne, versionTwo],
      [{ fromBomRef: 'pad-2', toBomRef: 'pad-1', relationshipType: 'depends_on' }],
      'complete',
    );
    currentGraph.normalizationVersion = CURRENT_SBOM_NORMALIZATION_VERSION;
    const persisted = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: currentSbom.id,
      sbomIngestionId: current.id,
      graph: currentGraph,
      correlationId: newCorrelationId(),
    });
    expect(persisted.ok).toBe(true);

    const occurrences = await prisma.componentOccurrence.findMany({
      where: { organizationId: org.id, sbomIngestionId: current.id },
      orderBy: { version: 'asc' },
    });
    expect(occurrences.map((row) => row.version)).toEqual(['1.0.0', '2.0.0']);
    expect(occurrences.map((row) => row.bomRef)).toEqual(['pad-1', 'pad-2']);
    expect(new Set(occurrences.map((row) => row.componentId)).size).toBe(1);
    const storedOne = occurrences[0];
    const storedTwo = occurrences[1];
    if (storedOne === undefined || storedTwo === undefined) {
      throw new Error('expected two version occurrences');
    }
    const component = await prisma.component.findUniqueOrThrow({
      where: { id: storedOne.componentId },
    });
    expect(component.identityKey).toBe(versionOne.identityKey);
    expect(component.identityKey).not.toContain('@');

    const edge = await prisma.dependencyRelationship.findFirstOrThrow({
      where: { organizationId: org.id, sbomIngestionId: current.id },
    });
    const from = occurrences.find((row) => row.id === edge.fromOccurrenceId);
    const to = occurrences.find((row) => row.id === edge.toOccurrenceId);
    expect(from?.version).toBe('2.0.0');
    expect(to?.version).toBe('1.0.0');

    const completedCurrent = await prisma.sbomIngestion.findUniqueOrThrow({
      where: { id: current.id },
    });
    const replay = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: currentSbom.id,
      sbomIngestionId: current.id,
      graph: currentGraph,
      correlationId: newCorrelationId(),
    });
    expect(replay.ok).toBe(true);
    const replayed = await prisma.componentOccurrence.findMany({
      where: { organizationId: org.id, sbomIngestionId: current.id },
      orderBy: { version: 'asc' },
    });
    expect(replayed.map((row) => row.id)).toEqual(occurrences.map((row) => row.id));
    expect(replayed.map((row) => row.createdAt)).toEqual(occurrences.map((row) => row.createdAt));
    expect(replayed.map((row) => row.version)).toEqual(['1.0.0', '2.0.0']);
    const currentAfter = await prisma.sbomIngestion.findUniqueOrThrow({
      where: { id: current.id },
    });
    expect(currentAfter.updatedAt).toEqual(completedCurrent.updatedAt);
    expect(currentAfter.completedAt).toEqual(completedCurrent.completedAt);
    expect(currentAfter.normalizationVersion).toBe(CURRENT_SBOM_NORMALIZATION_VERSION);
    expect(
      await prisma.auditEvent.count({
        where: {
          organizationId: org.id,
          subjectId: current.id,
          action: 'sbom.ingestion.completed',
        },
      }),
    ).toBe(1);

    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          sbomId: currentSbom.id,
          sbomIngestionId: current.id,
          componentId: component.id,
          bomRef: 'pad-1-again',
          version: '1.0.0',
          versionKnown: true,
        },
      }),
    ).rejects.toThrow();

    const unknown = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: currentSbom.id,
        sbomIngestionId: current.id,
        componentId: component.id,
        bomRef: 'pad-unknown',
        version: '',
        versionKnown: false,
      },
    });
    expect(unknown.versionKnown).toBe(false);
    expect(unknown.version).toBe('');

    const other = await createOrg(prisma, `mv-b-${randomUUID().slice(0, 8)}`);
    const otherAsset = await createAsset(prisma, other.id, 'other-asset');
    const otherSbom = await createSbom(prisma, {
      organizationId: other.id,
      assetId: otherAsset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-10-05T14:00:00.000Z'),
    });
    const otherIngestion = await prisma.sbomIngestion.create({
      data: {
        organizationId: other.id,
        sbomId: otherSbom.id,
        assetId: otherAsset.id,
        parserVersion: PARSER_VERSION,
        normalizationVersion: CURRENT_SBOM_NORMALIZATION_VERSION,
        state: 'processing',
        stage: 'persist_graph',
        startedAt: new Date('2026-10-05T14:00:00.000Z'),
      },
    });
    const otherPersist = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: other.id,
      assetId: otherAsset.id,
      sbomId: otherSbom.id,
      sbomIngestionId: otherIngestion.id,
      graph: currentGraph,
      correlationId: newCorrelationId(),
    });
    expect(otherPersist.ok).toBe(true);
    const otherOccurrences = await prisma.componentOccurrence.findMany({
      where: { organizationId: other.id, sbomIngestionId: otherIngestion.id },
    });
    expect(otherOccurrences).toHaveLength(2);
    expect(otherOccurrences.map((row) => row.id)).not.toEqual(
      expect.arrayContaining(occurrences.map((row) => row.id)),
    );
    const disclosed = JSON.stringify(otherOccurrences);
    for (const row of occurrences) {
      expect(disclosed).not.toContain(row.id);
    }
    expect(
      await prisma.componentOccurrence.findFirst({
        where: { organizationId: other.id, id: storedOne.id },
      }),
    ).toBeNull();
    expect(
      await prisma.componentOccurrence.findFirst({
        where: { organizationId: other.id, id: randomUUID() },
      }),
    ).toBeNull();

    expect(await prisma.finding.count({ where: { organizationId: org.id } })).toBe(0);
    expect(await prisma.findingObservation.count({ where: { organizationId: org.id } })).toBe(0);
    expect(
      await prisma.productMatchEvaluationEvidence.count({ where: { organizationId: org.id } }),
    ).toBe(0);
    expect(await prisma.finding.count({ where: { organizationId: other.id } })).toBe(0);

    const indexes = await prisma.$queryRaw<Array<{ indexname: string; indexdef: string }>>`
      SELECT indexname, indexdef
      FROM pg_indexes
      WHERE indexname IN (
        'component_occurrence_identity_key',
        'finding_identity_key',
        'product_match_evaluation_evidence_evaluation_uidx'
      )
    `;
    const byName = new Map(indexes.map((row) => [row.indexname, row.indexdef]));
    const occurrenceIndex = byName.get('component_occurrence_identity_key') ?? '';
    expect(occurrenceIndex).toContain('organization_id');
    expect(occurrenceIndex).toContain('sbom_ingestion_id');
    expect(occurrenceIndex).toContain('component_id');
    expect(occurrenceIndex).toContain('version');
    const findingIndex = byName.get('finding_identity_key') ?? '';
    expect(findingIndex).toContain('organization_id');
    expect(findingIndex).toContain('asset_id');
    expect(findingIndex).toContain('component_id');
    expect(findingIndex).toContain('vulnerability_id');
    expect(findingIndex).not.toContain('component_occurrence_id');
    const evidenceIndex = byName.get('product_match_evaluation_evidence_evaluation_uidx') ?? '';
    expect(evidenceIndex).toContain('organization_id');
    expect(evidenceIndex).toContain('component_occurrence_id');
    expect(evidenceIndex).toContain('advisory_revision_id');
    expect(evidenceIndex).toContain('evaluator_version');
  });
});
