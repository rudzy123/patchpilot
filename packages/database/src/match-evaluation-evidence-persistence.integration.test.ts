/**
 * Disposable PostgreSQL proof for immutable npm match-evaluation evidence.
 * Synthetic inputs only. No provider contact and no Finding writes.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  FIRST_ECOSYSTEM_EVALUATOR_VERSION,
  FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
  FIRST_ECOSYSTEM_REQUEST_SCHEMA_VERSION,
  MATCH_EVALUATION_INSPECTION_SCHEMA_VERSION,
  MATCH_EVALUATION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
  componentEvidenceFingerprint,
  evaluateSelectedEcosystemAffectedVersion,
  type MatchEvaluationEvidenceProjection,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createMatchEvaluationEvidencePersistence } from './match-evaluation-evidence-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  SHA_A,
  SHA_B,
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  resolvedComponent,
} from './sbom-test-fixture.js';

const ADVISORY_FINGERPRINT = 'b'.repeat(64);

type Seed = {
  readonly organizationId: string;
  readonly assetId: string;
  readonly sbomId: string;
  readonly sbomIngestionId: string;
  readonly componentId: string;
  readonly occurrenceId: string;
  readonly identityKey: string;
  readonly sha256: string;
  readonly version: string;
  readonly versionKnown: boolean;
};

function evaluated(overrides: Record<string, unknown> = {}) {
  const result = evaluateSelectedEcosystemAffectedVersion({
    requestSchemaVersion: FIRST_ECOSYSTEM_REQUEST_SCHEMA_VERSION,
    evaluatorPolicyId: FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
    evaluatorVersion: FIRST_ECOSYSTEM_EVALUATOR_VERSION,
    ecosystem: 'npm',
    namespace: null,
    name: 'left-pad',
    observedIdentity: 'left-pad',
    rawObservedVersion: '1.2.3',
    advisoryIdentity: 'SYNTHETIC-ADVISORY-2',
    advisorySourceClassification: 'synthetic_fixture',
    advisoryEvidenceFingerprint: ADVISORY_FINGERPRINT,
    advisoryEvidenceOrigin: 'synthetic',
    advisoryRevisionDisposition: 'active_synthetic',
    rangeType: 'SEMVER',
    affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.4' }] }],
    explicitAffectedVersions: [],
    evaluationCorrelationId: randomUUID(),
    sbomSourceClassification: 'synthetic',
    componentIdentityProvenance: 'synthetic',
    observedVersionProvenance: 'synthetic',
    rangeEvidenceProvenance: 'synthetic',
    ...overrides,
  });
  if (result.kind !== 'match_evaluation_evidence') {
    throw new Error(`evaluator did not return evidence: ${result.kind}`);
  }
  return result;
}

function persistenceCommand(seed: Seed, evidence = evaluated()) {
  if (typeof evidence.rawObservedVersion !== 'string') {
    throw new Error('raw version was omitted');
  }
  return {
    commandSchemaVersion: MATCH_EVALUATION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
    organizationId: seed.organizationId,
    componentOccurrenceId: seed.occurrenceId,
    assetId: seed.assetId,
    sbomId: seed.sbomId,
    sbomIngestionId: seed.sbomIngestionId,
    componentId: seed.componentId,
    componentIdentityKey: seed.identityKey,
    sbomSha256: seed.sha256,
    versionKnown: seed.versionKnown,
    componentEvidenceFingerprint: componentEvidenceFingerprint({
      organizationId: seed.organizationId,
      componentOccurrenceId: seed.occurrenceId,
      assetId: seed.assetId,
      sbomId: seed.sbomId,
      sbomIngestionId: seed.sbomIngestionId,
      componentId: seed.componentId,
      componentIdentityKey: seed.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: 'left-pad',
      rawObservedVersion: evidence.rawObservedVersion,
      versionKnown: seed.versionKnown,
      sbomSha256: seed.sha256,
    }),
    evidence,
  };
}

async function seedOccurrence(prisma: PrismaClient, label: string, sha256: string): Promise<Seed> {
  const org = await createOrg(prisma, `${label}-${randomUUID().slice(0, 8)}`);
  const asset = await createAsset(prisma, org.id, `asset-${label}`);
  const sbom = await createSbom(prisma, {
    organizationId: org.id,
    assetId: asset.id,
    sha256,
    receivedAt: new Date('2026-10-01T12:00:00.000Z'),
  });
  const ingestion = await createProcessingIngestion(prisma, {
    organizationId: org.id,
    sbomId: sbom.id,
    assetId: asset.id,
  });
  const componentInput = resolvedComponent({
    name: 'left-pad',
    bomRef: 'component-1',
    version: '1.2.3',
  });
  const component = await prisma.component.create({
    data: {
      organizationId: org.id,
      identityKey: componentInput.identityKey,
      purl: componentInput.versionlessPurl,
      ecosystem: 'npm',
      namespace: null,
      name: 'left-pad',
      identityState: 'resolved',
    },
  });
  const occurrence = await prisma.componentOccurrence.create({
    data: {
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: component.id,
      bomRef: 'component-1',
      version: '1.2.3',
      versionKnown: true,
      isDirect: true,
    },
  });
  return {
    organizationId: org.id,
    assetId: asset.id,
    sbomId: sbom.id,
    sbomIngestionId: ingestion.id,
    componentId: component.id,
    occurrenceId: occurrence.id,
    identityKey: component.identityKey,
    sha256,
    version: '1.2.3',
    versionKnown: true,
  };
}

async function evidenceCount(prisma: PrismaClient): Promise<number> {
  const rows = await prisma.$queryRaw<Array<{ count: bigint | number | string }>>`
    SELECT COUNT(*)::bigint AS count FROM "match_evaluation_evidence"
  `;
  return Number(rows[0]?.count);
}

function requireRecorded(result: {
  readonly kind: string;
  readonly projection?: MatchEvaluationEvidenceProjection;
}): MatchEvaluationEvidenceProjection {
  if (result.kind !== 'recorded' || result.projection === undefined) {
    throw new Error(`expected recorded, received ${result.kind}`);
  }
  return result.projection;
}

describe('immutable match evaluation evidence persistence', { timeout: 180_000 }, () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let seed: Seed;
  let other: Seed;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    expect(await evidenceCount(prisma)).toBe(0);
    seed = await seedOccurrence(prisma, 'alpha', SHA_A);
    other = await seedOccurrence(prisma, 'beta', SHA_B);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('persists affected, unaffected, and unknown evidence without Finding authority', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const affected = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(persistenceCommand(seed)),
    );
    const unaffectedEvidence = evaluated({
      advisoryIdentity: 'SYNTHETIC-UNAFFECTED',
      affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }] }],
    });
    const unaffected = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(
        persistenceCommand(seed, unaffectedEvidence),
      ),
    );
    const unknownEvidence = evaluated({
      advisoryIdentity: 'SYNTHETIC-UNKNOWN',
      rangeType: 'GIT',
      affectedRanges: [],
    });
    const unknown = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(persistenceCommand(seed, unknownEvidence)),
    );
    expect(affected.outcome).toBe('affected');
    expect(unaffected.outcome).toBe('unaffected');
    expect(unknown.outcome).toBe('unknown');
    expect(affected.rawObservedVersion).toBe('1.2.3');
    expect(affected.findingAuthority).toBe(false);
    expect(affected.suppressionAuthority).toBe(false);
    expect(affected.explanationCodes.length).toBeGreaterThan(0);
    expect([affected, unaffected, unknown].map((item) => item.evidenceId).sort()).toHaveLength(3);
    const findings = await prisma.finding.count();
    expect(findings).toBe(0);
  });

  it('replays an exact command without a second insert', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const command = persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-REPLAY' }));
    const first = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(command));
    const before = await evidenceCount(prisma);
    const second = await port.persistImmutableMatchEvaluationEvidence(command);
    expect(second.kind).toBe('already_applied');
    if (second.kind !== 'already_applied') {
      return;
    }
    expect(second.counts).toEqual({ inserts: 0, updates: 0, deletes: 0, evaluatorCalls: 0 });
    expect(second.projection.evidenceId).toBe(first.evidenceId);
    expect(second.projection.createdAt).toBe(first.createdAt);
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('rejects a forged replay fingerprint without overwriting evidence', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const command = persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-CONFLICT' }));
    const recorded = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(command));
    const forgedEvidence = {
      ...command.evidence,
      outcome: 'unknown',
      explanationCodes: ['unknown_incomplete_evidence'],
    };
    const forged = { ...command, evidence: forgedEvidence };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(forged);
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('immutable_conflict');
      expect(result.counts.inserts).toBe(0);
    }
    expect(await evidenceCount(prisma)).toBe(before);
    const inspected = await port.inspectMatchEvaluationEvidence({
      inspectionSchemaVersion: MATCH_EVALUATION_INSPECTION_SCHEMA_VERSION,
      organizationId: seed.organizationId,
      evidenceId: recorded.evidenceId,
    });
    expect(inspected.kind).toBe('found');
    if (inspected.kind === 'found') {
      expect(inspected.projection.outcome).toBe(recorded.outcome);
      expect(inspected.projection.createdAt).toBe(recorded.createdAt);
    }
  });

  it('rejects cross-tenant substitution and inspection', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const command = persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-TENANT' }));
    const recorded = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(command));
    const crossed = persistenceCommand(
      { ...other, occurrenceId: seed.occurrenceId, componentId: seed.componentId },
      evaluated({ advisoryIdentity: 'SYNTHETIC-TENANT-OTHER' }),
    );
    const missing = await port.persistImmutableMatchEvaluationEvidence({
      ...crossed,
      componentOccurrenceId: seed.occurrenceId,
      componentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: other.organizationId,
        componentOccurrenceId: seed.occurrenceId,
        assetId: other.assetId,
        sbomId: other.sbomId,
        sbomIngestionId: other.sbomIngestionId,
        componentId: seed.componentId,
        componentIdentityKey: other.identityKey,
        ecosystem: 'npm',
        namespace: null,
        name: 'left-pad',
        rawObservedVersion: '1.2.3',
        versionKnown: true,
        sbomSha256: other.sha256,
      }),
    });
    expect(missing.kind).toBe('rejected');
    if (missing.kind === 'rejected') {
      expect(missing.code).toBe('component_occurrence_missing');
    }
    const encoded = JSON.stringify(missing);
    expect(encoded).not.toContain(seed.organizationId);
    const hidden = await port.inspectMatchEvaluationEvidence({
      inspectionSchemaVersion: MATCH_EVALUATION_INSPECTION_SCHEMA_VERSION,
      organizationId: other.organizationId,
      evidenceId: recorded.evidenceId,
    });
    expect(hidden.kind).toBe('not_found');
  });

  it('rejects a component binding that does not match the stored occurrence', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const evidence = evaluated({ advisoryIdentity: 'SYNTHETIC-MISMATCH' });
    const command = persistenceCommand(seed, evidence);
    const forgedAsset = randomUUID();
    const forged = {
      ...command,
      assetId: forgedAsset,
      componentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: seed.organizationId,
        componentOccurrenceId: seed.occurrenceId,
        assetId: forgedAsset,
        sbomId: seed.sbomId,
        sbomIngestionId: seed.sbomIngestionId,
        componentId: seed.componentId,
        componentIdentityKey: seed.identityKey,
        ecosystem: 'npm',
        namespace: null,
        name: 'left-pad',
        rawObservedVersion: '1.2.3',
        versionKnown: true,
        sbomSha256: seed.sha256,
      }),
    };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(forged);
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('component_evidence_mismatch');
      expect(result.counts.inserts).toBe(0);
    }
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('rejects update, delete, and cascade deletion', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const recorded = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(
        persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-APPEND' })),
      ),
    );
    const before = await evidenceCount(prisma);
    await expect(
      prisma.$executeRaw`
        UPDATE "match_evaluation_evidence"
        SET "outcome" = 'unknown'
        WHERE "id" = ${recorded.evidenceId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        DELETE FROM "match_evaluation_evidence"
        WHERE "id" = ${recorded.evidenceId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.componentOccurrence.delete({ where: { id: seed.occurrenceId } }),
    ).rejects.toThrow();
    expect(await evidenceCount(prisma)).toBe(before);
    const row = await prisma.matchEvaluationEvidence.findFirst({
      where: { id: recorded.evidenceId, organizationId: seed.organizationId },
      select: { outcome: true, createdAt: true },
    });
    expect(row?.outcome).toBe(recorded.outcome);
    expect(row?.createdAt.toISOString()).toBe(recorded.createdAt);
  });

  it('rolls back a parent insert when explanation ordinals are incomplete', async () => {
    const evidence = evaluated({ advisoryIdentity: 'SYNTHETIC-ROLLBACK' });
    const command = persistenceCommand(seed, evidence);
    const before = await evidenceCount(prisma);
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.matchEvaluationEvidence.create({
          data: {
            organizationId: command.organizationId,
            componentOccurrenceId: command.componentOccurrenceId,
            assetId: command.assetId,
            sbomId: command.sbomId,
            sbomIngestionId: command.sbomIngestionId,
            componentId: command.componentId,
            sbomSha256: command.sbomSha256,
            componentIdentityKey: command.componentIdentityKey,
            versionKnown: command.versionKnown,
            componentEvidenceFingerprint: command.componentEvidenceFingerprint,
            evidenceSchemaVersion: evidence.evidenceSchemaVersion,
            evaluationId: evidence.evaluationId,
            evaluatorId: evidence.evaluatorId,
            evaluatorVersion: evidence.evaluatorVersion,
            evaluatorImplementation: evidence.evaluatorImplementation,
            policyId: evidence.policyId,
            ecosystem: 'npm',
            packageNamespace: null,
            packageName: 'left-pad',
            packageIdentityKey: evidence.packageIdentityKey ?? '',
            rawObservedVersion: evidence.rawObservedVersion ?? '',
            rawObservedVersionSha256: evidence.rawObservedVersionSha256,
            rawObservedVersionRetention: 'retained',
            parsedVersionClassification: 'valid_strict_semver',
            advisoryIdentity: evidence.advisoryIdentity,
            advisorySourceClassification: evidence.advisorySourceClassification,
            advisoryEvidenceFingerprint: evidence.advisoryEvidenceFingerprint,
            advisoryEvidenceOrigin: evidence.advisoryEvidenceOrigin,
            rangeFingerprint: evidence.rangeFingerprint,
            outcome: evidence.outcome,
            replayFingerprint: evidence.replayFingerprint,
            findingCreation: 'unavailable',
            suppressionAuthority: false,
            evaluationTimestampClassification: 'not_used',
            explanations: {
              create: [
                {
                  ordinal: 2,
                  explanationCode: evidence.explanationCodes[0] ?? 'unknown_incomplete_evidence',
                },
              ],
            },
          },
        });
      }),
    ).rejects.toThrow();
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('admits one winner for concurrent identical commands', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const command = persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-RACE' }));
    const before = await evidenceCount(prisma);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = [0, 1].map(async () => {
      await gate;
      return port.persistImmutableMatchEvaluationEvidence(command);
    });
    release();
    const results = await Promise.all(pending);
    const kinds = results.map((result) => result.kind).sort();
    expect(kinds).toEqual(['already_applied', 'recorded']);
    expect(await evidenceCount(prisma)).toBe(before + 1);
  });

  it('rejects a synthetic origin labeled as KEV before any insert', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const evidence = {
      ...evaluated({ advisoryIdentity: 'SYNTHETIC-KEV-LABEL' }),
      advisorySourceClassification: 'cisa_kev',
      advisoryEvidenceOrigin: 'synthetic',
    };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(
      persistenceCommand(seed, evidence as never),
    );
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('advisory_mismatch');
      expect(result.counts).toEqual({ inserts: 0, updates: 0, deletes: 0, evaluatorCalls: 0 });
    }
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('does not let a second evaluator version replace stored evidence', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const command = persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-VERSION' }));
    const before = await evidenceCount(prisma);
    const forged = {
      ...command,
      evidence: { ...command.evidence, evaluatorVersion: 'session_15_unreviewed' },
    };
    const result = await port.persistImmutableMatchEvaluationEvidence(forged);
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('invalid_command');
      expect(result.counts.evaluatorCalls).toBe(0);
    }
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('admits one winner when concurrent commands share a replay fingerprint and disagree', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const honest = persistenceCommand(
      seed,
      evaluated({ advisoryIdentity: 'SYNTHETIC-CONFLICT-RACE' }),
    );
    const forged = {
      ...honest,
      evidence: {
        ...honest.evidence,
        evaluationId: randomUUID(),
        outcome: 'unknown' as const,
        explanationCodes: ['unknown_incomplete_evidence'] as const,
      },
    };
    const before = await evidenceCount(prisma);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = [honest, forged].map(async (command) => {
      await gate;
      return port.persistImmutableMatchEvaluationEvidence(command);
    });
    release();
    const results = await Promise.all(pending);
    const recorded = results.find((result) => result.kind === 'recorded');
    const conflict = results.find((result) => result.kind === 'rejected');
    expect(recorded?.kind).toBe('recorded');
    expect(conflict?.kind).toBe('rejected');
    if (conflict?.kind === 'rejected') {
      expect(conflict.code).toBe('immutable_conflict');
      expect(JSON.stringify(conflict)).not.toContain(seed.organizationId);
    }
    expect(await evidenceCount(prisma)).toBe(before + 1);
    if (recorded?.kind === 'recorded') {
      const stored = await prisma.matchEvaluationEvidence.findUniqueOrThrow({
        where: {
          organizationId_componentOccurrenceId_replayFingerprint: {
            organizationId: seed.organizationId,
            componentOccurrenceId: seed.occurrenceId,
            replayFingerprint: honest.evidence.replayFingerprint,
          },
        },
        select: { outcome: true },
      });
      expect(stored.outcome).toBe(recorded.projection.outcome);
    }
  });

  it('returns database_unavailable when the database cannot be reached and inserts nothing', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const before = await evidenceCount(prisma);
    const brokenUrl = new URL(databaseUrl);
    brokenUrl.port = '1';
    const unreachable = new PrismaClient({
      datasources: { db: { url: brokenUrl.toString() } },
    });
    try {
      const isolated = createMatchEvaluationEvidencePersistence(unreachable);
      const result = await isolated.persistImmutableMatchEvaluationEvidence(
        persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-UNREACHABLE' })),
      );
      expect(result.kind).toBe('rejected');
      if (result.kind === 'rejected') {
        expect(result.code).toBe('database_unavailable');
        expect(result.counts).toEqual({ inserts: 0, updates: 0, deletes: 0, evaluatorCalls: 0 });
        expect(JSON.stringify(result)).not.toContain('55432');
        expect(JSON.stringify(result)).not.toContain(seed.organizationId);
      }
    } finally {
      await unreachable.$disconnect();
    }
    expect(await evidenceCount(prisma)).toBe(before);
    const followUp = await port.persistImmutableMatchEvaluationEvidence(
      persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-AFTER-UNREACHABLE' })),
    );
    expect(followUp.kind).toBe('recorded');
  });

  it('rejects an explanation insert after the evidence transaction commits', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const recorded = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(
        persistenceCommand(seed, evaluated({ advisoryIdentity: 'SYNTHETIC-CLOSED-EXPLANATION' })),
      ),
    );
    const before = await prisma.matchEvaluationExplanation.count({
      where: { matchEvaluationEvidenceId: recorded.evidenceId },
    });
    await expect(
      prisma.$executeRaw`
        INSERT INTO "match_evaluation_explanation" (
          "id",
          "organization_id",
          "match_evaluation_evidence_id",
          "ordinal",
          "explanation_code"
        )
        VALUES (
          CAST(${randomUUID()} AS UUID),
          CAST(${seed.organizationId} AS UUID),
          CAST(${recorded.evidenceId} AS UUID),
          8,
          'affected_explicit_version_equal'
        )
      `,
    ).rejects.toThrow();
    expect(
      await prisma.matchEvaluationExplanation.count({
        where: { matchEvaluationEvidenceId: recorded.evidenceId },
      }),
    ).toBe(before);
  });

  it('rejects the same replay fingerprint submitted for another tenant', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const owned = persistenceCommand(
      seed,
      evaluated({ advisoryIdentity: 'SYNTHETIC-CROSS-TENANT-FINGERPRINT' }),
    );
    const recorded = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(owned));
    const foreign = persistenceCommand(
      other,
      evaluated({ advisoryIdentity: 'SYNTHETIC-CROSS-TENANT-FINGERPRINT' }),
    );
    const collided = {
      ...foreign,
      evidence: {
        ...foreign.evidence,
        replayFingerprint: owned.evidence.replayFingerprint,
        evaluationId: recorded.evaluationId,
      },
    };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(collided);
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('immutable_conflict');
      expect(result.counts).toEqual({ inserts: 0, updates: 0, deletes: 0, evaluatorCalls: 0 });
      expect(JSON.stringify(result)).not.toContain(seed.organizationId);
      expect(JSON.stringify(result)).not.toContain(recorded.evidenceId);
    }
    expect(await evidenceCount(prisma)).toBe(before);
  });

  it('stores the same evaluator fingerprint for another tenant when the evaluation content agrees', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const advisoryIdentity = 'SYNTHETIC-SHARED-CONTENT';
    const owned = persistenceCommand(seed, evaluated({ advisoryIdentity }));
    const foreign = persistenceCommand(other, evaluated({ advisoryIdentity }));
    expect(owned.evidence.replayFingerprint).toBe(foreign.evidence.replayFingerprint);
    expect(owned.evidence.evaluationId).not.toBe(foreign.evidence.evaluationId);
    const first = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(owned));
    const before = await evidenceCount(prisma);
    const second = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(foreign));
    expect(second.evidenceId).not.toBe(first.evidenceId);
    expect(second.organizationId).toBe(other.organizationId);
    expect(second.replayFingerprint).toBe(first.replayFingerprint);
    expect(second.outcome).toBe(first.outcome);
    expect(await evidenceCount(prisma)).toBe(before + 1);
    const hidden = await port.inspectMatchEvaluationEvidence({
      inspectionSchemaVersion: MATCH_EVALUATION_INSPECTION_SCHEMA_VERSION,
      organizationId: other.organizationId,
      evidenceId: first.evidenceId,
    });
    expect(hidden.kind).toBe('not_found');
  });

  it('rejects a reused fingerprint whose outcome disagrees and does not overwrite either tenant', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const advisoryIdentity = 'SYNTHETIC-FINGERPRINT-CONTENT';
    const owned = persistenceCommand(seed, evaluated({ advisoryIdentity }));
    const recorded = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(owned));
    const foreign = persistenceCommand(other, evaluated({ advisoryIdentity }));
    const forged = {
      ...foreign,
      evidence: {
        ...foreign.evidence,
        evaluationId: randomUUID(),
        replayFingerprint: owned.evidence.replayFingerprint,
        outcome: 'unknown' as const,
        explanationCodes: ['unknown_incomplete_evidence'] as const,
      },
    };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(forged);
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('immutable_conflict');
      expect(result.counts).toEqual({ inserts: 0, updates: 0, deletes: 0, evaluatorCalls: 0 });
      expect(JSON.stringify(result)).not.toContain(seed.organizationId);
      expect(JSON.stringify(result)).not.toContain(recorded.evidenceId);
    }
    expect(await evidenceCount(prisma)).toBe(before);
    const inspected = await port.inspectMatchEvaluationEvidence({
      inspectionSchemaVersion: MATCH_EVALUATION_INSPECTION_SCHEMA_VERSION,
      organizationId: seed.organizationId,
      evidenceId: recorded.evidenceId,
    });
    expect(inspected.kind).toBe('found');
    if (inspected.kind === 'found') {
      expect(inspected.projection.outcome).toBe('affected');
    }
  });

  it('stores the same fingerprint on a second occurrence in the same tenant', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const advisoryIdentity = 'SYNTHETIC-SECOND-OCCURRENCE';
    const owned = persistenceCommand(seed, evaluated({ advisoryIdentity }));
    const first = requireRecorded(await port.persistImmutableMatchEvaluationEvidence(owned));
    const asset = await createAsset(prisma, seed.organizationId, `asset-second-${randomUUID()}`);
    const sha256 = 'c'.repeat(64);
    const sbom = await createSbom(prisma, {
      organizationId: seed.organizationId,
      assetId: asset.id,
      sha256,
      receivedAt: new Date('2026-10-01T12:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: seed.organizationId,
      sbomId: sbom.id,
      assetId: asset.id,
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: seed.organizationId,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: seed.componentId,
        bomRef: 'component-2',
        version: '1.2.3',
        versionKnown: true,
        isDirect: true,
      },
    });
    const secondSeed: Seed = {
      ...seed,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      occurrenceId: occurrence.id,
      sha256,
    };
    const before = await evidenceCount(prisma);
    const second = requireRecorded(
      await port.persistImmutableMatchEvaluationEvidence(
        persistenceCommand(secondSeed, evaluated({ advisoryIdentity })),
      ),
    );
    expect(second.evidenceId).not.toBe(first.evidenceId);
    expect(second.componentOccurrenceId).toBe(occurrence.id);
    expect(second.replayFingerprint).toBe(first.replayFingerprint);
    expect(second.sbomSha256).toBe(sha256);
    expect(await evidenceCount(prisma)).toBe(before + 1);
  });

  it('rejects KEV evidence presented as affected before insert', async () => {
    const port = createMatchEvaluationEvidencePersistence(prisma);
    const evidence = {
      ...evaluated({ advisoryIdentity: 'SYNTHETIC-KEV-AFFECTED' }),
      advisorySourceClassification: 'cisa_kev',
      advisoryEvidenceOrigin: 'untrusted_not_recorded',
      outcome: 'affected',
      explanationCodes: ['affected_explicit_version_equal'],
    };
    const before = await evidenceCount(prisma);
    const result = await port.persistImmutableMatchEvaluationEvidence(
      persistenceCommand(seed, evidence as never),
    );
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('advisory_mismatch');
      expect(result.counts.evaluatorCalls).toBe(0);
    }
    expect(await evidenceCount(prisma)).toBe(before);
    const findings = await prisma.finding.count();
    expect(findings).toBe(0);
  });
});
