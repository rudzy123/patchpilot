/**
 * Uncomposed PostgreSQL adapter for immutable npm match-evaluation evidence.
 * Construction performs no I/O. The adapter does not evaluate affectedness
 * and does not create Findings.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  FIRST_ECOSYSTEM_EXPLANATION_CODES,
  MATCH_EVALUATION_ZERO_COUNTS,
  componentEvidenceFingerprint,
  explanationOutcome,
  evaluatorPackageIdentityKey,
  matchEvaluationFingerprintContentAgrees,
  matchEvaluationRecordsAgree,
  parseMatchEvaluationInspection,
  parseMatchEvaluationPersistenceCommand,
  sha256Utf8,
  type InspectMatchEvaluationEvidenceResult,
  type MatchEvaluationEvidencePersistencePort,
  type MatchEvaluationEvidenceProjection,
  type MatchEvaluationFingerprintContent,
  type MatchEvaluationPersistenceRejectionCode,
  type PersistImmutableMatchEvaluationEvidenceResult,
  type ParsedMatchEvaluationPersistenceCommand,
} from '@patchpilot/vulnerability-intelligence';

import {
  isMatchEvaluationUniqueViolation,
  translateMatchEvaluationPersistenceFailure,
} from './match-evaluation-evidence-errors.js';
import { isRootPrismaClient } from './guards.js';

const ROOT_CLIENT_REQUIRED = 'Match evaluation persistence requires the root database client.';

const EVIDENCE_SELECT = {
  id: true,
  organizationId: true,
  componentOccurrenceId: true,
  assetId: true,
  sbomId: true,
  sbomIngestionId: true,
  componentId: true,
  sbomSha256: true,
  componentIdentityKey: true,
  versionKnown: true,
  componentEvidenceFingerprint: true,
  evidenceSchemaVersion: true,
  evaluationId: true,
  evaluatorId: true,
  evaluatorVersion: true,
  evaluatorImplementation: true,
  policyId: true,
  ecosystem: true,
  packageNamespace: true,
  packageName: true,
  packageIdentityKey: true,
  rawObservedVersion: true,
  rawObservedVersionSha256: true,
  rawObservedVersionRetention: true,
  parsedVersionClassification: true,
  advisoryIdentity: true,
  advisorySourceClassification: true,
  advisoryEvidenceFingerprint: true,
  advisoryEvidenceOrigin: true,
  rangeFingerprint: true,
  outcome: true,
  replayFingerprint: true,
  findingCreation: true,
  suppressionAuthority: true,
  evaluationTimestampClassification: true,
  createdAt: true,
  explanations: {
    orderBy: { ordinal: 'asc' as const },
    select: {
      ordinal: true,
      explanationCode: true,
      organizationId: true,
    },
  },
} satisfies Prisma.MatchEvaluationEvidenceSelect;

type EvidenceRow = Prisma.MatchEvaluationEvidenceGetPayload<{ select: typeof EVIDENCE_SELECT }>;

class MatchEvaluationRowError extends Error {
  public constructor() {
    super('Match evaluation evidence row is malformed.');
    this.name = 'MatchEvaluationRowError';
  }
}

class MatchEvaluationPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'MatchEvaluationPersistenceFailure';
  }
}

function storedSha256(value: string): string | null {
  const significant = value.replace(/ +$/u, '');
  return /^[a-f0-9]{64}$/.test(significant) ? significant : null;
}

function fingerprintContent(
  command: ParsedMatchEvaluationPersistenceCommand,
): MatchEvaluationFingerprintContent {
  return {
    evaluatorId: command.evaluatorId,
    evaluatorVersion: command.evaluatorVersion,
    policyId: command.policyId,
    ecosystem: command.ecosystem,
    packageNamespace: command.packageNamespace,
    packageName: command.packageName,
    packageIdentityKey: command.packageIdentityKey,
    rawObservedVersion: command.rawObservedVersion,
    rawObservedVersionSha256: command.rawObservedVersionSha256,
    rawObservedVersionRetention: command.rawObservedVersionRetention,
    parsedVersionClassification: command.parsedVersionClassification,
    advisoryIdentity: command.advisoryIdentity,
    advisorySourceClassification: command.advisorySourceClassification,
    advisoryEvidenceFingerprint: command.advisoryEvidenceFingerprint,
    advisoryEvidenceOrigin: command.advisoryEvidenceOrigin,
    rangeFingerprint: command.rangeFingerprint,
    outcome: command.outcome,
    explanationCodes: command.explanationCodes,
  };
}

function projectionContent(
  row: MatchEvaluationEvidenceProjection,
): MatchEvaluationFingerprintContent {
  return {
    evaluatorId: row.evaluatorId,
    evaluatorVersion: row.evaluatorVersion,
    policyId: row.policyId,
    ecosystem: row.ecosystem,
    packageNamespace: row.packageNamespace,
    packageName: row.packageName,
    packageIdentityKey: row.packageIdentityKey,
    rawObservedVersion: row.rawObservedVersion,
    rawObservedVersionSha256: row.rawObservedVersionSha256,
    rawObservedVersionRetention: row.rawObservedVersionRetention,
    parsedVersionClassification: row.parsedVersionClassification,
    advisoryIdentity: row.advisoryIdentity,
    advisorySourceClassification: row.advisorySourceClassification,
    advisoryEvidenceFingerprint: row.advisoryEvidenceFingerprint,
    advisoryEvidenceOrigin: row.advisoryEvidenceOrigin,
    rangeFingerprint: row.rangeFingerprint,
    outcome: row.outcome,
    explanationCodes: row.explanationCodes,
  };
}

function rejected(
  code: MatchEvaluationPersistenceRejectionCode,
): PersistImmutableMatchEvaluationEvidenceResult {
  return { kind: 'rejected', code, counts: MATCH_EVALUATION_ZERO_COUNTS };
}

function projectRow(row: EvidenceRow): MatchEvaluationEvidenceProjection {
  if (
    row.evidenceSchemaVersion !== 'osv_first_ecosystem_match_evaluation_evidence_v1' ||
    row.evaluatorId !== 'osv_first_ecosystem_affected_version_evaluator_v1' ||
    row.evaluatorVersion !== 'session_14_batch_2_in_memory' ||
    row.evaluatorImplementation !== 'in_memory_uncomposed' ||
    row.policyId !== 'osv_first_ecosystem_matching_architecture_v1' ||
    row.ecosystem !== 'npm' ||
    row.findingCreation !== 'unavailable' ||
    row.suppressionAuthority !== false ||
    row.evaluationTimestampClassification !== 'not_used' ||
    row.rawObservedVersionRetention !== 'retained' ||
    (row.outcome !== 'affected' && row.outcome !== 'unaffected' && row.outcome !== 'unknown')
  ) {
    throw new MatchEvaluationRowError();
  }
  if (
    evaluatorPackageIdentityKey(row.packageNamespace, row.packageName) !== row.packageIdentityKey ||
    sha256Utf8(row.rawObservedVersion) !== row.rawObservedVersionSha256
  ) {
    throw new MatchEvaluationRowError();
  }
  const fingerprint = componentEvidenceFingerprint({
    organizationId: row.organizationId,
    componentOccurrenceId: row.componentOccurrenceId,
    assetId: row.assetId,
    sbomId: row.sbomId,
    sbomIngestionId: row.sbomIngestionId,
    componentId: row.componentId,
    componentIdentityKey: row.componentIdentityKey,
    ecosystem: row.ecosystem,
    namespace: row.packageNamespace,
    name: row.packageName,
    rawObservedVersion: row.rawObservedVersion,
    versionKnown: row.versionKnown,
    sbomSha256: row.sbomSha256,
  });
  if (fingerprint !== row.componentEvidenceFingerprint) {
    throw new MatchEvaluationRowError();
  }
  if (row.explanations.length === 0 || row.explanations.length > 8) {
    throw new MatchEvaluationRowError();
  }
  const codes = row.explanations.map((item, index) => {
    if (item.ordinal !== index + 1 || item.organizationId !== row.organizationId) {
      throw new MatchEvaluationRowError();
    }
    return item.explanationCode;
  });
  const seen = new Set<string>();
  let previousRank = -1;
  for (const code of codes) {
    if (seen.has(code) || explanationOutcome(code) !== row.outcome) {
      throw new MatchEvaluationRowError();
    }
    seen.add(code);
    const rank = FIRST_ECOSYSTEM_EXPLANATION_CODES.indexOf(code);
    if (rank < 0 || rank <= previousRank) {
      throw new MatchEvaluationRowError();
    }
    previousRank = rank;
  }
  if (!(row.createdAt instanceof Date) || Number.isNaN(row.createdAt.getTime())) {
    throw new MatchEvaluationRowError();
  }
  return {
    evidenceId: row.id,
    evaluationId: row.evaluationId,
    organizationId: row.organizationId,
    componentOccurrenceId: row.componentOccurrenceId,
    assetId: row.assetId,
    sbomId: row.sbomId,
    sbomIngestionId: row.sbomIngestionId,
    componentId: row.componentId,
    sbomSha256: row.sbomSha256,
    versionKnown: row.versionKnown,
    componentEvidenceFingerprint: row.componentEvidenceFingerprint,
    evidenceSchemaVersion: row.evidenceSchemaVersion,
    evaluatorId: row.evaluatorId,
    evaluatorVersion: row.evaluatorVersion,
    policyId: row.policyId,
    ecosystem: 'npm',
    packageNamespace: row.packageNamespace,
    packageName: row.packageName,
    packageIdentityKey: row.packageIdentityKey,
    rawObservedVersion: row.rawObservedVersion,
    rawObservedVersionSha256: row.rawObservedVersionSha256,
    rawObservedVersionRetention: 'retained',
    parsedVersionClassification: row.parsedVersionClassification,
    advisoryIdentity: row.advisoryIdentity,
    advisorySourceClassification: row.advisorySourceClassification,
    advisoryEvidenceFingerprint: row.advisoryEvidenceFingerprint,
    advisoryEvidenceOrigin: row.advisoryEvidenceOrigin,
    rangeFingerprint: row.rangeFingerprint,
    outcome: row.outcome,
    explanationCodes: codes,
    replayFingerprint: row.replayFingerprint,
    findingCreation: 'unavailable',
    findingAuthority: false,
    suppressionAuthority: false,
    createdAt: row.createdAt.toISOString(),
  };
}

function classifyExisting(
  row: EvidenceRow,
  command: ParsedMatchEvaluationPersistenceCommand,
): PersistImmutableMatchEvaluationEvidenceResult {
  let projection: MatchEvaluationEvidenceProjection;
  try {
    projection = projectRow(row);
  } catch (error) {
    if (error instanceof MatchEvaluationRowError) {
      return rejected('malformed_persisted_state');
    }
    throw error;
  }
  const agrees = matchEvaluationRecordsAgree(
    {
      organizationId: command.organizationId,
      componentOccurrenceId: command.componentOccurrenceId,
      assetId: command.assetId,
      sbomId: command.sbomId,
      sbomIngestionId: command.sbomIngestionId,
      componentId: command.componentId,
      componentIdentityKey: command.componentIdentityKey,
      sbomSha256: command.sbomSha256,
      versionKnown: command.versionKnown,
      componentEvidenceFingerprint: command.componentEvidenceFingerprint,
      evaluationId: command.evaluationId,
      ecosystem: command.ecosystem,
      packageNamespace: command.packageNamespace,
      packageName: command.packageName,
      packageIdentityKey: command.packageIdentityKey,
      rawObservedVersion: command.rawObservedVersion,
      rawObservedVersionSha256: command.rawObservedVersionSha256,
      rawObservedVersionRetention: command.rawObservedVersionRetention,
      parsedVersionClassification: command.parsedVersionClassification,
      advisoryIdentity: command.advisoryIdentity,
      advisorySourceClassification: command.advisorySourceClassification,
      advisoryEvidenceFingerprint: command.advisoryEvidenceFingerprint,
      advisoryEvidenceOrigin: command.advisoryEvidenceOrigin,
      rangeFingerprint: command.rangeFingerprint,
      outcome: command.outcome,
      explanationCodes: command.explanationCodes,
      replayFingerprint: command.replayFingerprint,
      evaluatorId: command.evaluatorId,
      evaluatorVersion: command.evaluatorVersion,
      policyId: command.policyId,
    },
    {
      organizationId: projection.organizationId,
      componentOccurrenceId: projection.componentOccurrenceId,
      assetId: projection.assetId,
      sbomId: projection.sbomId,
      sbomIngestionId: projection.sbomIngestionId,
      componentId: projection.componentId,
      componentIdentityKey: row.componentIdentityKey,
      sbomSha256: projection.sbomSha256,
      versionKnown: projection.versionKnown,
      componentEvidenceFingerprint: projection.componentEvidenceFingerprint,
      evaluationId: projection.evaluationId,
      ecosystem: projection.ecosystem,
      packageNamespace: projection.packageNamespace,
      packageName: projection.packageName,
      packageIdentityKey: projection.packageIdentityKey,
      rawObservedVersion: projection.rawObservedVersion,
      rawObservedVersionSha256: projection.rawObservedVersionSha256,
      rawObservedVersionRetention: projection.rawObservedVersionRetention,
      parsedVersionClassification: projection.parsedVersionClassification,
      advisoryIdentity: projection.advisoryIdentity,
      advisorySourceClassification: projection.advisorySourceClassification,
      advisoryEvidenceFingerprint: projection.advisoryEvidenceFingerprint,
      advisoryEvidenceOrigin: projection.advisoryEvidenceOrigin,
      rangeFingerprint: projection.rangeFingerprint,
      outcome: projection.outcome,
      explanationCodes: projection.explanationCodes,
      replayFingerprint: projection.replayFingerprint,
      evaluatorId: projection.evaluatorId,
      evaluatorVersion: projection.evaluatorVersion,
      policyId: projection.policyId,
    },
  );
  if (!agrees) {
    return rejected('immutable_conflict');
  }
  return {
    kind: 'already_applied',
    projection,
    counts: MATCH_EVALUATION_ZERO_COUNTS,
  };
}

export function createMatchEvaluationEvidencePersistence(
  client: PrismaClient,
): MatchEvaluationEvidencePersistencePort {
  if (!isRootPrismaClient(client)) {
    throw new MatchEvaluationPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return new PrismaMatchEvaluationEvidencePersistence(client);
}

class PrismaMatchEvaluationEvidencePersistence implements MatchEvaluationEvidencePersistencePort {
  public constructor(private readonly client: PrismaClient) {}

  public async persistImmutableMatchEvaluationEvidence(
    command: unknown,
  ): Promise<PersistImmutableMatchEvaluationEvidenceResult> {
    const parsed = parseMatchEvaluationPersistenceCommand(command);
    if (!parsed.accepted) {
      return rejected(parsed.code);
    }
    try {
      const existing = await this.findOccurrenceReplay(
        parsed.command.organizationId,
        parsed.command.componentOccurrenceId,
        parsed.command.replayFingerprint,
      );
      if (existing !== null) {
        return classifyExisting(existing, parsed.command);
      }
      return await this.insertEvidence(parsed.command);
    } catch (error) {
      if (error instanceof MatchEvaluationRowError) {
        return rejected('malformed_persisted_state');
      }
      if (isMatchEvaluationUniqueViolation(error)) {
        return this.reloadConflict(parsed.command);
      }
      const code = translateMatchEvaluationPersistenceFailure(error);
      return rejected(code);
    }
  }

  public async inspectMatchEvaluationEvidence(
    query: unknown,
  ): Promise<InspectMatchEvaluationEvidenceResult> {
    const parsed = parseMatchEvaluationInspection(query);
    if (!parsed.accepted) {
      return { kind: 'rejected', code: 'invalid_command' };
    }
    try {
      const row =
        parsed.inspection.mode === 'evidence_id'
          ? await this.client.matchEvaluationEvidence.findFirst({
              where: {
                organizationId: parsed.inspection.organizationId,
                id: parsed.inspection.evidenceId,
              },
              select: EVIDENCE_SELECT,
            })
          : await this.client.matchEvaluationEvidence.findFirst({
              where: {
                organizationId: parsed.inspection.organizationId,
                componentOccurrenceId: parsed.inspection.componentOccurrenceId,
                replayFingerprint: parsed.inspection.replayFingerprint,
              },
              select: EVIDENCE_SELECT,
            });
      if (row === null) {
        return { kind: 'not_found' };
      }
      return { kind: 'found', projection: projectRow(row) };
    } catch (error) {
      if (error instanceof MatchEvaluationRowError) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      const code = translateMatchEvaluationPersistenceFailure(error);
      if (code === 'database_unavailable' || code === 'timeout' || code === 'internal_failure') {
        return { kind: 'rejected', code };
      }
      return { kind: 'rejected', code: 'internal_failure' };
    }
  }

  private async findOccurrenceReplay(
    organizationId: string,
    componentOccurrenceId: string,
    replayFingerprint: string,
  ): Promise<EvidenceRow | null> {
    return this.client.matchEvaluationEvidence.findFirst({
      where: { organizationId, componentOccurrenceId, replayFingerprint },
      select: EVIDENCE_SELECT,
    });
  }

  private async reloadConflict(
    command: ParsedMatchEvaluationPersistenceCommand,
  ): Promise<PersistImmutableMatchEvaluationEvidenceResult> {
    const byReplay = await this.findOccurrenceReplay(
      command.organizationId,
      command.componentOccurrenceId,
      command.replayFingerprint,
    );
    const row =
      byReplay ??
      (await this.client.matchEvaluationEvidence.findUnique({
        where: { evaluationId: command.evaluationId },
        select: EVIDENCE_SELECT,
      }));
    if (row === null) {
      return rejected('internal_failure');
    }
    return classifyExisting(row, command);
  }

  private async insertEvidence(
    command: ParsedMatchEvaluationPersistenceCommand,
  ): Promise<PersistImmutableMatchEvaluationEvidenceResult> {
    return this.client.$transaction(async (tx) => {
      const raced = await tx.matchEvaluationEvidence.findFirst({
        where: {
          organizationId: command.organizationId,
          componentOccurrenceId: command.componentOccurrenceId,
          replayFingerprint: command.replayFingerprint,
        },
        select: EVIDENCE_SELECT,
      });
      if (raced !== null) {
        return classifyExisting(raced, command);
      }
      const peer = await tx.matchEvaluationEvidence.findFirst({
        where: { replayFingerprint: command.replayFingerprint },
        select: EVIDENCE_SELECT,
      });
      if (peer !== null) {
        let peerProjection: MatchEvaluationEvidenceProjection;
        try {
          peerProjection = projectRow(peer);
        } catch (error) {
          if (error instanceof MatchEvaluationRowError) {
            return rejected('malformed_persisted_state');
          }
          throw error;
        }
        if (
          !matchEvaluationFingerprintContentAgrees(
            fingerprintContent(command),
            projectionContent(peerProjection),
          )
        ) {
          return rejected('immutable_conflict');
        }
      }
      const occurrence = await tx.componentOccurrence.findFirst({
        where: { organizationId: command.organizationId, id: command.componentOccurrenceId },
        select: {
          id: true,
          organizationId: true,
          assetId: true,
          sbomId: true,
          sbomIngestionId: true,
          componentId: true,
          version: true,
          versionKnown: true,
        },
      });
      if (occurrence === null) {
        return rejected('component_occurrence_missing');
      }
      if (
        occurrence.assetId !== command.assetId ||
        occurrence.sbomId !== command.sbomId ||
        occurrence.sbomIngestionId !== command.sbomIngestionId ||
        occurrence.componentId !== command.componentId ||
        occurrence.version !== command.rawObservedVersion ||
        occurrence.versionKnown !== command.versionKnown
      ) {
        return rejected('component_evidence_mismatch');
      }
      const component = await tx.component.findFirst({
        where: { organizationId: command.organizationId, id: command.componentId },
        select: {
          identityKey: true,
          ecosystem: true,
          namespace: true,
          name: true,
          identityState: true,
        },
      });
      const sbom = await tx.sbom.findFirst({
        where: {
          organizationId: command.organizationId,
          id: command.sbomId,
          assetId: command.assetId,
        },
        select: { sha256: true },
      });
      const ingestion = await tx.sbomIngestion.findFirst({
        where: {
          organizationId: command.organizationId,
          id: command.sbomIngestionId,
          sbomId: command.sbomId,
          assetId: command.assetId,
        },
        select: { id: true },
      });
      if (
        component === null ||
        sbom === null ||
        ingestion === null ||
        component.identityState !== 'resolved' ||
        component.ecosystem !== 'npm' ||
        component.name !== command.packageName ||
        component.namespace !== command.packageNamespace ||
        component.identityKey !== command.componentIdentityKey ||
        storedSha256(sbom.sha256) !== command.sbomSha256
      ) {
        return rejected('component_evidence_mismatch');
      }
      const row = await tx.matchEvaluationEvidence.create({
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
          evidenceSchemaVersion: command.evidenceSchemaVersion,
          evaluationId: command.evaluationId,
          evaluatorId: command.evaluatorId,
          evaluatorVersion: command.evaluatorVersion,
          evaluatorImplementation: command.evaluatorImplementation,
          policyId: command.policyId,
          ecosystem: command.ecosystem,
          packageNamespace: command.packageNamespace,
          packageName: command.packageName,
          packageIdentityKey: command.packageIdentityKey,
          rawObservedVersion: command.rawObservedVersion,
          rawObservedVersionSha256: command.rawObservedVersionSha256,
          rawObservedVersionRetention: command.rawObservedVersionRetention,
          parsedVersionClassification: command.parsedVersionClassification,
          advisoryIdentity: command.advisoryIdentity,
          advisorySourceClassification: command.advisorySourceClassification,
          advisoryEvidenceFingerprint: command.advisoryEvidenceFingerprint,
          advisoryEvidenceOrigin: command.advisoryEvidenceOrigin,
          rangeFingerprint: command.rangeFingerprint,
          outcome: command.outcome,
          replayFingerprint: command.replayFingerprint,
          findingCreation: command.findingCreation,
          suppressionAuthority: false,
          evaluationTimestampClassification: command.evaluationTimestampClassification,
          explanations: {
            create: command.explanationCodes.map((explanationCode, index) => ({
              ordinal: index + 1,
              explanationCode,
            })),
          },
        },
        select: EVIDENCE_SELECT,
      });
      return {
        kind: 'recorded' as const,
        projection: projectRow(row),
        counts: {
          inserts: 1 as const,
          updates: 0 as const,
          deletes: 0 as const,
          evaluatorCalls: 0 as const,
        },
      };
    });
  }
}
