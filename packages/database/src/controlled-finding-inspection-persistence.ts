/**
 * Controlled Finding inspection read.
 * One organization-scoped read projects stored lineage.
 * The API finding operator runtime is the only production constructor.
 * Web, worker, seed, and the package barrel do not construct this adapter.
 * The read does not insert, update, or delete a Finding.
 * Legal repeated observations stay internal and do not enter the projection.
 */

import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  classifyInspectionObservationShape,
  type FindingInspectionEvidenceBundle,
  type FindingInspectionLinkRecord,
  type FindingInspectionLoad,
  type FindingInspectionObservationRecord,
  type FindingInspectionPort,
} from '@patchpilot/domain';

import { repeatedObservationInspectionAgrees } from './controlled-finding-inspection-repeated-validation.js';
import { isRootPrismaClient } from './guards.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const OBSERVATION_EVIDENCE_KEYS = [
  'affectedEvidenceCount',
  'evidenceSetFingerprint',
  'policyId',
  'policyVersion',
  'purpose',
  'schemaVersion',
  'transition',
] as const;

export function createControlledFindingInspectionPersistence(
  client: PrismaClient,
): FindingInspectionPort {
  if (!isRootPrismaClient(client)) {
    throw new Error('Finding inspection requires the root database client.');
  }
  return {
    async load(query): Promise<FindingInspectionLoad> {
      if (!isUuid(query.organizationId) || !isUuid(query.findingId)) {
        return { status: 'internal_failure' };
      }
      try {
        return await client.$transaction(
          async (tx) => {
            await tx.$queryRaw`SELECT set_config('transaction_read_only', 'on', true)`;
            return loadInTransaction(tx, query.organizationId, query.findingId);
          },
          { isolationLevel: 'RepeatableRead' },
        );
      } catch (error) {
        return { status: translateFailure(error) };
      }
    },
  };
}

async function loadInTransaction(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<FindingInspectionLoad> {
  const finding = await tx.finding.findFirst({
    where: { organizationId, id: findingId },
    select: {
      id: true,
      state: true,
      createdAt: true,
      firstObservedAt: true,
      lastObservedAt: true,
      updatedAt: true,
      assetId: true,
      componentId: true,
      vulnerabilityId: true,
      componentOccurrenceId: true,
      resolvedAt: true,
      reopenedAt: true,
      assignedMembershipId: true,
      assignedTeamId: true,
      dueAt: true,
      currentRiskCalculationId: true,
      version: true,
      asset: {
        select: {
          id: true,
          organizationId: true,
          name: true,
          lastSuccessfulSbomIngestionId: true,
        },
      },
      component: {
        select: {
          id: true,
          organizationId: true,
          ecosystem: true,
          namespace: true,
          name: true,
        },
      },
      vulnerability: {
        select: { id: true, osvId: true },
      },
    },
  });
  if (finding === null) {
    return { status: 'not_found' };
  }
  const [
    observations,
    links,
    remediationTaskCount,
    riskAcceptanceCount,
    riskCalculationCount,
    genericEvidenceCount,
  ] = await Promise.all([
    tx.findingObservation.findMany({
      where: { organizationId, findingId: finding.id },
      select: {
        id: true,
        sbomIngestionId: true,
        occurrenceId: true,
        result: true,
        method: true,
        transitionClassification: true,
        creationPurpose: true,
        creationPolicyId: true,
        creationPolicyVersion: true,
        affectedEvidenceCount: true,
        replayFingerprint: true,
        evidence: true,
        observationPurpose: true,
        observationPolicyId: true,
        observationPolicyVersion: true,
        aggregateClassification: true,
        evidenceLinkCount: true,
      },
    }),
    tx.findingCreationEvidenceLink.findMany({
      where: { organizationId, findingId: finding.id },
      select: {
        findingObservationId: true,
        productMatchEvaluationEvidenceId: true,
        assetId: true,
        componentId: true,
        vulnerabilityId: true,
        sbomIngestionId: true,
        componentOccurrenceId: true,
        outcome: true,
      },
    }),
    tx.remediationTask.count({ where: { organizationId, findingId: finding.id } }),
    tx.riskAcceptance.count({ where: { organizationId, findingId: finding.id } }),
    tx.riskCalculation.count({ where: { organizationId, findingId: finding.id } }),
    tx.evidence.count({ where: { organizationId, findingId: finding.id } }),
  ]);

  const creationRows = [];
  for (const row of observations) {
    const shape = classifyInspectionObservationShape({
      method: row.method,
      result: row.result,
      occurrenceId: row.occurrenceId,
      transitionClassification: row.transitionClassification,
      creationPurpose: row.creationPurpose,
      creationPolicyId: row.creationPolicyId,
      creationPolicyVersion: row.creationPolicyVersion,
      observationPurpose: row.observationPurpose,
      observationPolicyId: row.observationPolicyId,
      observationPolicyVersion: row.observationPolicyVersion,
      aggregate: row.aggregateClassification,
    });
    if (shape.role === 'creation_observation') {
      creationRows.push(row);
    } else if (shape.role !== 'later_observation') {
      return { status: 'malformed_persisted_state' };
    }
  }
  if (creationRows.length !== 1) {
    return { status: 'malformed_persisted_state' };
  }
  const repeatedAgrees = await repeatedObservationInspectionAgrees(tx, {
    organizationId,
    findingId: finding.id,
    assetId: finding.assetId,
    componentId: finding.componentId,
    vulnerabilityId: finding.vulnerabilityId,
    firstObservedAt: finding.firstObservedAt,
    lastObservedAt: finding.lastObservedAt,
    createdAt: finding.createdAt,
    updatedAt: finding.updatedAt,
  });
  if (!repeatedAgrees) {
    return { status: 'malformed_persisted_state' };
  }
  const observation = creationRows[0];
  if (observation === undefined) {
    return { status: 'malformed_persisted_state' };
  }
  const occurrenceScope = await countOccurrences(tx, {
    organizationId,
    assetId: finding.assetId,
    componentId: finding.componentId,
    sbomIngestionId: observation.sbomIngestionId,
    linkedOccurrenceIds: links.map((link) => link.componentOccurrenceId),
  });

  const evidenceRows =
    links.length === 0
      ? []
      : await tx.productMatchEvaluationEvidence.findMany({
          where: {
            organizationId,
            id: { in: links.map((link) => link.productMatchEvaluationEvidenceId) },
          },
          select: {
            id: true,
            organizationId: true,
            outcome: true,
            productOrigin: true,
            evaluatorId: true,
            evaluatorVersion: true,
            matchingPolicyId: true,
            matchingPolicyVersion: true,
            productEvidencePolicyId: true,
            productEvidencePolicyVersion: true,
            evidenceSchemaVersion: true,
            findingCreation: true,
            suppressionAuthority: true,
            rawObservedVersion: true,
            advisoryRevisionId: true,
            vulnerabilityId: true,
            assetId: true,
            componentId: true,
            sbomIngestionId: true,
            componentOccurrenceId: true,
            explanations: {
              select: { explanationCode: true },
              orderBy: { ordinal: 'asc' },
            },
            revision: {
              select: {
                id: true,
                withdrawalClassification: true,
                quarantineClassification: true,
                successors: { select: { id: true }, take: 1 },
                binding: {
                  select: {
                    vulnerabilityId: true,
                    mappingReviewState: true,
                    conflictClassification: true,
                  },
                },
              },
            },
            approval: {
              select: {
                approvalPurpose: true,
                advisoryRevisionId: true,
                vulnerabilityId: true,
              },
            },
            componentOccurrence: {
              select: {
                id: true,
                organizationId: true,
                assetId: true,
                componentId: true,
                sbomIngestionId: true,
                version: true,
                versionKnown: true,
              },
            },
            sbomIngestion: {
              select: {
                id: true,
                organizationId: true,
                assetId: true,
                state: true,
                normalizationVersion: true,
              },
            },
          },
        });
  const evidenceById = new Map(evidenceRows.map((row) => [row.id, row]));
  const linkRecords = links.map((link) =>
    mapLink(organizationId, link, evidenceById.get(link.productMatchEvaluationEvidenceId)),
  );
  const evidenceIds = [...linkRecords.map((link) => link.evidenceId)].sort(compareUuid);
  const fingerprint = creationEvidenceFingerprint(evidenceIds);
  const mappedObservations: FindingInspectionObservationRecord[] = creationRows.map((row) => ({
    id: row.id,
    sbomIngestionId: row.sbomIngestionId,
    occurrenceId: row.occurrenceId,
    result: row.result,
    method: row.method,
    transitionClassification: row.transitionClassification,
    creationPurpose: row.creationPurpose,
    creationPolicyId: row.creationPolicyId,
    creationPolicyVersion: row.creationPolicyVersion,
    affectedEvidenceCount: row.affectedEvidenceCount,
    replayAgrees: row.replayFingerprint === fingerprint,
    evidenceRecordAgrees: evidenceRecordAgrees(
      row.evidence,
      row.replayFingerprint,
      row.affectedEvidenceCount,
    ),
  }));

  const bundle: FindingInspectionEvidenceBundle = {
    findingId: finding.id,
    state: finding.state,
    createdAt: timestamp(finding.createdAt),
    assetId: finding.assetId,
    componentId: finding.componentId,
    vulnerabilityId: finding.vulnerabilityId,
    componentOccurrenceId: finding.componentOccurrenceId,
    resolvedAt: timestamp(finding.resolvedAt),
    reopenedAt: timestamp(finding.reopenedAt),
    assignedMembershipId: finding.assignedMembershipId,
    assignedTeamId: finding.assignedTeamId,
    dueAt: timestamp(finding.dueAt),
    currentRiskCalculationId: finding.currentRiskCalculationId,
    version: finding.version,
    assetPresent: finding.asset !== null && finding.asset.organizationId === organizationId,
    assetDisplayName: finding.asset?.name ?? null,
    assetCurrentIngestionId: finding.asset?.lastSuccessfulSbomIngestionId ?? null,
    componentPresent:
      finding.component !== null && finding.component.organizationId === organizationId,
    componentEcosystem: finding.component?.ecosystem ?? null,
    componentNamespace: finding.component?.namespace ?? null,
    componentName: finding.component?.name ?? null,
    vulnerabilityPresent: finding.vulnerability !== null,
    vulnerabilityPublicId: finding.vulnerability?.osvId ?? null,
    remediationTaskCount,
    riskAcceptanceCount,
    riskCalculationCount,
    genericEvidenceCount,
    creationIngestionOccurrenceCount: occurrenceScope.creationIngestionOccurrenceCount,
    otherOccurrenceCount: occurrenceScope.otherOccurrenceCount,
    observations: mappedObservations,
    links: linkRecords,
  };
  return { status: 'ready', bundle };
}

async function countOccurrences(
  tx: Prisma.TransactionClient,
  scope: {
    readonly organizationId: string;
    readonly assetId: string;
    readonly componentId: string;
    readonly sbomIngestionId: string;
    readonly linkedOccurrenceIds: readonly string[];
  },
): Promise<{
  readonly creationIngestionOccurrenceCount: number;
  readonly otherOccurrenceCount: number;
}> {
  const where = {
    organizationId: scope.organizationId,
    assetId: scope.assetId,
    componentId: scope.componentId,
    sbomIngestionId: scope.sbomIngestionId,
  };
  const creationIngestionOccurrenceCount = await tx.componentOccurrence.count({ where });
  const linkedInIngestion =
    scope.linkedOccurrenceIds.length === 0
      ? 0
      : await tx.componentOccurrence.count({
          where: { ...where, id: { in: [...scope.linkedOccurrenceIds] } },
        });
  return {
    creationIngestionOccurrenceCount,
    otherOccurrenceCount: creationIngestionOccurrenceCount - linkedInIngestion,
  };
}

function mapLink(
  organizationId: string,
  link: LinkRow,
  stored: EvidenceRow | undefined,
): FindingInspectionLinkRecord {
  const aligned = evidenceTargetAligned(link, stored);
  const evidence = aligned ? (stored ?? null) : null;
  const occurrence = evidence?.componentOccurrence ?? null;
  const revision = evidence?.revision ?? null;
  const approval = evidence?.approval ?? null;
  const ingestion = evidence?.sbomIngestion ?? null;
  const binding = revision?.binding ?? null;
  return {
    evidenceId: link.productMatchEvaluationEvidenceId,
    findingObservationId: link.findingObservationId,
    assetId: link.assetId,
    componentId: link.componentId,
    vulnerabilityId: link.vulnerabilityId,
    sbomIngestionId: link.sbomIngestionId,
    componentOccurrenceId: link.componentOccurrenceId,
    linkOutcome: link.outcome,
    evidencePresent: evidence !== null && evidence.organizationId === organizationId,
    evidenceTargetAligned: stored === undefined || aligned,
    evidenceOutcome: evidence?.outcome ?? null,
    productOrigin: evidence?.productOrigin ?? null,
    evaluatorId: evidence?.evaluatorId ?? null,
    evaluatorVersion: evidence?.evaluatorVersion ?? null,
    matchingPolicyId: evidence?.matchingPolicyId ?? null,
    matchingPolicyVersion: evidence?.matchingPolicyVersion ?? null,
    productEvidencePolicyId: evidence?.productEvidencePolicyId ?? null,
    productEvidencePolicyVersion: evidence?.productEvidencePolicyVersion ?? null,
    evidenceSchemaVersion: evidence?.evidenceSchemaVersion ?? null,
    findingCreation: evidence?.findingCreation ?? null,
    suppressionAuthority: evidence?.suppressionAuthority ?? null,
    rawObservedVersion: evidence?.rawObservedVersion ?? null,
    occurrencePresent:
      occurrence !== null &&
      occurrence.organizationId === organizationId &&
      occurrence.id === link.componentOccurrenceId,
    occurrenceVersion: occurrence?.version ?? null,
    occurrenceVersionKnown: occurrence?.versionKnown ?? null,
    occurrenceAssetId: occurrence?.assetId ?? null,
    occurrenceComponentId: occurrence?.componentId ?? null,
    occurrenceIngestionId: occurrence?.sbomIngestionId ?? null,
    revisionPresent: revision !== null,
    withdrawal: revision?.withdrawalClassification ?? null,
    quarantine: revision?.quarantineClassification ?? null,
    hasSuccessor: (revision?.successors.length ?? 0) > 0,
    approvalPresent: approval !== null,
    approvalPurpose: approval?.approvalPurpose ?? null,
    approvalRevisionMatches:
      approval !== null &&
      evidence !== null &&
      approval.advisoryRevisionId === evidence.advisoryRevisionId,
    approvalVulnerabilityMatches:
      approval !== null &&
      evidence !== null &&
      approval.vulnerabilityId === evidence.vulnerabilityId,
    bindingPresent: binding !== null,
    bindingReviewed:
      binding !== null &&
      evidence !== null &&
      binding.mappingReviewState === 'reviewed' &&
      binding.conflictClassification === 'none' &&
      binding.vulnerabilityId === evidence.vulnerabilityId,
    normalizationVersion: ingestion?.normalizationVersion ?? null,
    ingestionState: ingestion?.state ?? null,
    ingestionPresent:
      ingestion !== null &&
      ingestion.organizationId === organizationId &&
      ingestion.id === link.sbomIngestionId &&
      ingestion.assetId === link.assetId,
    explanationCodes: evidence?.explanations.map((row) => row.explanationCode) ?? [],
  };
}

type EvidenceRow = {
  readonly id: string;
  readonly organizationId: string;
  readonly outcome: string;
  readonly productOrigin: string;
  readonly evaluatorId: string;
  readonly evaluatorVersion: string;
  readonly matchingPolicyId: string;
  readonly matchingPolicyVersion: string;
  readonly productEvidencePolicyId: string;
  readonly productEvidencePolicyVersion: number;
  readonly evidenceSchemaVersion: string;
  readonly findingCreation: string;
  readonly suppressionAuthority: boolean;
  readonly rawObservedVersion: string;
  readonly advisoryRevisionId: string;
  readonly vulnerabilityId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly sbomIngestionId: string;
  readonly componentOccurrenceId: string;
  readonly explanations: readonly { explanationCode: string }[];
  readonly revision: {
    id: string;
    withdrawalClassification: string;
    quarantineClassification: string;
    successors: readonly { id: string }[];
    binding: {
      vulnerabilityId: string;
      mappingReviewState: string;
      conflictClassification: string;
    } | null;
  } | null;
  readonly approval: {
    approvalPurpose: string;
    advisoryRevisionId: string;
    vulnerabilityId: string;
  } | null;
  readonly componentOccurrence: {
    id: string;
    organizationId: string;
    assetId: string;
    componentId: string;
    sbomIngestionId: string;
    version: string;
    versionKnown: boolean;
  } | null;
  readonly sbomIngestion: {
    id: string;
    organizationId: string;
    assetId: string;
    state: string;
    normalizationVersion: string;
  } | null;
};

function evidenceTargetAligned(link: LinkRow, stored: EvidenceRow | undefined): boolean {
  if (stored === undefined) {
    return true;
  }
  return (
    stored.assetId === link.assetId &&
    stored.componentId === link.componentId &&
    stored.vulnerabilityId === link.vulnerabilityId &&
    stored.sbomIngestionId === link.sbomIngestionId &&
    stored.componentOccurrenceId === link.componentOccurrenceId
  );
}

type LinkRow = {
  findingObservationId: string;
  productMatchEvaluationEvidenceId: string;
  assetId: string;
  componentId: string;
  vulnerabilityId: string;
  sbomIngestionId: string;
  componentOccurrenceId: string;
  outcome: string;
};

function evidenceRecordAgrees(
  evidence: Prisma.JsonValue,
  fingerprint: string | null,
  count: number | null,
): boolean {
  if (fingerprint === null || count === null) {
    return false;
  }
  if (typeof evidence !== 'object' || evidence === null || Array.isArray(evidence)) {
    return false;
  }
  const keys = Object.keys(evidence).sort(compareDisplay);
  if (keys.length !== OBSERVATION_EVIDENCE_KEYS.length) {
    return false;
  }
  for (let index = 0; index < OBSERVATION_EVIDENCE_KEYS.length; index += 1) {
    if (keys[index] !== OBSERVATION_EVIDENCE_KEYS[index]) {
      return false;
    }
  }
  return (
    evidence['schemaVersion'] === 'finding_creation_observation_v1' &&
    evidence['transition'] === 'initial_creation' &&
    evidence['purpose'] === FINDING_CREATION_PURPOSE &&
    evidence['policyId'] === FINDING_CREATION_POLICY_ID &&
    evidence['policyVersion'] === FINDING_CREATION_POLICY_VERSION &&
    evidence['affectedEvidenceCount'] === count &&
    evidence['evidenceSetFingerprint'] === fingerprint
  );
}

function creationEvidenceFingerprint(ids: readonly string[]): string {
  const fields = [
    lengthPrefixed('schema', FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION),
    lengthPrefixed('count', String(ids.length)),
  ];
  for (let index = 0; index < ids.length; index += 1) {
    const id = ids[index];
    if (id === undefined) {
      return '';
    }
    fields.push(lengthPrefixed(`id.${String(index)}`, id));
  }
  return createHash('sha256').update(fields.join('|'), 'utf8').digest('hex');
}

function lengthPrefixed(name: string, value: string): string {
  return `${String(name.length)}:${name}${String(value.length)}:${value}`;
}

function compareUuid(left: string, right: string): number {
  return compareDisplay(left, right);
}

function compareDisplay(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function timestamp(value: Date | null): string | null {
  if (value === null || Number.isNaN(value.getTime())) {
    return null;
  }
  return value.toISOString();
}

function isUuid(value: string): boolean {
  return UUID_LOWER_PATTERN.test(value);
}

function translateFailure(error: unknown): 'database_unavailable' | 'internal_failure' {
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return 'database_unavailable';
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (
      error.code === 'P1001' ||
      error.code === 'P1002' ||
      error.code === 'P1008' ||
      error.code === 'P1017' ||
      error.code === 'P2024'
    ) {
      return 'database_unavailable';
    }
  }
  return 'internal_failure';
}
