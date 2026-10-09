/**
 * Internal read validation for legal repeated observations.
 * The public inspection bundle stays on the creation observation.
 * This module does not write, expose support rows, or infer a lifecycle.
 */

import { Prisma } from '@prisma/client';
import {
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID,
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION,
  FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA,
  FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_ORIGIN,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION,
} from '../../domain/dist/findings/controlled-inspection/policy.js';
import { canonicalRepeatedObservationReplayFingerprint } from '../../domain/dist/findings/controlled-observation/support.js';
import {
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
  classifyInspectionObservationShape,
} from '@patchpilot/domain';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const NORMALIZATION_VERSION = String(FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION);

const EVIDENCE_KEYS = [
  'aggregate',
  'evidenceLinkCount',
  'mappedResult',
  'policyId',
  'policyVersion',
  'purpose',
  'replayFingerprint',
  'schemaVersion',
] as const;

export type RepeatedObservationInspectionTarget = {
  readonly organizationId: string;
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly firstObservedAt: Date;
  readonly lastObservedAt: Date;
  readonly createdAt: Date;
  readonly updatedAt: Date;
};

export type RepeatedObservationSupportFact = {
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomId: string;
  readonly sbomIngestionId: string;
  readonly occurrenceId: string;
  readonly supportKind: string;
  readonly evidenceId: string | null;
  readonly outcome: string | null;
  readonly occurrenceVersionKnown: boolean | null;
  readonly occurrenceAligned: boolean;
  readonly evidenceOutcome: string | null;
  readonly evidenceAligned: boolean;
  readonly productOrigin: string | null;
  readonly evaluatorId: string | null;
  readonly evaluatorVersion: string | null;
  readonly matchingPolicyId: string | null;
  readonly matchingPolicyVersion: string | null;
  readonly productEvidencePolicyId: string | null;
  readonly productEvidencePolicyVersion: number | null;
  readonly evidenceSchemaVersion: string | null;
  readonly findingCreation: string | null;
  readonly suppressionAuthority: boolean | null;
  readonly occurrenceVersion: string | null;
  readonly evidenceRawObservedVersion: string | null;
};

export type RepeatedObservationFact = {
  readonly organizationId: string;
  readonly findingId: string;
  readonly sbomId: string;
  readonly sbomIngestionId: string;
  readonly method: string;
  readonly result: string;
  readonly occurrenceId: string | null;
  readonly transitionClassification: string | null;
  readonly creationPurpose: string | null;
  readonly creationPolicyId: string | null;
  readonly creationPolicyVersion: number | null;
  readonly observationPurpose: string | null;
  readonly observationPolicyId: string | null;
  readonly observationPolicyVersion: number | null;
  readonly aggregate: string | null;
  readonly evidenceLinkCount: number | null;
  readonly replayFingerprint: string;
  readonly actorMembershipId: string | null;
  readonly correlationId: string | null;
  readonly observedAt: string;
  readonly createdAt: string;
  readonly membershipPresent: boolean;
  readonly absenceGraphCompleteness: string | null;
  readonly absenceComponentCount: number | null;
  readonly absenceDependencyEdgeCount: number | null;
  readonly evidence: unknown;
  readonly unknownVersionOccurrenceHasEvidence: boolean;
  readonly ingestion: {
    readonly present: boolean;
    readonly organizationId: string | null;
    readonly assetId: string | null;
    readonly sbomId: string | null;
    readonly state: string | null;
    readonly normalizationVersion: string | null;
    readonly strictlyLater: boolean;
    readonly graphCompleteness: string | null;
    readonly componentCount: number | null;
    readonly dependencyEdgeCount: number | null;
    readonly liveComponentCount: number;
    readonly liveEdgeCount: number;
    readonly targetOccurrenceIds: readonly string[];
  };
  readonly links: readonly RepeatedObservationSupportFact[];
};

export type RepeatedObservationInspectionFacts = {
  readonly target: {
    readonly organizationId: string;
    readonly findingId: string;
    readonly assetId: string;
    readonly componentId: string;
    readonly vulnerabilityId: string;
  };
  readonly finding: {
    readonly firstObservedAt: string;
    readonly lastObservedAt: string;
    readonly createdAt: string;
    readonly updatedAt: string;
  };
  readonly creation: {
    readonly observedAt: string;
    readonly createdAt: string;
    readonly sbomIngestionId: string;
  };
  readonly repeated: readonly RepeatedObservationFact[];
};

type ObservationRow = {
  id: string;
  organizationId: string;
  findingId: string;
  sbomId: string;
  sbomIngestionId: string;
  occurrenceId: string | null;
  result: string;
  method: string;
  transitionClassification: string | null;
  creationPurpose: string | null;
  creationPolicyId: string | null;
  creationPolicyVersion: number | null;
  observationPurpose: string | null;
  observationPolicyId: string | null;
  observationPolicyVersion: number | null;
  aggregateClassification: string | null;
  evidenceLinkCount: number | null;
  replayFingerprint: string | null;
  evidence: Prisma.JsonValue;
  actorMembershipId: string | null;
  correlationId: string | null;
  observedAt: Date;
  createdAt: Date;
  absenceGraphCompleteness: string | null;
  absenceComponentCount: number | null;
  absenceDependencyEdgeCount: number | null;
};

type LinkRow = {
  findingId: string;
  findingObservationId: string;
  sbomId: string;
  productMatchEvaluationEvidenceId: string | null;
  assetId: string;
  componentId: string;
  vulnerabilityId: string;
  sbomIngestionId: string;
  componentOccurrenceId: string;
  supportKind: string;
  outcome: string | null;
};

type OccurrenceRow = {
  id: string;
  organizationId: string;
  assetId: string;
  componentId: string;
  sbomIngestionId: string;
  version: string | null;
  versionKnown: boolean | null;
};

type EvidenceRow = {
  id: string;
  organizationId: string;
  outcome: string;
  assetId: string;
  componentId: string;
  vulnerabilityId: string;
  sbomIngestionId: string;
  componentOccurrenceId: string;
  productOrigin: string;
  evaluatorId: string;
  evaluatorVersion: string;
  matchingPolicyId: string;
  matchingPolicyVersion: string;
  productEvidencePolicyId: string;
  productEvidencePolicyVersion: number;
  evidenceSchemaVersion: string;
  findingCreation: string;
  suppressionAuthority: boolean;
  rawObservedVersion: string;
};

type IngestionRow = {
  id: string;
  organizationId: string;
  assetId: string;
  sbomId: string;
  state: string;
  normalizationVersion: string;
  graphCompleteness: string | null;
  componentCount: number | null;
  dependencyEdgeCount: number | null;
};

type Tx = Prisma.TransactionClient;

export async function repeatedObservationInspectionAgrees(
  tx: Tx,
  finding: RepeatedObservationInspectionTarget,
): Promise<boolean> {
  const observations = await tx.findingObservation.findMany({
    where: { organizationId: finding.organizationId, findingId: finding.findingId },
    select: {
      id: true,
      organizationId: true,
      findingId: true,
      sbomId: true,
      sbomIngestionId: true,
      occurrenceId: true,
      result: true,
      method: true,
      transitionClassification: true,
      creationPurpose: true,
      creationPolicyId: true,
      creationPolicyVersion: true,
      observationPurpose: true,
      observationPolicyId: true,
      observationPolicyVersion: true,
      aggregateClassification: true,
      evidenceLinkCount: true,
      replayFingerprint: true,
      evidence: true,
      actorMembershipId: true,
      correlationId: true,
      observedAt: true,
      createdAt: true,
      absenceGraphCompleteness: true,
      absenceComponentCount: true,
      absenceDependencyEdgeCount: true,
    },
  });
  const creationRows: ObservationRow[] = [];
  const laterRows: ObservationRow[] = [];
  for (const row of observations) {
    const role = observationRole(row);
    if (role === 'creation_observation') {
      creationRows.push(row);
    } else if (role === 'later_observation') {
      laterRows.push(row);
    } else {
      return false;
    }
  }
  const creation = creationRows.length === 1 ? creationRows[0] : undefined;
  if (creation === undefined) {
    return false;
  }
  const facts = await inspectionFacts(tx, finding, creation, laterRows);
  if (facts === null) {
    return false;
  }
  return repeatedObservationFactsAgree(facts);
}

export function repeatedSupportLinksStayOnLaterObservations(
  laterObservationIds: readonly string[],
  linkObservationIds: readonly string[],
): boolean {
  const later = new Set(laterObservationIds);
  if (later.size !== laterObservationIds.length) {
    return false;
  }
  for (const id of linkObservationIds) {
    if (!later.has(id)) {
      return false;
    }
  }
  return true;
}

export function repeatedObservationFactsAgree(facts: RepeatedObservationInspectionFacts): boolean {
  try {
    return factsAgree(facts);
  } catch {
    return false;
  }
}

function factsAgree(facts: RepeatedObservationInspectionFacts): boolean {
  if (!timestampsAgree(facts)) {
    return false;
  }
  const ingestions = new Set<string>();
  for (const observation of facts.repeated) {
    if (!oneRepeatedAgrees(facts, observation)) {
      return false;
    }
    if (ingestions.has(observation.sbomIngestionId)) {
      return false;
    }
    ingestions.add(observation.sbomIngestionId);
  }
  return true;
}

function oneRepeatedAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
): boolean {
  const target = facts.target;
  if (
    observation.organizationId !== target.organizationId ||
    observation.findingId !== target.findingId ||
    observation.sbomIngestionId === facts.creation.sbomIngestionId ||
    !isUuid(observation.sbomId) ||
    !isUuid(observation.sbomIngestionId) ||
    !isUuid(observation.actorMembershipId) ||
    !observation.membershipPresent ||
    !isUuid(observation.correlationId) ||
    !FINGERPRINT_PATTERN.test(observation.replayFingerprint) ||
    classifyInspectionObservationShape(shapeInput(observation)).role !== 'later_observation' ||
    !evidenceRecordAgrees(observation) ||
    !ingestionAgrees(facts, observation)
  ) {
    return false;
  }
  if (observation.aggregate === 'component_absent') {
    return absenceAgrees(facts, observation);
  }
  return supportAgrees(facts, observation);
}

function absenceAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
): boolean {
  const graph = observation.absenceGraphCompleteness;
  const components = observation.absenceComponentCount;
  const edges = observation.absenceDependencyEdgeCount;
  const ingestion = observation.ingestion;
  if (
    observation.result !== 'absent' ||
    observation.evidenceLinkCount !== 0 ||
    observation.links.length !== 0 ||
    observation.ingestion.targetOccurrenceIds.length !== 0 ||
    observation.unknownVersionOccurrenceHasEvidence ||
    (graph !== 'complete' && graph !== 'no_dependencies') ||
    components === null ||
    edges === null ||
    !Number.isInteger(components) ||
    !Number.isInteger(edges) ||
    components < 1 ||
    components > 100_000 ||
    edges < 0 ||
    edges > 100_000 ||
    (graph === 'complete' && edges < 1) ||
    (graph === 'no_dependencies' && edges !== 0) ||
    ingestion.graphCompleteness !== graph ||
    ingestion.componentCount !== components ||
    ingestion.dependencyEdgeCount !== edges ||
    ingestion.liveComponentCount !== components ||
    ingestion.liveEdgeCount !== edges
  ) {
    return false;
  }
  const supportFingerprint = canonicalRepeatedObservationAbsenceFingerprint({
    sbomIngestionId: observation.sbomIngestionId,
    graphCompleteness: graph,
    componentCount: components,
    occurrenceCardinality: components,
    dependencyEdgeCount: edges,
  });
  return replayAgrees(facts, observation, supportFingerprint, 0);
}

function supportAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
): boolean {
  const count = observation.evidenceLinkCount;
  if (
    observation.absenceGraphCompleteness !== null ||
    observation.absenceComponentCount !== null ||
    observation.absenceDependencyEdgeCount !== null ||
    count === null ||
    !Number.isInteger(count) ||
    count < 1 ||
    count > FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS ||
    observation.links.length !== count ||
    observation.unknownVersionOccurrenceHasEvidence
  ) {
    return false;
  }
  const occurrenceIds: string[] = [];
  const evidenceIds: string[] = [];
  const unknownIds: string[] = [];
  for (const link of observation.links) {
    if (!linkAgrees(facts, observation, link)) {
      return false;
    }
    occurrenceIds.push(link.occurrenceId);
    if (link.supportKind === 'unknown_version_occurrence') {
      unknownIds.push(link.occurrenceId);
    } else if (link.evidenceId !== null) {
      evidenceIds.push(link.evidenceId);
    }
  }
  if (
    !sameUniqueIds(occurrenceIds, observation.ingestion.targetOccurrenceIds) ||
    new Set(evidenceIds).size !== evidenceIds.length
  ) {
    return false;
  }
  evidenceIds.sort(compareUuid);
  unknownIds.sort(compareUuid);
  const supportFingerprint = canonicalRepeatedObservationEvidenceFingerprint(
    evidenceIds,
    unknownIds,
    count,
  );
  const derived = derivedAggregate(observation.links);
  if (derived === null || derived !== observation.aggregate) {
    return false;
  }
  return replayAgrees(facts, observation, supportFingerprint, count);
}

function linkAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
  link: RepeatedObservationSupportFact,
): boolean {
  const target = facts.target;
  if (
    link.findingId !== target.findingId ||
    link.assetId !== target.assetId ||
    link.componentId !== target.componentId ||
    link.vulnerabilityId !== target.vulnerabilityId ||
    link.sbomId !== observation.sbomId ||
    link.sbomIngestionId !== observation.sbomIngestionId ||
    !isUuid(link.occurrenceId) ||
    !link.occurrenceAligned
  ) {
    return false;
  }
  if (link.supportKind === 'unknown_version_occurrence') {
    return (
      link.evidenceId === null &&
      link.outcome === null &&
      link.occurrenceVersionKnown === false &&
      link.evidenceOutcome === null &&
      link.evidenceAligned === false &&
      link.productOrigin === null &&
      link.evaluatorId === null &&
      link.evaluatorVersion === null &&
      link.matchingPolicyId === null &&
      link.matchingPolicyVersion === null &&
      link.productEvidencePolicyId === null &&
      link.productEvidencePolicyVersion === null &&
      link.evidenceSchemaVersion === null &&
      link.findingCreation === null &&
      link.suppressionAuthority === null &&
      link.evidenceRawObservedVersion === null
    );
  }
  if (link.supportKind !== 'product_match_evidence') {
    return false;
  }
  return (
    isUuid(link.evidenceId) &&
    link.occurrenceVersionKnown === true &&
    link.evidenceAligned === true &&
    link.outcome !== null &&
    link.evidenceOutcome === link.outcome &&
    (link.outcome === 'affected' || link.outcome === 'unaffected' || link.outcome === 'unknown') &&
    evidenceLineageAgrees(link)
  );
}

function evidenceLineageAgrees(link: RepeatedObservationSupportFact): boolean {
  return (
    link.productOrigin === FINDING_INSPECTION_ACCEPTED_ORIGIN &&
    link.evaluatorId === FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID &&
    link.evaluatorVersion === FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION &&
    link.matchingPolicyId === FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID &&
    link.matchingPolicyVersion === FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID &&
    link.productEvidencePolicyId === FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID &&
    link.productEvidencePolicyVersion === FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION &&
    link.evidenceSchemaVersion === FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA &&
    link.findingCreation === 'unavailable' &&
    link.suppressionAuthority === false &&
    link.occurrenceVersion !== null &&
    link.occurrenceVersion.length > 0 &&
    link.occurrenceVersion.length <= 256 &&
    !link.occurrenceVersion.includes('\u0000') &&
    link.evidenceRawObservedVersion === link.occurrenceVersion
  );
}

function derivedAggregate(links: readonly RepeatedObservationSupportFact[]): string | null {
  let affected = false;
  let unknown = false;
  for (const link of links) {
    if (link.supportKind === 'unknown_version_occurrence') {
      unknown = true;
      continue;
    }
    if (link.outcome === 'affected') {
      affected = true;
    } else if (link.outcome === 'unknown') {
      unknown = true;
    } else if (link.outcome !== 'unaffected') {
      return null;
    }
  }
  if (affected) {
    return 'affected';
  }
  if (unknown) {
    return 'unknown';
  }
  if (links.length === 0) {
    return null;
  }
  return 'unaffected';
}

function replayAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
  supportFingerprint: string,
  supportCount: number,
): boolean {
  if (observation.aggregate === null) {
    return false;
  }
  const replayFingerprint = canonicalRepeatedObservationReplayFingerprint({
    organizationId: facts.target.organizationId,
    findingId: facts.target.findingId,
    assetId: facts.target.assetId,
    componentId: facts.target.componentId,
    vulnerabilityId: facts.target.vulnerabilityId,
    sbomIngestionId: observation.sbomIngestionId,
    aggregate: observation.aggregate,
    mappedResult: observation.result,
    supportFingerprint,
    supportCount,
  });
  return observation.replayFingerprint === replayFingerprint;
}

function ingestionAgrees(
  facts: RepeatedObservationInspectionFacts,
  observation: RepeatedObservationFact,
): boolean {
  const ingestion = observation.ingestion;
  return (
    ingestion.present &&
    ingestion.organizationId === facts.target.organizationId &&
    ingestion.assetId === facts.target.assetId &&
    ingestion.sbomId === observation.sbomId &&
    ingestion.state === 'completed' &&
    ingestion.normalizationVersion === NORMALIZATION_VERSION &&
    ingestion.strictlyLater === true
  );
}

function evidenceRecordAgrees(observation: RepeatedObservationFact): boolean {
  const evidence = observation.evidence;
  if (typeof evidence !== 'object' || evidence === null || Array.isArray(evidence)) {
    return false;
  }
  const record = evidence as Record<string, unknown>;
  const keys = Object.keys(record).sort(compareUuid);
  if (keys.length !== EVIDENCE_KEYS.length) {
    return false;
  }
  for (let index = 0; index < EVIDENCE_KEYS.length; index += 1) {
    if (keys[index] !== EVIDENCE_KEYS[index]) {
      return false;
    }
  }
  return (
    record['schemaVersion'] === FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION &&
    record['purpose'] === FINDING_REPEATED_OBSERVATION_PURPOSE &&
    record['policyId'] === FINDING_REPEATED_OBSERVATION_POLICY_ID &&
    record['policyVersion'] === FINDING_REPEATED_OBSERVATION_POLICY_VERSION &&
    record['aggregate'] === observation.aggregate &&
    record['mappedResult'] === observation.result &&
    record['evidenceLinkCount'] === observation.evidenceLinkCount &&
    record['replayFingerprint'] === observation.replayFingerprint
  );
}

function timestampsAgree(facts: RepeatedObservationInspectionFacts): boolean {
  const first = instant(facts.finding.firstObservedAt);
  const last = instant(facts.finding.lastObservedAt);
  const created = instant(facts.finding.createdAt);
  const updated = instant(facts.finding.updatedAt);
  const observed = instant(facts.creation.observedAt);
  const creationCreated = instant(facts.creation.createdAt);
  if (
    first === null ||
    last === null ||
    created === null ||
    updated === null ||
    observed === null ||
    creationCreated === null ||
    first !== created ||
    first !== observed ||
    observed !== creationCreated ||
    last < first ||
    updated < created ||
    last !== updated
  ) {
    return false;
  }
  if (facts.repeated.length === 0) {
    return last === first;
  }
  let max = Number.NEGATIVE_INFINITY;
  let explainsLast = false;
  for (const observation of facts.repeated) {
    const at = instant(observation.observedAt);
    const rowCreated = instant(observation.createdAt);
    if (at === null || rowCreated === null || at !== rowCreated || at < first) {
      return false;
    }
    if (at === last) {
      explainsLast = true;
    }
    if (at > max) {
      max = at;
    }
  }
  return explainsLast && max === last;
}

async function inspectionFacts(
  tx: Tx,
  finding: RepeatedObservationInspectionTarget,
  creation: ObservationRow,
  laterRows: readonly ObservationRow[],
): Promise<RepeatedObservationInspectionFacts | null> {
  const creationObserved = stamp(creation.observedAt);
  const creationCreated = stamp(creation.createdAt);
  if (creationObserved === null || creationCreated === null) {
    return null;
  }
  const supportObservationIds = await tx.findingRepeatedObservationEvidenceLink.findMany({
    where: { organizationId: finding.organizationId, findingId: finding.findingId },
    select: { findingObservationId: true },
  });
  if (
    !repeatedSupportLinksStayOnLaterObservations(
      laterRows.map((row) => row.id),
      supportObservationIds.map((link) => link.findingObservationId),
    )
  ) {
    return null;
  }
  const repeated =
    laterRows.length === 0 ? [] : await repeatedFacts(tx, finding, creation, laterRows);
  if (repeated === null) {
    return null;
  }
  const first = stamp(finding.firstObservedAt);
  const last = stamp(finding.lastObservedAt);
  const created = stamp(finding.createdAt);
  const updated = stamp(finding.updatedAt);
  if (first === null || last === null || created === null || updated === null) {
    return null;
  }
  return {
    target: {
      organizationId: finding.organizationId,
      findingId: finding.findingId,
      assetId: finding.assetId,
      componentId: finding.componentId,
      vulnerabilityId: finding.vulnerabilityId,
    },
    finding: {
      firstObservedAt: first,
      lastObservedAt: last,
      createdAt: created,
      updatedAt: updated,
    },
    creation: {
      observedAt: creationObserved,
      createdAt: creationCreated,
      sbomIngestionId: creation.sbomIngestionId,
    },
    repeated,
  };
}

async function repeatedFacts(
  tx: Tx,
  finding: RepeatedObservationInspectionTarget,
  creation: ObservationRow,
  laterRows: readonly ObservationRow[],
): Promise<readonly RepeatedObservationFact[] | null> {
  const observationIds = laterRows.map((row) => row.id);
  const ingestionIds = [...new Set(laterRows.map((row) => row.sbomIngestionId))];
  const [links, occurrences, ingestions, laterFlags, componentCounts, edgeCounts] =
    await Promise.all([
      tx.findingRepeatedObservationEvidenceLink.findMany({
        where: {
          organizationId: finding.organizationId,
          findingId: finding.findingId,
          findingObservationId: { in: observationIds },
        },
        select: {
          findingId: true,
          findingObservationId: true,
          sbomId: true,
          productMatchEvaluationEvidenceId: true,
          assetId: true,
          componentId: true,
          vulnerabilityId: true,
          sbomIngestionId: true,
          componentOccurrenceId: true,
          supportKind: true,
          outcome: true,
        },
      }),
      tx.componentOccurrence.findMany({
        where: {
          organizationId: finding.organizationId,
          assetId: finding.assetId,
          componentId: finding.componentId,
          sbomIngestionId: { in: ingestionIds },
        },
        select: {
          id: true,
          organizationId: true,
          assetId: true,
          componentId: true,
          sbomIngestionId: true,
          version: true,
          versionKnown: true,
        },
      }),
      tx.sbomIngestion.findMany({
        where: {
          organizationId: finding.organizationId,
          assetId: finding.assetId,
          id: { in: ingestionIds },
        },
        select: {
          id: true,
          organizationId: true,
          assetId: true,
          sbomId: true,
          state: true,
          normalizationVersion: true,
          graphCompleteness: true,
          componentCount: true,
          dependencyEdgeCount: true,
        },
      }),
      laterThanCreation(tx, finding, creation.sbomIngestionId, ingestionIds),
      groupedCount(tx, 'component_occurrence', finding.organizationId, ingestionIds),
      groupedCount(tx, 'dependency_relationship', finding.organizationId, ingestionIds),
    ]);
  const evidenceIds = links
    .map((link) => link.productMatchEvaluationEvidenceId)
    .filter((id): id is string => id !== null);
  const unknownOccurrenceIds = links
    .filter((link) => link.supportKind === 'unknown_version_occurrence')
    .map((link) => link.componentOccurrenceId);
  const membershipIds = [
    ...new Set(
      laterRows.map((row) => row.actorMembershipId).filter((id): id is string => id !== null),
    ),
  ];
  const [evidenceRows, strayEvidence, memberships] = await Promise.all([
    evidenceIds.length === 0
      ? Promise.resolve([] as EvidenceRow[])
      : tx.productMatchEvaluationEvidence.findMany({
          where: { organizationId: finding.organizationId, id: { in: evidenceIds } },
          select: {
            id: true,
            organizationId: true,
            outcome: true,
            assetId: true,
            componentId: true,
            vulnerabilityId: true,
            sbomIngestionId: true,
            componentOccurrenceId: true,
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
          },
        }),
    unknownOccurrenceIds.length === 0
      ? Promise.resolve([] as { componentOccurrenceId: string }[])
      : tx.productMatchEvaluationEvidence.findMany({
          where: {
            organizationId: finding.organizationId,
            componentOccurrenceId: { in: unknownOccurrenceIds },
          },
          select: { componentOccurrenceId: true },
        }),
    membershipIds.length === 0
      ? Promise.resolve([] as { id: string }[])
      : tx.membership.findMany({
          where: { organizationId: finding.organizationId, id: { in: membershipIds } },
          select: { id: true },
        }),
  ]);
  const linksByObservation = groupBy(links, (link) => link.findingObservationId);
  const occurrencesByIngestion = groupBy(occurrences, (row) => row.sbomIngestionId);
  const occurrenceById = new Map(occurrences.map((row) => [row.id, row]));
  const evidenceById = new Map(evidenceRows.map((row) => [row.id, row]));
  const ingestionById = new Map(ingestions.map((row) => [row.id, row]));
  const laterById = new Map(laterFlags.map((row) => [row.id, row.strictly_later === true]));
  const membershipIdsPresent = new Set(memberships.map((row) => row.id));
  const strayOccurrences = new Set(strayEvidence.map((row) => row.componentOccurrenceId));
  const facts: RepeatedObservationFact[] = [];
  for (const row of laterRows) {
    const fact = oneFact(
      finding,
      row,
      linksByObservation.get(row.id) ?? [],
      occurrencesByIngestion.get(row.sbomIngestionId) ?? [],
      occurrenceById,
      evidenceById,
      ingestionById.get(row.sbomIngestionId),
      laterById.get(row.sbomIngestionId) === true,
      componentCounts.get(row.sbomIngestionId) ?? 0,
      edgeCounts.get(row.sbomIngestionId) ?? 0,
      membershipIdsPresent.has(row.actorMembershipId ?? ''),
      strayOccurrences,
    );
    if (fact === null) {
      return null;
    }
    facts.push(fact);
  }
  return facts;
}

function oneFact(
  finding: RepeatedObservationInspectionTarget,
  row: ObservationRow,
  links: readonly LinkRow[],
  occurrences: readonly OccurrenceRow[],
  occurrenceById: ReadonlyMap<string, OccurrenceRow>,
  evidenceById: ReadonlyMap<string, EvidenceRow>,
  ingestion: IngestionRow | undefined,
  strictlyLater: boolean,
  liveComponentCount: number,
  liveEdgeCount: number,
  membershipPresent: boolean,
  strayOccurrences: ReadonlySet<string>,
): RepeatedObservationFact | null {
  const observedAt = stamp(row.observedAt);
  const createdAt = stamp(row.createdAt);
  const fingerprint = (row.replayFingerprint ?? '').trim();
  if (observedAt === null || createdAt === null) {
    return null;
  }
  const support: RepeatedObservationSupportFact[] = [];
  let unknownVersionOccurrenceHasEvidence = false;
  for (const link of links) {
    const occurrence = occurrenceById.get(link.componentOccurrenceId);
    const evidence =
      link.productMatchEvaluationEvidenceId === null
        ? undefined
        : evidenceById.get(link.productMatchEvaluationEvidenceId);
    if (
      link.supportKind === 'unknown_version_occurrence' &&
      strayOccurrences.has(link.componentOccurrenceId)
    ) {
      unknownVersionOccurrenceHasEvidence = true;
    }
    support.push({
      findingId: link.findingId,
      assetId: link.assetId,
      componentId: link.componentId,
      vulnerabilityId: link.vulnerabilityId,
      sbomId: link.sbomId,
      sbomIngestionId: link.sbomIngestionId,
      occurrenceId: link.componentOccurrenceId,
      supportKind: link.supportKind,
      evidenceId: link.productMatchEvaluationEvidenceId,
      outcome: link.outcome,
      occurrenceVersionKnown: occurrence?.versionKnown ?? null,
      occurrenceAligned: occurrenceAligned(finding, row.sbomIngestionId, occurrence),
      evidenceOutcome: evidence?.outcome ?? null,
      evidenceAligned: evidenceAligned(finding, link, evidence),
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
      occurrenceVersion: occurrence?.version ?? null,
      evidenceRawObservedVersion: evidence?.rawObservedVersion ?? null,
    });
  }
  return {
    organizationId: row.organizationId,
    findingId: row.findingId,
    sbomId: row.sbomId,
    sbomIngestionId: row.sbomIngestionId,
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
    evidenceLinkCount: row.evidenceLinkCount,
    replayFingerprint: fingerprint,
    actorMembershipId: row.actorMembershipId,
    correlationId: row.correlationId,
    observedAt,
    createdAt,
    membershipPresent,
    absenceGraphCompleteness: row.absenceGraphCompleteness,
    absenceComponentCount: row.absenceComponentCount,
    absenceDependencyEdgeCount: row.absenceDependencyEdgeCount,
    evidence: row.evidence,
    unknownVersionOccurrenceHasEvidence,
    ingestion: {
      present: ingestion !== undefined,
      organizationId: ingestion?.organizationId ?? null,
      assetId: ingestion?.assetId ?? null,
      sbomId: ingestion?.sbomId ?? null,
      state: ingestion?.state ?? null,
      normalizationVersion: ingestion?.normalizationVersion ?? null,
      strictlyLater,
      graphCompleteness: ingestion?.graphCompleteness ?? null,
      componentCount: ingestion?.componentCount ?? null,
      dependencyEdgeCount: ingestion?.dependencyEdgeCount ?? null,
      liveComponentCount,
      liveEdgeCount,
      targetOccurrenceIds: occurrences.map((occurrence) => occurrence.id),
    },
    links: support,
  };
}

function occurrenceAligned(
  finding: RepeatedObservationInspectionTarget,
  sbomIngestionId: string,
  occurrence: OccurrenceRow | undefined,
): boolean {
  return (
    occurrence !== undefined &&
    occurrence.organizationId === finding.organizationId &&
    occurrence.assetId === finding.assetId &&
    occurrence.componentId === finding.componentId &&
    occurrence.sbomIngestionId === sbomIngestionId
  );
}

function evidenceAligned(
  finding: RepeatedObservationInspectionTarget,
  link: LinkRow,
  evidence: EvidenceRow | undefined,
): boolean {
  return (
    evidence !== undefined &&
    evidence.organizationId === finding.organizationId &&
    evidence.assetId === link.assetId &&
    evidence.componentId === link.componentId &&
    evidence.vulnerabilityId === link.vulnerabilityId &&
    evidence.sbomIngestionId === link.sbomIngestionId &&
    evidence.componentOccurrenceId === link.componentOccurrenceId &&
    evidence.assetId === finding.assetId &&
    evidence.componentId === finding.componentId &&
    evidence.vulnerabilityId === finding.vulnerabilityId
  );
}

async function laterThanCreation(
  tx: Tx,
  finding: RepeatedObservationInspectionTarget,
  creationIngestionId: string,
  ingestionIds: readonly string[],
): Promise<readonly { id: string; strictly_later: boolean }[]> {
  return tx.$queryRaw<Array<{ id: string; strictly_later: boolean }>>`
    SELECT target."id"::text AS id,
           (
             (target_sbom."received_at", target."created_at", target."id")
             > (creation_sbom."received_at", creation."created_at", creation."id")
           ) AS strictly_later
    FROM "sbom_ingestion" AS target
    INNER JOIN "sbom" AS target_sbom
      ON target_sbom."organization_id" = target."organization_id"
     AND target_sbom."id" = target."sbom_id"
    INNER JOIN "sbom_ingestion" AS creation
      ON creation."organization_id" = target."organization_id"
     AND creation."id" = ${creationIngestionId}::uuid
    INNER JOIN "sbom" AS creation_sbom
      ON creation_sbom."organization_id" = creation."organization_id"
     AND creation_sbom."id" = creation."sbom_id"
    WHERE target."organization_id" = ${finding.organizationId}::uuid
      AND target."asset_id" = ${finding.assetId}::uuid
      AND target."id" IN (${Prisma.join(ingestionIds.map((id) => Prisma.sql`${id}::uuid`))})
  `;
}

async function groupedCount(
  tx: Tx,
  table: 'component_occurrence' | 'dependency_relationship',
  organizationId: string,
  ingestionIds: readonly string[],
): Promise<ReadonlyMap<string, number>> {
  const rows =
    table === 'component_occurrence'
      ? await tx.$queryRaw<Array<{ id: string; count: number }>>`
          SELECT "sbom_ingestion_id"::text AS id, COUNT(*)::int AS count
          FROM "component_occurrence"
          WHERE "organization_id" = ${organizationId}::uuid
            AND "sbom_ingestion_id" IN (${Prisma.join(ingestionIds.map((id) => Prisma.sql`${id}::uuid`))})
          GROUP BY "sbom_ingestion_id"
        `
      : await tx.$queryRaw<Array<{ id: string; count: number }>>`
          SELECT "sbom_ingestion_id"::text AS id, COUNT(*)::int AS count
          FROM "dependency_relationship"
          WHERE "organization_id" = ${organizationId}::uuid
            AND "sbom_ingestion_id" IN (${Prisma.join(ingestionIds.map((id) => Prisma.sql`${id}::uuid`))})
          GROUP BY "sbom_ingestion_id"
        `;
  const counts = new Map<string, number>();
  for (const row of rows) {
    const count = typeof row.count === 'number' ? row.count : Number(row.count);
    if (!Number.isInteger(count) || count < 0) {
      continue;
    }
    counts.set(row.id, count);
  }
  return counts;
}

function observationRole(
  observation: ObservationRow,
): 'creation_observation' | 'later_observation' | 'malformed_persisted_state' {
  return classifyInspectionObservationShape(shapeInput(observation)).role;
}

function shapeInput(observation: {
  readonly method: string;
  readonly result: string;
  readonly occurrenceId: string | null;
  readonly transitionClassification: string | null;
  readonly creationPurpose: string | null;
  readonly creationPolicyId: string | null;
  readonly creationPolicyVersion: number | null;
  readonly observationPurpose: string | null;
  readonly observationPolicyId: string | null;
  readonly observationPolicyVersion: number | null;
  readonly aggregate?: string | null;
  readonly aggregateClassification?: string | null;
}): {
  readonly method: string;
  readonly result: string;
  readonly occurrenceId: string | null;
  readonly transitionClassification: string | null;
  readonly creationPurpose: string | null;
  readonly creationPolicyId: string | null;
  readonly creationPolicyVersion: number | null;
  readonly observationPurpose: string | null;
  readonly observationPolicyId: string | null;
  readonly observationPolicyVersion: number | null;
  readonly aggregate: string | null;
} {
  return {
    method: observation.method,
    result: observation.result,
    occurrenceId: observation.occurrenceId,
    transitionClassification: observation.transitionClassification,
    creationPurpose: observation.creationPurpose,
    creationPolicyId: observation.creationPolicyId,
    creationPolicyVersion: observation.creationPolicyVersion,
    observationPurpose: observation.observationPurpose,
    observationPolicyId: observation.observationPolicyId,
    observationPolicyVersion: observation.observationPolicyVersion,
    aggregate: observation.aggregate ?? observation.aggregateClassification ?? null,
  };
}

function groupBy<T>(rows: readonly T[], key: (row: T) => string): Map<string, T[]> {
  const grouped = new Map<string, T[]>();
  for (const row of rows) {
    const id = key(row);
    const list = grouped.get(id) ?? [];
    list.push(row);
    grouped.set(id, list);
  }
  return grouped;
}

function sameUniqueIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const sortedLeft = [...left].sort(compareUuid);
  const sortedRight = [...right].sort(compareUuid);
  const seen = new Set<string>();
  for (let index = 0; index < sortedLeft.length; index += 1) {
    const value = sortedLeft[index];
    if (value === undefined || value !== sortedRight[index] || seen.has(value)) {
      return false;
    }
    seen.add(value);
  }
  return true;
}

function stamp(value: Date): string | null {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return null;
  }
  return value.toISOString();
}

function instant(value: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    return null;
  }
  const parsed = new Date(value).getTime();
  if (Number.isNaN(parsed) || new Date(parsed).toISOString() !== value) {
    return null;
  }
  return parsed;
}

function isUuid(value: string | null): value is string {
  return value !== null && UUID_LOWER_PATTERN.test(value);
}

function compareUuid(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}
