/**
 * Pure latest-observation selection for ADR 0040 Session 1.
 * One legal creation observation is the fallback when no repeated candidate exists.
 * Otherwise exactly one legal repeated observation is selected.
 * This module does not read PostgreSQL, write a Finding, read a clock, or
 * register production inspection. `projectFindingInspection` stays creation based.
 *
 * Total order, applied to a copy of the repeated candidates:
 * 1. Any illegal, cross-tenant, contradictory, or unordered candidate fails
 *    the set. An illegal repeated row is not skipped in favor of an older row
 *    or the creation observation.
 * 2. An empty legal repeated set projects the creation observation.
 * 3. A non-empty legal repeated set projects one repeated observation.
 * 4. The later canonical `observedAt` wins. Instants are canonical UTC
 *    `YYYY-MM-DDTHH:mm:ss.ssssssZ` text with exactly six fractional digits,
 *    the accepted `timestamptz(6)` precision. Comparison is lexicographic and
 *    descending. Year, date, time, and fraction are fixed width, so code-unit
 *    order is chronological order. The instant is not passed through Date, so
 *    two values inside one millisecond stay distinct. Offsets and other
 *    precisions are rejected.
 * 5. Equal timestamps break by `sbomIngestionId` descending in PostgreSQL
 *    uuid byte order. Canonical lowercase UUID text has hyphens in fixed
 *    positions and hex digits in nibble order, so code-unit order matches
 *    that byte order. ADR 0039 already compares ingestion ids as the uuid
 *    column. Within one Finding the accepted observation natural identity is
 *    `organizationId` + `findingId` + `sbomIngestionId`, so the ingestion id
 *    is the stable discriminator. The surrogate observation id stays internal
 *    and is not the tie break.
 * 6. Caller array order is not an ordering field. Selection sorts a copy.
 * 7. A repeated natural identity or surrogate observation id that appears
 *    twice fails closed, including when the payloads differ.
 * 8. Ingestion strict-later order is the PostgreSQL tuple
 *    `(sbom.received_at, ingestion.created_at, ingestion.id)` at microsecond
 *    precision. Exact tuple equality is not strictly later.
 * 9. Every product-match support on a repeated candidate must satisfy
 *    `patchpilot_finding_repeated_observation_current_evidence`. An illegal
 *    support fails the set. It is not skipped, and selection does not fall
 *    back to an older observation or to creation.
 */

import type { FindingObservationResult } from '../../lifecycle.js';
import { parseFindingCreationEvidenceSet } from '../controlled-creation/evidence-set.js';
import { FINDING_CREATION_MAX_EVIDENCE_SET_SIZE } from '../controlled-creation/policy.js';
import {
  classifyInspectionObservationShape,
} from '../controlled-observation/inspection-compatibility.js';
import {
  closedRecord,
  isHostileProxy,
  ownDataProperties,
} from '../controlled-observation/plain.js';
import {
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  isFindingRepeatedObservationAggregate,
  mapRepeatedObservationAggregate,
  type FindingRepeatedObservationAggregate,
} from '../controlled-observation/policy.js';
import {
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
  canonicalRepeatedObservationReplayFingerprint,
  type FindingRepeatedObservationAbsenceGraph,
} from '../controlled-observation/support.js';
import {
  FINDING_INSPECTION_ACCEPTED_APPROVAL_PURPOSE,
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID,
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION,
  FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA,
  FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_ORIGIN,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION,
  FINDING_INSPECTION_CREATION_POLICY_ID,
  FINDING_INSPECTION_CREATION_POLICY_VERSION,
  FINDING_INSPECTION_CREATION_PURPOSE,
  FINDING_INSPECTION_CREATION_TRANSITION,
  FINDING_INSPECTION_NORMALIZATION_VERSION,
} from './policy.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/;
const MONTH_LENGTHS: readonly number[] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const COUNT_LIMIT = 100_000;
const NORMALIZATION_VERSION = String(FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION);

export const FINDING_LATEST_OBSERVATION_SELECTION_SCHEMA_VERSION =
  'finding_latest_observation_selection_v1' as const;

export const FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION =
  'finding_latest_observation_result_v1' as const;

export const FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION =
  'finding_latest_observation_projection_v1' as const;

export const FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION =
  'finding_latest_observation_external_result_v1' as const;

/**
 * Safe future inspection failure. It is not an internal diagnostic name.
 * Missing and foreign Findings stay `not_found`. Every other selector failure
 * uses this one category so persistence, evidence, and tenant details stay hidden.
 */
export const FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE = 'unavailable' as const;

const CREATION_OBSERVATION_EVIDENCE_SCHEMA = 'finding_creation_observation_v1' as const;

export const FINDING_LATEST_OBSERVATION_SELECTION_ORDER = Object.freeze({
  illegalRepeatedObservation: 'fail_closed',
  emptyRepeatedSet: 'creation_observation',
  nonEmptyRepeatedSet: 'one_repeated_observation',
  observedAt: 'descending_canonical_utc_timestamptz6',
  timestampTieBreak: 'sbom_ingestion_id_descending_postgresql_uuid_byte_order',
  callerArrayOrder: 'irrelevant',
  duplicateNaturalIdentity: 'malformed_persisted_state',
  duplicateSurrogateIdentity: 'malformed_persisted_state',
});

export const FINDING_LATEST_OBSERVATION_INSPECTION_INVARIANTS = Object.freeze({
  session: 'controlled_finding_latest_observation_inspection_session_1',
  nextSession: 'controlled_finding_latest_observation_inspection_session_1r2',
  productionRegistration: 'absent',
  persistenceReadImplemented: false,
  postgresqlReadImplemented: false,
  productionInspection: 'creation_based',
  productAvailability: 'unavailable',
  repeatedObservationWritesReachable: false,
  operatorReachability: 'deferred',
  historyExposed: false,
  findingStateRemains: 'open',
  findingVersionRemains: 1,
  schemaChanged: false,
  migrationChanged: false,
  writes: 0,
  clockDependency: false,
  candidateInputOrderRelevant: false,
});

export const FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS = [
  'schemaVersion',
  'findingId',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'observationSource',
  'observedAt',
  'aggregate',
  'mappedResult',
  'evidence',
] as const;

const SELECTION_KEYS = [
  'schemaVersion',
  'authorizedOrganizationId',
  'requestedFindingId',
  'finding',
  'creation',
  'repeated',
] as const;

const FINDING_KEYS = [
  'organizationId',
  'findingId',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'state',
  'version',
  'componentOccurrenceId',
  'resolvedAt',
  'reopenedAt',
  'assignedMembershipId',
  'assignedTeamId',
  'dueAt',
  'currentRiskCalculationId',
  'firstObservedAt',
  'lastObservedAt',
  'createdAt',
  'updatedAt',
  'assetCurrentIngestionId',
  'remediationTaskCount',
  'riskAcceptanceCount',
  'riskCalculationCount',
  'genericEvidenceCount',
] as const;

const CREATION_KEYS = [
  'observationId',
  'organizationId',
  'findingId',
  'sbomId',
  'sbomIngestionId',
  'observedAt',
  'createdAt',
  'method',
  'result',
  'occurrenceId',
  'transitionClassification',
  'creationPurpose',
  'creationPolicyId',
  'creationPolicyVersion',
  'observationPurpose',
  'observationPolicyId',
  'observationPolicyVersion',
  'aggregate',
  'affectedEvidenceCount',
  'evidence',
  'replayFingerprint',
  'otherOccurrenceCount',
  'creationIngestionOccurrenceCount',
  'ingestion',
  'links',
] as const;

const CREATION_INGESTION_KEYS = [
  'id',
  'sbomId',
  'organizationId',
  'assetId',
  'state',
  'normalizationVersion',
  'receivedAt',
  'createdAt',
] as const;

const CREATION_LINK_KEYS = [
  'organizationId',
  'findingId',
  'findingObservationId',
  'evidenceId',
  'evidenceOrganizationId',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'sbomIngestionId',
  'occurrenceId',
  'outcome',
  'evidencePresent',
  'occurrencePresent',
  'occurrenceVersion',
  'occurrenceVersionKnown',
  'evidenceAligned',
  'evidenceOutcome',
  'productOrigin',
  'evaluatorId',
  'evaluatorVersion',
  'matchingPolicyId',
  'matchingPolicyVersion',
  'productEvidencePolicyId',
  'productEvidencePolicyVersion',
  'evidenceSchemaVersion',
  'findingCreation',
  'suppressionAuthority',
  'evidenceRawObservedVersion',
  'occurrenceAssetId',
  'occurrenceComponentId',
  'occurrenceIngestionId',
  'withdrawal',
  'quarantine',
  'hasSuccessor',
  'revisionOrigin',
  'approvalPresent',
  'approvalPurpose',
  'approvalRevisionMatches',
  'approvalVulnerabilityMatches',
  'bindingPresent',
  'bindingReviewed',
] as const;

const REPEATED_KEYS = [
  'observationId',
  'organizationId',
  'findingId',
  'sbomId',
  'sbomIngestionId',
  'method',
  'result',
  'occurrenceId',
  'transitionClassification',
  'creationPurpose',
  'creationPolicyId',
  'creationPolicyVersion',
  'observationPurpose',
  'observationPolicyId',
  'observationPolicyVersion',
  'aggregate',
  'evidenceLinkCount',
  'replayFingerprint',
  'actorMembershipId',
  'correlationId',
  'observedAt',
  'createdAt',
  'membershipPresent',
  'absenceGraphCompleteness',
  'absenceComponentCount',
  'absenceDependencyEdgeCount',
  'evidence',
  'unknownVersionOccurrenceHasEvidence',
  'ingestion',
  'supports',
] as const;

const REPEATED_INGESTION_KEYS = [
  'id',
  'sbomId',
  'organizationId',
  'assetId',
  'state',
  'normalizationVersion',
  'receivedAt',
  'createdAt',
  'graphCompleteness',
  'componentCount',
  'dependencyEdgeCount',
  'liveComponentCount',
  'liveEdgeCount',
  'targetOccurrenceIds',
] as const;

const SUPPORT_KEYS = [
  'organizationId',
  'findingId',
  'findingObservationId',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'sbomId',
  'sbomIngestionId',
  'occurrenceId',
  'supportKind',
  'evidenceId',
  'evidenceOrganizationId',
  'outcome',
  'occurrenceVersionKnown',
  'occurrenceAligned',
  'evidencePresent',
  'occurrencePresent',
  'occurrenceVersion',
  'evidenceAligned',
  'evidenceOutcome',
  'productOrigin',
  'evaluatorId',
  'evaluatorVersion',
  'matchingPolicyId',
  'matchingPolicyVersion',
  'productEvidencePolicyId',
  'productEvidencePolicyVersion',
  'evidenceSchemaVersion',
  'findingCreation',
  'suppressionAuthority',
  'evidenceRawObservedVersion',
  'withdrawal',
  'quarantine',
  'hasSuccessor',
  'revisionOrigin',
  'approvalPresent',
  'approvalPurpose',
  'approvalRevisionMatches',
  'approvalVulnerabilityMatches',
  'bindingPresent',
  'bindingReviewed',
] as const;

const CREATION_EVIDENCE_KEYS = [
  'affectedEvidenceCount',
  'evidenceSetFingerprint',
  'policyId',
  'policyVersion',
  'purpose',
  'schemaVersion',
  'transition',
] as const;

const REPEATED_EVIDENCE_KEYS = [
  'aggregate',
  'evidenceLinkCount',
  'mappedResult',
  'policyId',
  'policyVersion',
  'purpose',
  'replayFingerprint',
  'schemaVersion',
] as const;

const GRAPH_VALUES = ['empty', 'no_dependencies', 'partial', 'complete'] as const;

type Integrity = 'ok' | NestedFailure;

type NestedFailure =
  | 'not_found'
  | 'malformed_persisted_state'
  | 'evidence_unavailable'
  | 'unsupported_envelope'
  | 'integrity_failure';

type Parsed<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly status: NestedFailure };

type Instant = { readonly text: string };

type CurrentEvidenceClass = 'current' | 'rejected' | 'unavailable' | 'malformed';

type CurrentEvidenceFacts = {
  readonly withdrawal: 'not_withdrawn' | 'withdrawn';
  readonly quarantine: 'not_quarantined' | 'quarantined';
  readonly hasSuccessor: boolean;
  readonly revisionOrigin: string;
  readonly approvalPurpose: string;
  readonly approvalRevisionMatches: boolean;
  readonly approvalVulnerabilityMatches: boolean;
  readonly bindingReviewed: boolean;
};

type IngestionOrder = {
  readonly id: string;
  readonly receivedAt: Instant;
  readonly createdAt: Instant;
};

type Scope = {
  readonly organizationId: string;
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly firstObservedAt: Instant;
  readonly lastObservedAt: Instant;
  readonly createdAt: Instant;
  readonly updatedAt: Instant;
  readonly assetCurrentIngestionId: string;
};

export type FindingLatestObservationOccurrenceEvidence = {
  readonly kind: 'occurrence_support';
  readonly affectedSupportCount: number;
  readonly unaffectedSupportCount: number;
  readonly unknownSupportCount: number;
  readonly unknownVersionSupportCount: number;
  readonly knownVersions: readonly string[];
};

export type FindingLatestObservationAbsenceEvidence = {
  readonly kind: 'component_absence';
  readonly graphCompleteness: FindingRepeatedObservationAbsenceGraph;
  readonly componentCount: number;
  readonly dependencyEdgeCount: number;
};

export type FindingLatestObservationEvidenceProjection =
  | FindingLatestObservationOccurrenceEvidence
  | FindingLatestObservationAbsenceEvidence;

export type FindingLatestObservationProjection = {
  readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION;
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly observationSource: 'creation' | 'latest_repeated';
  readonly observedAt: string;
  readonly aggregate: FindingRepeatedObservationAggregate;
  readonly mappedResult: FindingObservationResult;
  readonly evidence: FindingLatestObservationEvidenceProjection;
};

export type FindingLatestObservationExternalResult =
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION;
      readonly status: 'found';
      readonly projection: FindingLatestObservationProjection;
    }
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION;
      readonly status: 'not_found' | typeof FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE;
    };

export type FindingLatestObservationSelectionResult =
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION;
      readonly status: 'found';
      readonly projection: FindingLatestObservationProjection;
    }
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION;
      readonly status: NestedFailure;
    };

type LegalCreation = {
  readonly observationId: string;
  readonly sbomIngestionId: string;
  readonly observedAt: Instant;
  readonly createdAt: Instant;
  readonly ingestion: IngestionOrder;
  readonly evidence: FindingLatestObservationOccurrenceEvidence;
  readonly currentEvidence: boolean;
};

type LegalRepeated = {
  readonly observationId: string;
  readonly sbomIngestionId: string;
  readonly observedAt: Instant;
  readonly createdAt: Instant;
  readonly aggregate: FindingRepeatedObservationAggregate;
  readonly mappedResult: FindingObservationResult;
  readonly evidence: FindingLatestObservationEvidenceProjection;
};

type SupportFact = {
  readonly occurrenceId: string;
  readonly evidenceId: string | null;
  readonly unknownVersion: boolean;
  readonly outcome: 'affected' | 'unaffected' | 'unknown' | null;
  readonly version: string | null;
};

export function selectFindingLatestObservation(
  input: unknown,
): FindingLatestObservationSelectionResult {
  const envelope = closedRecord(input, SELECTION_KEYS);
  if (
    envelope === null ||
    envelope.get('schemaVersion') !== FINDING_LATEST_OBSERVATION_SELECTION_SCHEMA_VERSION
  ) {
    return failure('unsupported_envelope');
  }
  const authorizedOrganizationId = readUuid(envelope.get('authorizedOrganizationId'));
  const requestedFindingId = readUuid(envelope.get('requestedFindingId'));
  if (authorizedOrganizationId === null || requestedFindingId === null) {
    return failure('unsupported_envelope');
  }
  const finding = parseFinding(
    envelope.get('finding'),
    authorizedOrganizationId,
    requestedFindingId,
  );
  if (!finding.ok) {
    return failure(finding.status);
  }
  const creation = parseCreation(envelope.get('creation'), finding.value);
  const repeated = parseRepeated(
    envelope.get('repeated'),
    finding.value,
    creation.ok ? creation.value : null,
  );
  const status = worse(creation.ok ? 'ok' : creation.status, repeated.ok ? 'ok' : repeated.status);
  if (!creation.ok || !repeated.ok || status !== 'ok') {
    return failure(status === 'ok' ? 'malformed_persisted_state' : status);
  }
  if (
    !identitiesUnique(creation.value, repeated.value) ||
    !timestampsAgree(finding.value, creation.value, repeated.value)
  ) {
    return failure('malformed_persisted_state');
  }
  if (repeated.value.length === 0) {
    if (
      !creation.value.currentEvidence ||
      creation.value.sbomIngestionId !== finding.value.assetCurrentIngestionId
    ) {
      return failure('integrity_failure');
    }
    return found(projectCreation(finding.value, creation.value));
  }
  const selected = selectLatest(repeated.value);
  if (selected === null) {
    return failure('malformed_persisted_state');
  }
  if (
    hasProductMatchEvidence(selected.evidence) &&
    selected.sbomIngestionId !== finding.value.assetCurrentIngestionId
  ) {
    return failure('integrity_failure');
  }
  return found(projectRepeated(finding.value, selected));
}

export function mapFindingLatestObservationInspectionResult(
  result: FindingLatestObservationSelectionResult,
): FindingLatestObservationExternalResult {
  if (result.status === 'found') {
    return Object.freeze({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: 'found',
      projection: result.projection,
    });
  }
  if (result.status === 'not_found') {
    return Object.freeze({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: 'not_found',
    });
  }
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
    status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
  });
}

function parseFinding(
  input: unknown,
  authorizedOrganizationId: string,
  requestedFindingId: string,
): Parsed<Scope> {
  const values = closedRecord(input, FINDING_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const organizationId = readUuid(values.get('organizationId'));
  const findingId = readUuid(values.get('findingId'));
  const assetId = readUuid(values.get('assetId'));
  const componentId = readUuid(values.get('componentId'));
  const vulnerabilityId = readUuid(values.get('vulnerabilityId'));
  const firstObservedAt = readInstant(values.get('firstObservedAt'));
  const lastObservedAt = readInstant(values.get('lastObservedAt'));
  const createdAt = readInstant(values.get('createdAt'));
  const updatedAt = readInstant(values.get('updatedAt'));
  const assetCurrentIngestionId = readUuid(values.get('assetCurrentIngestionId'));
  if (
    organizationId === null ||
    findingId === null ||
    assetId === null ||
    componentId === null ||
    vulnerabilityId === null ||
    firstObservedAt === null ||
    lastObservedAt === null ||
    createdAt === null ||
    updatedAt === null ||
    assetCurrentIngestionId === null
  ) {
    return fail('malformed_persisted_state');
  }
  if (organizationId !== authorizedOrganizationId || findingId !== requestedFindingId) {
    return fail('not_found');
  }
  if (
    values.get('state') !== 'open' ||
    !Object.is(values.get('version'), 1) ||
    values.get('componentOccurrenceId') !== null ||
    values.get('resolvedAt') !== null ||
    values.get('reopenedAt') !== null ||
    values.get('assignedMembershipId') !== null ||
    values.get('assignedTeamId') !== null ||
    values.get('dueAt') !== null ||
    values.get('currentRiskCalculationId') !== null ||
    !isZeroCount(values.get('remediationTaskCount')) ||
    !isZeroCount(values.get('riskAcceptanceCount')) ||
    !isZeroCount(values.get('riskCalculationCount')) ||
    !isZeroCount(values.get('genericEvidenceCount'))
  ) {
    return fail('malformed_persisted_state');
  }
  return ok({
    organizationId,
    findingId,
    assetId,
    componentId,
    vulnerabilityId,
    firstObservedAt,
    lastObservedAt,
    createdAt,
    updatedAt,
    assetCurrentIngestionId,
  });
}

function parseCreation(input: unknown, scope: Scope): Parsed<LegalCreation> {
  const values = closedRecord(input, CREATION_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const identity = rowIdentity(values, scope);
  if (identity !== null) {
    return fail(identity);
  }
  const observationId = readUuid(values.get('observationId'));
  const sbomId = readUuid(values.get('sbomId'));
  const sbomIngestionId = readUuid(values.get('sbomIngestionId'));
  const observedAt = readInstant(values.get('observedAt'));
  const createdAt = readInstant(values.get('createdAt'));
  const affectedEvidenceCount = readBoundedInteger(
    values.get('affectedEvidenceCount'),
    1,
    FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
  );
  const otherOccurrenceCount = readBoundedInteger(
    values.get('otherOccurrenceCount'),
    0,
    COUNT_LIMIT,
  );
  const creationIngestionOccurrenceCount = readBoundedInteger(
    values.get('creationIngestionOccurrenceCount'),
    1,
    COUNT_LIMIT,
  );
  const replayFingerprint = readFingerprint(values.get('replayFingerprint'));
  if (
    observationId === null ||
    sbomId === null ||
    sbomIngestionId === null ||
    observedAt === null ||
    createdAt === null ||
    affectedEvidenceCount === null ||
    otherOccurrenceCount === null ||
    creationIngestionOccurrenceCount === null ||
    replayFingerprint === null ||
    classifyInspectionObservationShape(shapeInput(values)).role !== 'creation_observation'
  ) {
    return fail('malformed_persisted_state');
  }
  const ingestion = parseCreationIngestion(values.get('ingestion'), scope, sbomId, sbomIngestionId);
  if (!ingestion.ok) {
    return ingestion;
  }
  const links = readClosedArray(values.get('links'), FINDING_CREATION_MAX_EVIDENCE_SET_SIZE);
  if (
    links === null ||
    links.length !== affectedEvidenceCount ||
    creationIngestionOccurrenceCount !== links.length + otherOccurrenceCount
  ) {
    return fail('malformed_persisted_state');
  }
  const evidenceIds: string[] = [];
  const occurrenceIds = new Set<string>();
  const versions: string[] = [];
  let currentEvidence = true;
  let status: Integrity = 'ok';
  for (const link of links) {
    const parsed = parseCreationLink(link, scope, observationId, sbomIngestionId);
    if (!parsed.ok) {
      status = worse(status, parsed.status);
      continue;
    }
    if (
      occurrenceIds.has(parsed.value.occurrenceId) ||
      evidenceIds.includes(parsed.value.evidenceId)
    ) {
      status = worse(status, 'malformed_persisted_state');
      continue;
    }
    occurrenceIds.add(parsed.value.occurrenceId);
    evidenceIds.push(parsed.value.evidenceId);
    versions.push(parsed.value.version);
    if (!parsed.value.current) {
      currentEvidence = false;
    }
  }
  if (status !== 'ok') {
    return fail(status);
  }
  const fingerprint = creationFingerprint(evidenceIds);
  if (
    fingerprint === null ||
    fingerprint !== replayFingerprint ||
    !creationEvidenceAgrees(values.get('evidence'), affectedEvidenceCount, fingerprint)
  ) {
    return fail('malformed_persisted_state');
  }
  return ok({
    observationId,
    sbomIngestionId,
    observedAt,
    createdAt,
    ingestion: ingestion.value,
    evidence: occurrenceEvidence({
      affected: versions.length,
      unaffected: 0,
      unknown: 0,
      unknownVersion: 0,
      versions,
    }),
    currentEvidence,
  });
}

function parseCreationLink(
  input: unknown,
  scope: Scope,
  observationId: string,
  sbomIngestionId: string,
): Parsed<{
  readonly evidenceId: string;
  readonly occurrenceId: string;
  readonly version: string;
  readonly current: boolean;
}> {
  const values = closedRecord(input, CREATION_LINK_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const aligned = supportTargetAgrees(values, scope, observationId, null, sbomIngestionId);
  if (aligned !== null) {
    return fail(aligned);
  }
  const evidenceId = readUuid(values.get('evidenceId'));
  const occurrenceId = readUuid(values.get('occurrenceId'));
  if (
    evidenceId === null ||
    occurrenceId === null ||
    values.get('outcome') !== 'affected' ||
    values.get('occurrenceVersionKnown') !== true ||
    values.get('evidenceAligned') !== true ||
    values.get('findingObservationId') !== observationId ||
    values.get('sbomIngestionId') !== sbomIngestionId
  ) {
    return fail('malformed_persisted_state');
  }
  const evidenceOrganizationId = readNullableUuid(values.get('evidenceOrganizationId'));
  if (evidenceOrganizationId === undefined) {
    return fail('malformed_persisted_state');
  }
  if (evidenceOrganizationId !== null && evidenceOrganizationId !== scope.organizationId) {
    return fail('integrity_failure');
  }
  if (values.get('evidencePresent') !== true || values.get('occurrencePresent') !== true) {
    return fail('evidence_unavailable');
  }
  if (evidenceOrganizationId !== scope.organizationId) {
    return fail('malformed_persisted_state');
  }
  const version = readVersion(values.get('occurrenceVersion'));
  if (
    version === null ||
    values.get('evidenceOutcome') !== 'affected' ||
    values.get('evidenceRawObservedVersion') !== version ||
    values.get('occurrenceAssetId') !== scope.assetId ||
    values.get('occurrenceComponentId') !== scope.componentId ||
    values.get('occurrenceIngestionId') !== sbomIngestionId ||
    !productMatchLineageAgrees(values)
  ) {
    return fail('malformed_persisted_state');
  }
  const evidenceClass = classifyProductMatchCurrentEvidence(values);
  if (evidenceClass === 'malformed') {
    return fail('malformed_persisted_state');
  }
  if (evidenceClass === 'unavailable') {
    return fail('evidence_unavailable');
  }
  return ok({ evidenceId, occurrenceId, version, current: evidenceClass === 'current' });
}

function parseRepeated(
  input: unknown,
  scope: Scope,
  creation: LegalCreation | null,
): Parsed<readonly LegalRepeated[]> {
  const items = readClosedArray(input);
  if (items === null) {
    return fail('malformed_persisted_state');
  }
  const observations: LegalRepeated[] = [];
  let status: Integrity = 'ok';
  for (const item of items) {
    const parsed = parseOneRepeated(item, scope, creation);
    if (!parsed.ok) {
      status = worse(status, parsed.status);
      continue;
    }
    observations.push(parsed.value);
  }
  if (status !== 'ok') {
    return fail(status);
  }
  return ok(observations);
}

function parseOneRepeated(
  input: unknown,
  scope: Scope,
  creation: LegalCreation | null,
): Parsed<LegalRepeated> {
  const values = closedRecord(input, REPEATED_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const identity = rowIdentity(values, scope);
  if (identity !== null) {
    return fail(identity);
  }
  const observationId = readUuid(values.get('observationId'));
  const sbomId = readUuid(values.get('sbomId'));
  const sbomIngestionId = readUuid(values.get('sbomIngestionId'));
  const observedAt = readInstant(values.get('observedAt'));
  const createdAt = readInstant(values.get('createdAt'));
  const actorMembershipId = readUuid(values.get('actorMembershipId'));
  const correlationId = readUuid(values.get('correlationId'));
  const replayFingerprint = readFingerprint(values.get('replayFingerprint'));
  const aggregate = values.get('aggregate');
  if (
    observationId === null ||
    sbomId === null ||
    sbomIngestionId === null ||
    observedAt === null ||
    createdAt === null ||
    actorMembershipId === null ||
    correlationId === null ||
    replayFingerprint === null ||
    values.get('membershipPresent') !== true ||
    values.get('unknownVersionOccurrenceHasEvidence') !== false ||
    !isFindingRepeatedObservationAggregate(aggregate) ||
    classifyInspectionObservationShape(shapeInput(values)).role !== 'later_observation'
  ) {
    return fail('malformed_persisted_state');
  }
  const mappedResult = mapRepeatedObservationAggregate(aggregate);
  if (values.get('result') !== mappedResult) {
    return fail('malformed_persisted_state');
  }
  const ingestion = parseRepeatedIngestion(values.get('ingestion'), scope, sbomId, sbomIngestionId);
  if (!ingestion.ok) {
    return ingestion;
  }
  if (creation !== null && !ingestionStrictlyLater(ingestion.value.order, creation.ingestion)) {
    return fail('malformed_persisted_state');
  }
  const evidenceLinkCount = readNullableInteger(
    values.get('evidenceLinkCount'),
    0,
    FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  );
  if (evidenceLinkCount === undefined || evidenceLinkCount === null) {
    return fail('malformed_persisted_state');
  }
  const body =
    aggregate === 'component_absent'
      ? parseAbsence(
          values,
          scope,
          sbomIngestionId,
          aggregate,
          mappedResult,
          replayFingerprint,
          evidenceLinkCount,
          ingestion.value,
        )
      : parseSupports(
          values,
          scope,
          observationId,
          sbomId,
          sbomIngestionId,
          aggregate,
          mappedResult,
          replayFingerprint,
          evidenceLinkCount,
          ingestion.value,
        );
  if (!body.ok) {
    return body;
  }
  return ok({
    observationId,
    sbomIngestionId,
    observedAt,
    createdAt,
    aggregate,
    mappedResult,
    evidence: body.value,
  });
}

function parseAbsence(
  values: ReadonlyMap<string, unknown>,
  scope: Scope,
  sbomIngestionId: string,
  aggregate: FindingRepeatedObservationAggregate,
  mappedResult: FindingObservationResult,
  replayFingerprint: string,
  evidenceLinkCount: number,
  ingestion: RepeatedIngestion,
): Parsed<FindingLatestObservationAbsenceEvidence> {
  const graph = values.get('absenceGraphCompleteness');
  const components = readNullableInteger(values.get('absenceComponentCount'), 1, COUNT_LIMIT);
  const edges = readNullableInteger(values.get('absenceDependencyEdgeCount'), 0, COUNT_LIMIT);
  const supports = readClosedArray(values.get('supports'), 0);
  if (!isAbsenceGraph(graph)) {
    return fail('malformed_persisted_state');
  }
  if (components === undefined || components === null || edges === undefined || edges === null) {
    return fail('malformed_persisted_state');
  }
  if (supports === null) {
    return fail('malformed_persisted_state');
  }
  if (
    supports.length !== 0 ||
    evidenceLinkCount !== 0 ||
    ingestion.targetOccurrenceIds.length !== 0 ||
    (graph === 'complete' && edges < 1) ||
    (graph === 'no_dependencies' && edges !== 0) ||
    ingestion.graphCompleteness !== graph ||
    ingestion.componentCount !== components ||
    ingestion.dependencyEdgeCount !== edges ||
    ingestion.liveComponentCount !== components ||
    ingestion.liveEdgeCount !== edges
  ) {
    return fail('malformed_persisted_state');
  }
  const supportFingerprint = canonicalRepeatedObservationAbsenceFingerprint({
    sbomIngestionId,
    graphCompleteness: graph,
    componentCount: components,
    occurrenceCardinality: components,
    dependencyEdgeCount: edges,
  });
  if (
    !replayAgrees(
      scope,
      sbomIngestionId,
      aggregate,
      mappedResult,
      supportFingerprint,
      0,
      replayFingerprint,
    ) ||
    !repeatedEvidenceAgrees(
      values.get('evidence'),
      aggregate,
      mappedResult,
      evidenceLinkCount,
      replayFingerprint,
    )
  ) {
    return fail('malformed_persisted_state');
  }
  return ok(
    Object.freeze({
      kind: 'component_absence',
      graphCompleteness: graph,
      componentCount: components,
      dependencyEdgeCount: edges,
    }),
  );
}

function parseSupports(
  values: ReadonlyMap<string, unknown>,
  scope: Scope,
  observationId: string,
  sbomId: string,
  sbomIngestionId: string,
  aggregate: FindingRepeatedObservationAggregate,
  mappedResult: FindingObservationResult,
  replayFingerprint: string,
  evidenceLinkCount: number,
  ingestion: RepeatedIngestion,
): Parsed<FindingLatestObservationOccurrenceEvidence> {
  if (
    values.get('absenceGraphCompleteness') !== null ||
    values.get('absenceComponentCount') !== null ||
    values.get('absenceDependencyEdgeCount') !== null ||
    evidenceLinkCount < 1
  ) {
    return fail('malformed_persisted_state');
  }
  const supports = readClosedArray(
    values.get('supports'),
    FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  );
  if (supports === null || supports.length !== evidenceLinkCount) {
    return fail('malformed_persisted_state');
  }
  const facts: SupportFact[] = [];
  let status: Integrity = 'ok';
  for (const support of supports) {
    const parsed = parseSupport(support, scope, observationId, sbomId, sbomIngestionId);
    if (!parsed.ok) {
      status = worse(status, parsed.status);
      continue;
    }
    facts.push(parsed.value);
  }
  if (status !== 'ok') {
    return fail(status);
  }
  const occurrenceIds = facts.map((fact) => fact.occurrenceId);
  const evidenceIds = facts.flatMap((fact) => (fact.evidenceId === null ? [] : [fact.evidenceId]));
  const unknownIds = facts.flatMap((fact) => (fact.unknownVersion ? [fact.occurrenceId] : []));
  if (
    !sameUniqueIds(occurrenceIds, ingestion.targetOccurrenceIds) ||
    new Set(evidenceIds).size !== evidenceIds.length ||
    deriveAggregate(facts) !== aggregate
  ) {
    return fail('malformed_persisted_state');
  }
  const supportFingerprint = canonicalRepeatedObservationEvidenceFingerprint(
    [...evidenceIds].sort(compareUuid),
    [...unknownIds].sort(compareUuid),
    evidenceLinkCount,
  );
  if (
    !replayAgrees(
      scope,
      sbomIngestionId,
      aggregate,
      mappedResult,
      supportFingerprint,
      evidenceLinkCount,
      replayFingerprint,
    ) ||
    !repeatedEvidenceAgrees(
      values.get('evidence'),
      aggregate,
      mappedResult,
      evidenceLinkCount,
      replayFingerprint,
    )
  ) {
    return fail('malformed_persisted_state');
  }
  let affected = 0;
  let unaffected = 0;
  let unknown = 0;
  let unknownVersion = 0;
  const versions: string[] = [];
  for (const fact of facts) {
    if (fact.unknownVersion) {
      unknownVersion += 1;
      continue;
    }
    if (fact.outcome === 'affected') {
      affected += 1;
    } else if (fact.outcome === 'unaffected') {
      unaffected += 1;
    } else if (fact.outcome === 'unknown') {
      unknown += 1;
    }
    if (fact.version !== null) {
      versions.push(fact.version);
    }
  }
  return ok(occurrenceEvidence({ affected, unaffected, unknown, unknownVersion, versions }));
}

function parseSupport(
  input: unknown,
  scope: Scope,
  observationId: string,
  sbomId: string,
  sbomIngestionId: string,
): Parsed<SupportFact> {
  const values = closedRecord(input, SUPPORT_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const aligned = supportTargetAgrees(values, scope, observationId, sbomId, sbomIngestionId);
  if (aligned !== null) {
    return fail(aligned);
  }
  const occurrenceId = readUuid(values.get('occurrenceId'));
  if (
    occurrenceId === null ||
    values.get('occurrenceAligned') !== true ||
    values.get('findingObservationId') !== observationId
  ) {
    return fail('malformed_persisted_state');
  }
  if (values.get('supportKind') === 'unknown_version_occurrence') {
    return parseUnknownVersionSupport(values, occurrenceId);
  }
  if (values.get('supportKind') !== 'product_match_evidence') {
    return fail('malformed_persisted_state');
  }
  return parseProductMatchSupport(values, scope, occurrenceId);
}

function parseUnknownVersionSupport(
  values: ReadonlyMap<string, unknown>,
  occurrenceId: string,
): Parsed<SupportFact> {
  if (
    values.get('evidenceId') !== null ||
    values.get('evidenceOrganizationId') !== null ||
    values.get('outcome') !== null ||
    values.get('occurrenceVersionKnown') !== false ||
    values.get('evidencePresent') !== false ||
    values.get('occurrencePresent') !== true ||
    values.get('occurrenceVersion') !== null ||
    values.get('evidenceAligned') !== false ||
    values.get('evidenceOutcome') !== null ||
    values.get('productOrigin') !== null ||
    values.get('evaluatorId') !== null ||
    values.get('evaluatorVersion') !== null ||
    values.get('matchingPolicyId') !== null ||
    values.get('matchingPolicyVersion') !== null ||
    values.get('productEvidencePolicyId') !== null ||
    values.get('productEvidencePolicyVersion') !== null ||
    values.get('evidenceSchemaVersion') !== null ||
    values.get('findingCreation') !== null ||
    values.get('suppressionAuthority') !== null ||
    values.get('evidenceRawObservedVersion') !== null ||
    values.get('withdrawal') !== null ||
    values.get('quarantine') !== null ||
    values.get('hasSuccessor') !== null ||
    values.get('revisionOrigin') !== null ||
    values.get('approvalPresent') !== null ||
    values.get('approvalPurpose') !== null ||
    values.get('approvalRevisionMatches') !== null ||
    values.get('approvalVulnerabilityMatches') !== null ||
    values.get('bindingPresent') !== null ||
    values.get('bindingReviewed') !== null
  ) {
    return fail('malformed_persisted_state');
  }
  return ok({
    occurrenceId,
    evidenceId: null,
    unknownVersion: true,
    outcome: null,
    version: null,
  });
}

function parseProductMatchSupport(
  values: ReadonlyMap<string, unknown>,
  scope: Scope,
  occurrenceId: string,
): Parsed<SupportFact> {
  const evidenceId = readNullableUuid(values.get('evidenceId'));
  const evidenceOrganizationId = readNullableUuid(values.get('evidenceOrganizationId'));
  const outcome = values.get('outcome');
  if (
    evidenceId === undefined ||
    evidenceId === null ||
    evidenceOrganizationId === undefined ||
    (outcome !== 'affected' && outcome !== 'unaffected' && outcome !== 'unknown') ||
    values.get('occurrenceVersionKnown') !== true ||
    values.get('evidenceAligned') !== true
  ) {
    return fail('malformed_persisted_state');
  }
  if (evidenceOrganizationId !== null && evidenceOrganizationId !== scope.organizationId) {
    return fail('integrity_failure');
  }
  if (values.get('evidencePresent') !== true || values.get('occurrencePresent') !== true) {
    return fail('evidence_unavailable');
  }
  if (evidenceOrganizationId !== scope.organizationId) {
    return fail('malformed_persisted_state');
  }
  const version = readVersion(values.get('occurrenceVersion'));
  if (
    version === null ||
    values.get('evidenceOutcome') !== outcome ||
    values.get('evidenceRawObservedVersion') !== version ||
    !productMatchLineageAgrees(values)
  ) {
    return fail('malformed_persisted_state');
  }
  const evidenceClass = classifyProductMatchCurrentEvidence(values);
  if (evidenceClass === 'malformed') {
    return fail('malformed_persisted_state');
  }
  if (evidenceClass === 'unavailable') {
    return fail('evidence_unavailable');
  }
  if (evidenceClass !== 'current') {
    return fail('integrity_failure');
  }
  return ok({
    occurrenceId,
    evidenceId,
    unknownVersion: false,
    outcome,
    version,
  });
}

type RepeatedIngestion = IngestionOrder & {
  readonly order: IngestionOrder;
  readonly graphCompleteness: (typeof GRAPH_VALUES)[number] | null;
  readonly componentCount: number | null;
  readonly dependencyEdgeCount: number | null;
  readonly liveComponentCount: number | null;
  readonly liveEdgeCount: number | null;
  readonly targetOccurrenceIds: readonly string[];
};

function parseRepeatedIngestion(
  input: unknown,
  scope: Scope,
  sbomId: string,
  sbomIngestionId: string,
): Parsed<RepeatedIngestion> {
  const values = closedRecord(input, REPEATED_INGESTION_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  const order = parseIngestionOrder(values, scope, sbomId, sbomIngestionId);
  if (!order.ok) {
    return order;
  }
  const graph = readGraph(values.get('graphCompleteness'));
  const componentCount = readNullableInteger(values.get('componentCount'), 0, COUNT_LIMIT);
  const dependencyEdgeCount = readNullableInteger(
    values.get('dependencyEdgeCount'),
    0,
    COUNT_LIMIT,
  );
  const liveComponentCount = readNullableInteger(values.get('liveComponentCount'), 0, COUNT_LIMIT);
  const liveEdgeCount = readNullableInteger(values.get('liveEdgeCount'), 0, COUNT_LIMIT);
  const targetOccurrenceIds = readUuidSet(
    values.get('targetOccurrenceIds'),
    FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  );
  if (
    graph === undefined ||
    componentCount === undefined ||
    dependencyEdgeCount === undefined ||
    liveComponentCount === undefined ||
    liveEdgeCount === undefined ||
    targetOccurrenceIds === null
  ) {
    return fail('malformed_persisted_state');
  }
  return ok({
    ...order.value,
    order: order.value,
    graphCompleteness: graph,
    componentCount,
    dependencyEdgeCount,
    liveComponentCount,
    liveEdgeCount,
    targetOccurrenceIds,
  });
}

function parseCreationIngestion(
  input: unknown,
  scope: Scope,
  sbomId: string,
  sbomIngestionId: string,
): Parsed<IngestionOrder> {
  const values = closedRecord(input, CREATION_INGESTION_KEYS);
  if (values === null) {
    return fail('malformed_persisted_state');
  }
  return parseIngestionOrder(values, scope, sbomId, sbomIngestionId);
}

function parseIngestionOrder(
  values: ReadonlyMap<string, unknown>,
  scope: Scope,
  sbomId: string,
  sbomIngestionId: string,
): Parsed<IngestionOrder> {
  const id = readUuid(values.get('id'));
  const ingestionSbomId = readUuid(values.get('sbomId'));
  const organizationId = readUuid(values.get('organizationId'));
  const assetId = readUuid(values.get('assetId'));
  const receivedAt = readInstant(values.get('receivedAt'));
  const createdAt = readInstant(values.get('createdAt'));
  if (
    id === null ||
    ingestionSbomId === null ||
    organizationId === null ||
    assetId === null ||
    receivedAt === null ||
    createdAt === null ||
    values.get('state') !== 'completed' ||
    values.get('normalizationVersion') !== NORMALIZATION_VERSION
  ) {
    return fail('malformed_persisted_state');
  }
  if (organizationId !== scope.organizationId) {
    return fail('integrity_failure');
  }
  if (
    id !== sbomIngestionId ||
    ingestionSbomId !== sbomId ||
    assetId !== scope.assetId ||
    NORMALIZATION_VERSION !== FINDING_INSPECTION_NORMALIZATION_VERSION
  ) {
    return fail('malformed_persisted_state');
  }
  return ok({ id, receivedAt, createdAt });
}

function supportTargetAgrees(
  values: ReadonlyMap<string, unknown>,
  scope: Scope,
  observationId: string,
  sbomId: string | null,
  sbomIngestionId: string,
): NestedFailure | null {
  const organizationId = readUuid(values.get('organizationId'));
  const findingId = readUuid(values.get('findingId'));
  const assetId = readUuid(values.get('assetId'));
  const componentId = readUuid(values.get('componentId'));
  const vulnerabilityId = readUuid(values.get('vulnerabilityId'));
  const linkSbomId = sbomId === null ? sbomId : readUuid(values.get('sbomId'));
  const linkIngestionId = readUuid(values.get('sbomIngestionId'));
  if (
    organizationId === null ||
    findingId === null ||
    assetId === null ||
    componentId === null ||
    vulnerabilityId === null ||
    linkIngestionId === null ||
    (sbomId !== null && linkSbomId === null)
  ) {
    return 'malformed_persisted_state';
  }
  if (organizationId !== scope.organizationId) {
    return 'integrity_failure';
  }
  if (
    findingId !== scope.findingId ||
    assetId !== scope.assetId ||
    componentId !== scope.componentId ||
    vulnerabilityId !== scope.vulnerabilityId ||
    linkIngestionId !== sbomIngestionId ||
    (sbomId !== null && linkSbomId !== sbomId) ||
    values.get('findingObservationId') !== observationId
  ) {
    return 'malformed_persisted_state';
  }
  return null;
}

function rowIdentity(values: ReadonlyMap<string, unknown>, scope: Scope): NestedFailure | null {
  const organizationId = readUuid(values.get('organizationId'));
  const findingId = readUuid(values.get('findingId'));
  if (organizationId === null || findingId === null) {
    return 'malformed_persisted_state';
  }
  if (organizationId !== scope.organizationId) {
    return 'integrity_failure';
  }
  if (findingId !== scope.findingId) {
    return 'malformed_persisted_state';
  }
  return null;
}

function identitiesUnique(creation: LegalCreation, repeated: readonly LegalRepeated[]): boolean {
  const observationIds = new Set<string>([creation.observationId]);
  const ingestions = new Set<string>([creation.sbomIngestionId]);
  for (const observation of repeated) {
    if (
      observationIds.has(observation.observationId) ||
      ingestions.has(observation.sbomIngestionId)
    ) {
      return false;
    }
    observationIds.add(observation.observationId);
    ingestions.add(observation.sbomIngestionId);
  }
  return true;
}

function timestampsAgree(
  scope: Scope,
  creation: LegalCreation,
  repeated: readonly LegalRepeated[],
): boolean {
  if (
    scope.firstObservedAt.text !== scope.createdAt.text ||
    scope.firstObservedAt.text !== creation.observedAt.text ||
    creation.observedAt.text !== creation.createdAt.text ||
    scope.lastObservedAt.text < scope.firstObservedAt.text ||
    scope.updatedAt.text < scope.createdAt.text ||
    scope.lastObservedAt.text !== scope.updatedAt.text
  ) {
    return false;
  }
  if (repeated.length === 0) {
    return scope.lastObservedAt.text === scope.firstObservedAt.text;
  }
  let max = '';
  let explainsLast = false;
  for (const observation of repeated) {
    if (
      observation.observedAt.text !== observation.createdAt.text ||
      observation.observedAt.text < scope.firstObservedAt.text
    ) {
      return false;
    }
    if (observation.observedAt.text === scope.lastObservedAt.text) {
      explainsLast = true;
    }
    if (observation.observedAt.text > max) {
      max = observation.observedAt.text;
    }
  }
  return explainsLast && max === scope.lastObservedAt.text;
}

function selectLatest(repeated: readonly LegalRepeated[]): LegalRepeated | null {
  // Copy before sorting. Caller array order is not an ordering field.
  const ordered = [...repeated].sort(compareLatest);
  const selected = ordered[0];
  if (selected === undefined) {
    return null;
  }
  for (let index = 1; index < ordered.length; index += 1) {
    const next = ordered[index];
    if (next !== undefined && compareLatest(selected, next) === 0) {
      return null;
    }
  }
  return selected;
}

function compareLatest(left: LegalRepeated, right: LegalRepeated): number {
  // Descending timestamptz(6). Fixed-width canonical UTC text is chronological.
  if (left.observedAt.text !== right.observedAt.text) {
    return left.observedAt.text > right.observedAt.text ? -1 : 1;
  }
  // PostgreSQL uuid byte order on the natural-identity ingestion id.
  // Canonical lowercase text matches that byte order. The surrogate
  // observation id is not the tie-break.
  return compareUuid(right.sbomIngestionId, left.sbomIngestionId);
}

function projectCreation(
  scope: Scope,
  creation: LegalCreation,
): FindingLatestObservationProjection {
  return projection(
    scope,
    'creation',
    creation.observedAt.text,
    'affected',
    'present',
    creation.evidence,
  );
}

function projectRepeated(
  scope: Scope,
  selected: LegalRepeated,
): FindingLatestObservationProjection {
  return projection(
    scope,
    'latest_repeated',
    selected.observedAt.text,
    selected.aggregate,
    selected.mappedResult,
    selected.evidence,
  );
}

function projection(
  scope: Scope,
  observationSource: 'creation' | 'latest_repeated',
  observedAt: string,
  aggregate: FindingRepeatedObservationAggregate,
  mappedResult: FindingObservationResult,
  evidence: FindingLatestObservationEvidenceProjection,
): FindingLatestObservationProjection {
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION,
    findingId: scope.findingId,
    assetId: scope.assetId,
    componentId: scope.componentId,
    vulnerabilityId: scope.vulnerabilityId,
    observationSource,
    observedAt,
    aggregate,
    mappedResult,
    evidence,
  });
}

function occurrenceEvidence(input: {
  readonly affected: number;
  readonly unaffected: number;
  readonly unknown: number;
  readonly unknownVersion: number;
  readonly versions: readonly string[];
}): FindingLatestObservationOccurrenceEvidence {
  return Object.freeze({
    kind: 'occurrence_support',
    affectedSupportCount: input.affected,
    unaffectedSupportCount: input.unaffected,
    unknownSupportCount: input.unknown,
    unknownVersionSupportCount: input.unknownVersion,
    knownVersions: Object.freeze([...new Set(input.versions)].sort(compareDisplay)),
  });
}

function creationFingerprint(evidenceIds: readonly string[]): string | null {
  const parsed = parseFindingCreationEvidenceSet([...evidenceIds].sort(compareUuid));
  return parsed.ok ? parsed.evidenceSet.fingerprint : null;
}

function creationEvidenceAgrees(input: unknown, count: number, fingerprint: string): boolean {
  const values = closedRecord(input, CREATION_EVIDENCE_KEYS);
  return (
    values !== null &&
    values.get('schemaVersion') === CREATION_OBSERVATION_EVIDENCE_SCHEMA &&
    values.get('transition') === FINDING_INSPECTION_CREATION_TRANSITION &&
    values.get('purpose') === FINDING_INSPECTION_CREATION_PURPOSE &&
    values.get('policyId') === FINDING_INSPECTION_CREATION_POLICY_ID &&
    Object.is(values.get('policyVersion'), FINDING_INSPECTION_CREATION_POLICY_VERSION) &&
    Object.is(values.get('affectedEvidenceCount'), count) &&
    values.get('evidenceSetFingerprint') === fingerprint
  );
}

function repeatedEvidenceAgrees(
  input: unknown,
  aggregate: FindingRepeatedObservationAggregate,
  mappedResult: FindingObservationResult,
  evidenceLinkCount: number,
  replayFingerprint: string,
): boolean {
  const values = closedRecord(input, REPEATED_EVIDENCE_KEYS);
  return (
    values !== null &&
    values.get('schemaVersion') === FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION &&
    values.get('purpose') === FINDING_REPEATED_OBSERVATION_PURPOSE &&
    values.get('policyId') === FINDING_REPEATED_OBSERVATION_POLICY_ID &&
    Object.is(values.get('policyVersion'), FINDING_REPEATED_OBSERVATION_POLICY_VERSION) &&
    values.get('aggregate') === aggregate &&
    values.get('mappedResult') === mappedResult &&
    Object.is(values.get('evidenceLinkCount'), evidenceLinkCount) &&
    values.get('replayFingerprint') === replayFingerprint
  );
}

function replayAgrees(
  scope: Scope,
  sbomIngestionId: string,
  aggregate: FindingRepeatedObservationAggregate,
  mappedResult: FindingObservationResult,
  supportFingerprint: string,
  supportCount: number,
  replayFingerprint: string,
): boolean {
  return (
    canonicalRepeatedObservationReplayFingerprint({
      organizationId: scope.organizationId,
      findingId: scope.findingId,
      assetId: scope.assetId,
      componentId: scope.componentId,
      vulnerabilityId: scope.vulnerabilityId,
      sbomIngestionId,
      aggregate,
      mappedResult,
      supportFingerprint,
      supportCount,
    }) === replayFingerprint
  );
}

function hasProductMatchEvidence(evidence: FindingLatestObservationEvidenceProjection): boolean {
  return (
    evidence.kind === 'occurrence_support' &&
    evidence.affectedSupportCount + evidence.unaffectedSupportCount + evidence.unknownSupportCount >
      0
  );
}

/**
 * Mirrors `patchpilot_finding_repeated_observation_current_evidence`.
 * `bindingReviewed` is the existing inspection encoding of
 * `mapping_review_state = reviewed`, `conflict_classification = none`, and
 * binding vulnerability alignment. The asset's latest-successful ingestion is
 * checked only for the selected product-match observation. Applying that
 * pointer to every earlier candidate would reject a legal older ingestion
 * that is not the one being projected.
 */
function productMatchSupportSatisfiesCurrentEvidence(facts: CurrentEvidenceFacts): boolean {
  return (
    facts.withdrawal === 'not_withdrawn' &&
    facts.quarantine === 'not_quarantined' &&
    facts.hasSuccessor === false &&
    facts.revisionOrigin === FINDING_INSPECTION_ACCEPTED_ORIGIN &&
    facts.approvalPurpose === FINDING_INSPECTION_ACCEPTED_APPROVAL_PURPOSE &&
    facts.approvalRevisionMatches === true &&
    facts.approvalVulnerabilityMatches === true &&
    facts.bindingReviewed === true
  );
}

function classifyProductMatchCurrentEvidence(
  values: ReadonlyMap<string, unknown>,
): CurrentEvidenceClass {
  const withdrawal = readWithdrawal(values.get('withdrawal'));
  const quarantine = readQuarantine(values.get('quarantine'));
  const hasSuccessor = readBoolean(values.get('hasSuccessor'));
  const revisionOrigin = readText(values.get('revisionOrigin'));
  const approvalPresent = readBoolean(values.get('approvalPresent'));
  const approvalPurpose = readText(values.get('approvalPurpose'));
  const approvalRevisionMatches = readBoolean(values.get('approvalRevisionMatches'));
  const approvalVulnerabilityMatches = readBoolean(values.get('approvalVulnerabilityMatches'));
  const bindingPresent = readBoolean(values.get('bindingPresent'));
  const bindingReviewed = readBoolean(values.get('bindingReviewed'));
  if (
    withdrawal === undefined ||
    quarantine === undefined ||
    hasSuccessor === undefined ||
    revisionOrigin === undefined ||
    approvalPresent === undefined ||
    approvalPurpose === undefined ||
    approvalRevisionMatches === undefined ||
    approvalVulnerabilityMatches === undefined ||
    bindingPresent === undefined ||
    bindingReviewed === undefined
  ) {
    return 'malformed';
  }
  if (
    withdrawal === null ||
    quarantine === null ||
    hasSuccessor === null ||
    revisionOrigin === null ||
    approvalPresent !== true ||
    approvalPurpose === null ||
    approvalRevisionMatches === null ||
    approvalVulnerabilityMatches === null ||
    bindingPresent !== true ||
    bindingReviewed === null
  ) {
    return 'unavailable';
  }
  return productMatchSupportSatisfiesCurrentEvidence({
    withdrawal,
    quarantine,
    hasSuccessor,
    revisionOrigin,
    approvalPurpose,
    approvalRevisionMatches,
    approvalVulnerabilityMatches,
    bindingReviewed,
  })
    ? 'current'
    : 'rejected';
}

function readBoolean(value: unknown): boolean | null | undefined {
  if (value === null) {
    return null;
  }
  return typeof value === 'boolean' ? value : undefined;
}

function readText(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  return typeof value === 'string' ? value : undefined;
}

function readWithdrawal(value: unknown): 'not_withdrawn' | 'withdrawn' | null | undefined {
  if (value === null) {
    return null;
  }
  return value === 'not_withdrawn' || value === 'withdrawn' ? value : undefined;
}

function readQuarantine(value: unknown): 'not_quarantined' | 'quarantined' | null | undefined {
  if (value === null) {
    return null;
  }
  return value === 'not_quarantined' || value === 'quarantined' ? value : undefined;
}

function productMatchLineageAgrees(values: ReadonlyMap<string, unknown>): boolean {
  return (
    values.get('productOrigin') === FINDING_INSPECTION_ACCEPTED_ORIGIN &&
    values.get('evaluatorId') === FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID &&
    values.get('evaluatorVersion') === FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION &&
    values.get('matchingPolicyId') === FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID &&
    values.get('matchingPolicyVersion') === FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID &&
    values.get('productEvidencePolicyId') === FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID &&
    Object.is(
      values.get('productEvidencePolicyVersion'),
      FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION,
    ) &&
    values.get('evidenceSchemaVersion') === FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA &&
    values.get('findingCreation') === 'unavailable' &&
    values.get('suppressionAuthority') === false
  );
}

function deriveAggregate(
  facts: readonly SupportFact[],
): FindingRepeatedObservationAggregate | null {
  let affected = false;
  let unknown = false;
  for (const fact of facts) {
    if (fact.unknownVersion || fact.outcome === 'unknown') {
      unknown = true;
      continue;
    }
    if (fact.outcome === 'affected') {
      affected = true;
      continue;
    }
    if (fact.outcome !== 'unaffected') {
      return null;
    }
  }
  if (affected) {
    return 'affected';
  }
  if (unknown) {
    return 'unknown';
  }
  if (facts.length === 0) {
    return null;
  }
  return 'unaffected';
}

function ingestionStrictlyLater(candidate: IngestionOrder, creation: IngestionOrder): boolean {
  // PostgreSQL tuple (received_at, created_at, id), timestamptz(6) then uuid.
  if (candidate.receivedAt.text !== creation.receivedAt.text) {
    return candidate.receivedAt.text > creation.receivedAt.text;
  }
  if (candidate.createdAt.text !== creation.createdAt.text) {
    return candidate.createdAt.text > creation.createdAt.text;
  }
  return compareUuid(candidate.id, creation.id) > 0;
}

function shapeInput(values: ReadonlyMap<string, unknown>): {
  readonly method: unknown;
  readonly result: unknown;
  readonly occurrenceId: unknown;
  readonly transitionClassification: unknown;
  readonly creationPurpose: unknown;
  readonly creationPolicyId: unknown;
  readonly creationPolicyVersion: unknown;
  readonly observationPurpose: unknown;
  readonly observationPolicyId: unknown;
  readonly observationPolicyVersion: unknown;
  readonly aggregate: unknown;
} {
  return {
    method: values.get('method'),
    result: values.get('result'),
    occurrenceId: values.get('occurrenceId'),
    transitionClassification: values.get('transitionClassification'),
    creationPurpose: values.get('creationPurpose'),
    creationPolicyId: values.get('creationPolicyId'),
    creationPolicyVersion: values.get('creationPolicyVersion'),
    observationPurpose: values.get('observationPurpose'),
    observationPolicyId: values.get('observationPolicyId'),
    observationPolicyVersion: values.get('observationPolicyVersion'),
    aggregate: values.get('aggregate'),
  };
}

function sameUniqueIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length || new Set(left).size !== left.length) {
    return false;
  }
  const seen = new Set(right);
  if (seen.size !== right.length) {
    return false;
  }
  return left.every((value) => seen.has(value));
}

function readClosedArray(value: unknown, limit?: number): readonly unknown[] | null {
  if (
    typeof value !== 'object' ||
    value === null ||
    isHostileProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return null;
  }
  const owned = ownDataProperties(value as unknown as Record<string, unknown>);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    !owned.ok ||
    lengthDescriptor === undefined ||
    lengthDescriptor.get !== undefined ||
    typeof lengthDescriptor.value !== 'number' ||
    !Number.isInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    (limit !== undefined && lengthDescriptor.value > limit)
  ) {
    return null;
  }
  const length = lengthDescriptor.value;
  const allowed = new Set<string>(['length']);
  for (let index = 0; index < length; index += 1) {
    allowed.add(String(index));
  }
  for (const key of owned.keys) {
    if (!allowed.has(key)) {
      return null;
    }
  }
  const items: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
      return null;
    }
    items.push(descriptor.value);
  }
  return items;
}

function readUuidSet(value: unknown, limit: number): readonly string[] | null {
  const items = readClosedArray(value, limit);
  if (items === null) {
    return null;
  }
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const id = readUuid(item);
    if (id === null || seen.has(id)) {
      return null;
    }
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

function readUuid(value: unknown): string | null {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value) ? value : null;
}

function readNullableUuid(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  return readUuid(value) ?? undefined;
}

function readInstant(value: unknown): Instant | null {
  // Canonical UTC timestamptz(6). Lexicographic order is chronological only
  // while every accepted value keeps this fixed-width Z form.
  if (typeof value !== 'string') {
    return null;
  }
  const match = TIMESTAMP_PATTERN.exec(value);
  if (match === null) {
    return null;
  }
  const yearText = match[1];
  const monthText = match[2];
  const dayText = match[3];
  const hourText = match[4];
  const minuteText = match[5];
  const secondText = match[6];
  if (
    yearText === undefined ||
    monthText === undefined ||
    dayText === undefined ||
    hourText === undefined ||
    minuteText === undefined ||
    secondText === undefined
  ) {
    return null;
  }
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const monthLength = month >= 1 && month <= 12 ? MONTH_LENGTHS[month - 1] : undefined;
  if (
    monthLength === undefined ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    day > (month === 2 && isLeapYear(year) ? 29 : monthLength)
  ) {
    return null;
  }
  return { text: value };
}

function isLeapYear(year: number): boolean {
  if (year % 400 === 0) {
    return true;
  }
  if (year % 100 === 0) {
    return false;
  }
  return year % 4 === 0;
}

function readBoundedInteger(value: unknown, min: number, max: number): number | null {
  const parsed = readNullableInteger(value, min, max);
  return parsed === undefined || parsed === null ? null : parsed;
}

function readNullableInteger(value: unknown, min: number, max: number): number | null | undefined {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    return undefined;
  }
  return value;
}

function readFingerprint(value: unknown): string | null {
  return typeof value === 'string' && FINGERPRINT_PATTERN.test(value) ? value : null;
}

function readVersion(value: unknown): string | null {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 256 ||
    value.includes('\u0000')
  ) {
    return null;
  }
  return value;
}

function isAbsenceGraph(value: unknown): value is FindingRepeatedObservationAbsenceGraph {
  return value === 'complete' || value === 'no_dependencies';
}

function readGraph(value: unknown): (typeof GRAPH_VALUES)[number] | null | undefined {
  if (value === null) {
    return null;
  }
  return typeof value === 'string' && (GRAPH_VALUES as readonly string[]).includes(value)
    ? (value as (typeof GRAPH_VALUES)[number])
    : undefined;
}

function isZeroCount(value: unknown): boolean {
  return Object.is(value, 0);
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

function compareDisplay(left: string, right: string): number {
  return compareUuid(left, right);
}

function worse(left: Integrity, right: Integrity): Integrity {
  const rank: Record<Integrity, number> = {
    ok: 0,
    evidence_unavailable: 1,
    integrity_failure: 2,
    malformed_persisted_state: 3,
    unsupported_envelope: 4,
    not_found: 5,
  };
  return rank[left] >= rank[right] ? left : right;
}

function ok<T>(value: T): Parsed<T> {
  return { ok: true, value };
}

function fail<T>(status: NestedFailure): Parsed<T> {
  return { ok: false, status };
}

function found(
  projectionValue: FindingLatestObservationProjection,
): FindingLatestObservationSelectionResult {
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION,
    status: 'found',
    projection: projectionValue,
  });
}

function failure(status: NestedFailure): FindingLatestObservationSelectionResult {
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION,
    status,
  });
}
