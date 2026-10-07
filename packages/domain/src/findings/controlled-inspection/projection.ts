/**
 * Deterministic safe projection from one untrusted inspection bundle.
 * Applicability is classified here and is not written back.
 */

import { FINDING_CREATION_MAX_EVIDENCE_SET_SIZE } from '../controlled-creation/policy.js';
import type {
  FindingInspectionEvidenceBundle,
  FindingInspectionLinkRecord,
  FindingInspectionObservationRecord,
} from './port.js';
import {
  FINDING_INSPECTION_ACCEPTED_APPROVAL_PURPOSE,
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID,
  FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION,
  FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA,
  FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_ORIGIN,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID,
  FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION,
  FINDING_INSPECTION_ACCEPTED_RANGE_CODE,
  FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_INSPECTION_CREATION_METHOD,
  FINDING_INSPECTION_CREATION_POLICY_ID,
  FINDING_INSPECTION_CREATION_POLICY_VERSION,
  FINDING_INSPECTION_CREATION_PURPOSE,
  FINDING_INSPECTION_CREATION_TRANSITION,
  FINDING_INSPECTION_EXPLANATION_CODES,
  FINDING_INSPECTION_NORMALIZATION_VERSION,
  FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
  type FindingInspectionApplicability,
  type FindingInspectionExplanationCode,
  type FindingInspectionOtherOccurrenceClassification,
  type FindingInspectionStatus,
} from './policy.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CREATED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const COMPLETED_INGESTION = 'completed';

export type FindingInspectionAffectedVersions = {
  readonly values: readonly string[];
  readonly truncated: boolean;
  readonly omittedDistinctCount: number;
  readonly distinctCount: number;
};

export type FindingInspectionProjection = {
  readonly schemaVersion: typeof FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION;
  readonly findingId: string;
  readonly state: 'open';
  readonly asset: {
    readonly id: string;
    readonly displayName: string;
  };
  readonly component: {
    readonly id: string;
    readonly ecosystem: string | null;
    readonly namespace: string | null;
    readonly name: string;
  };
  readonly vulnerability: {
    readonly id: string;
    readonly publicId: string;
  };
  readonly affectedVersions: FindingInspectionAffectedVersions;
  readonly affectedOccurrenceCount: number;
  readonly otherOccurrenceCount: number;
  readonly otherOccurrenceClassification: FindingInspectionOtherOccurrenceClassification;
  readonly createdAt: string;
  readonly creationObservationPolicy: {
    readonly policyId: typeof FINDING_INSPECTION_CREATION_POLICY_ID;
    readonly policyVersion: typeof FINDING_INSPECTION_CREATION_POLICY_VERSION;
  };
  readonly explanationCodes: readonly FindingInspectionExplanationCode[];
  readonly creationEvidenceApplicability: FindingInspectionApplicability;
};

export type FindingInspectionResult =
  | {
      readonly schemaVersion: typeof FINDING_INSPECTION_RESULT_SCHEMA_VERSION;
      readonly status: 'found';
      readonly projection: FindingInspectionProjection;
    }
  | {
      readonly schemaVersion: typeof FINDING_INSPECTION_RESULT_SCHEMA_VERSION;
      readonly status: Exclude<FindingInspectionStatus, 'found'>;
    };

type LinkClass = 'current' | 'historical' | 'malformed' | 'unavailable';

export function projectFindingInspection(
  bundle: FindingInspectionEvidenceBundle,
  findingId: string,
): FindingInspectionResult {
  if (bundle.findingId !== findingId || !isUuid(bundle.findingId)) {
    return failure('internal_failure');
  }
  const structural = structuralFailure(bundle);
  if (structural !== null) {
    return failure(structural);
  }
  const observation = bundle.observations[0];
  if (observation === undefined) {
    return failure('malformed_persisted_state');
  }
  const classes = bundle.links.map((link) => classifyLink(bundle, observation, link));
  if (classes.some((value) => value === 'malformed')) {
    return failure('malformed_persisted_state');
  }
  if (classes.some((value) => value === 'unavailable')) {
    return failure('evidence_unavailable');
  }
  const applicability: FindingInspectionApplicability = classes.some(
    (value) => value === 'historical',
  )
    ? 'historical'
    : 'current';
  const versions = bundle.links.map((link) => link.occurrenceVersion ?? '');
  const summary = summarizeAffectedVersions(versions);
  const otherClassification: FindingInspectionOtherOccurrenceClassification =
    bundle.otherOccurrenceCount > 0
      ? 'other_occurrences_not_in_creation_evidence'
      : 'no_other_occurrences_in_creation_ingestion';
  const selected = new Set<FindingInspectionExplanationCode>([
    'finding_created_from_affected_product_match_evidence',
    'maintainer_reviewed_advisory_source',
    'independent_reviewer_approval',
    'affected_within_introduced_fixed_range',
  ]);
  if (bundle.links.length > 1) {
    selected.add('several_affected_occurrences');
  }
  if (bundle.otherOccurrenceCount > 0) {
    selected.add('other_occurrences_not_in_creation_evidence');
  }
  if (applicability === 'historical') {
    selected.add('creation_evidence_historical');
  }
  const assetName = bundle.assetDisplayName;
  const componentName = bundle.componentName;
  const publicId = bundle.vulnerabilityPublicId;
  // Display strings stay untrusted data. This projection does not encode them
  // and does not claim a future UI can render them without output encoding.
  const createdAt = bundle.createdAt;
  if (assetName === null || componentName === null || publicId === null || createdAt === null) {
    return failure('malformed_persisted_state');
  }
  return {
    schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
    status: 'found',
    projection: {
      schemaVersion: FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
      findingId: bundle.findingId,
      state: 'open',
      asset: { id: bundle.assetId, displayName: assetName },
      component: {
        id: bundle.componentId,
        ecosystem: bundle.componentEcosystem,
        namespace: bundle.componentNamespace,
        name: componentName,
      },
      vulnerability: { id: bundle.vulnerabilityId, publicId },
      affectedVersions: summary,
      affectedOccurrenceCount: bundle.links.length,
      otherOccurrenceCount: bundle.otherOccurrenceCount,
      otherOccurrenceClassification: otherClassification,
      createdAt,
      creationObservationPolicy: {
        policyId: FINDING_INSPECTION_CREATION_POLICY_ID,
        policyVersion: FINDING_INSPECTION_CREATION_POLICY_VERSION,
      },
      explanationCodes: FINDING_INSPECTION_EXPLANATION_CODES.filter((code) => selected.has(code)),
      creationEvidenceApplicability: applicability,
    },
  };
}

export function findingInspectionFailure(
  status: Exclude<FindingInspectionStatus, 'found'>,
): FindingInspectionResult {
  return failure(status);
}

function structuralFailure(
  bundle: FindingInspectionEvidenceBundle,
): 'malformed_persisted_state' | 'evidence_unavailable' | null {
  if (
    bundle.state !== 'open' ||
    bundle.componentOccurrenceId !== null ||
    bundle.resolvedAt !== null ||
    bundle.reopenedAt !== null ||
    bundle.assignedMembershipId !== null ||
    bundle.assignedTeamId !== null ||
    bundle.dueAt !== null ||
    bundle.currentRiskCalculationId !== null ||
    bundle.version !== 1 ||
    bundle.remediationTaskCount !== 0 ||
    bundle.riskAcceptanceCount !== 0 ||
    bundle.riskCalculationCount !== 0 ||
    bundle.genericEvidenceCount !== 0
  ) {
    return 'malformed_persisted_state';
  }
  if (
    !isUuid(bundle.assetId) ||
    !isUuid(bundle.componentId) ||
    !isUuid(bundle.vulnerabilityId) ||
    !isTimestamp(bundle.createdAt) ||
    !isDisplayText(bundle.assetDisplayName, 200) ||
    !isDisplayText(bundle.componentName, 512) ||
    !isDisplayText(bundle.vulnerabilityPublicId, 128) ||
    !isOptionalDisplay(bundle.componentEcosystem, 64) ||
    !isOptionalDisplay(bundle.componentNamespace, 512)
  ) {
    return 'malformed_persisted_state';
  }
  if (!bundle.assetPresent || !bundle.componentPresent || !bundle.vulnerabilityPresent) {
    return 'malformed_persisted_state';
  }
  if (!isCount(bundle.otherOccurrenceCount) || !isCount(bundle.creationIngestionOccurrenceCount)) {
    return 'malformed_persisted_state';
  }
  if (bundle.observations.length !== 1) {
    return 'malformed_persisted_state';
  }
  const observation = bundle.observations[0];
  if (observation === undefined || !observationWellFormed(observation)) {
    return 'malformed_persisted_state';
  }
  if (
    bundle.links.length !== observation.affectedEvidenceCount ||
    bundle.links.length < 1 ||
    bundle.links.length > FINDING_CREATION_MAX_EVIDENCE_SET_SIZE
  ) {
    return 'malformed_persisted_state';
  }
  if (
    bundle.creationIngestionOccurrenceCount !==
    bundle.links.length + bundle.otherOccurrenceCount
  ) {
    return 'malformed_persisted_state';
  }
  const evidenceIds = new Set<string>();
  const occurrenceIds = new Set<string>();
  for (const link of bundle.links) {
    if (evidenceIds.has(link.evidenceId) || occurrenceIds.has(link.componentOccurrenceId)) {
      return 'malformed_persisted_state';
    }
    evidenceIds.add(link.evidenceId);
    occurrenceIds.add(link.componentOccurrenceId);
  }
  return null;
}

function observationWellFormed(observation: FindingInspectionObservationRecord): boolean {
  return (
    isUuid(observation.id) &&
    isUuid(observation.sbomIngestionId) &&
    observation.occurrenceId === null &&
    observation.result === 'present' &&
    observation.method === FINDING_INSPECTION_CREATION_METHOD &&
    observation.transitionClassification === FINDING_INSPECTION_CREATION_TRANSITION &&
    observation.creationPurpose === FINDING_INSPECTION_CREATION_PURPOSE &&
    observation.creationPolicyId === FINDING_INSPECTION_CREATION_POLICY_ID &&
    observation.creationPolicyVersion === FINDING_INSPECTION_CREATION_POLICY_VERSION &&
    typeof observation.affectedEvidenceCount === 'number' &&
    Number.isInteger(observation.affectedEvidenceCount) &&
    observation.replayAgrees === true &&
    observation.evidenceRecordAgrees === true
  );
}

function classifyLink(
  bundle: FindingInspectionEvidenceBundle,
  observation: FindingInspectionObservationRecord,
  link: FindingInspectionLinkRecord,
): LinkClass {
  if (
    !isUuid(link.evidenceId) ||
    link.findingObservationId !== observation.id ||
    link.assetId !== bundle.assetId ||
    link.componentId !== bundle.componentId ||
    link.vulnerabilityId !== bundle.vulnerabilityId ||
    link.sbomIngestionId !== observation.sbomIngestionId ||
    !isUuid(link.componentOccurrenceId) ||
    link.linkOutcome !== 'affected' ||
    link.evidenceTargetAligned !== true
  ) {
    return 'malformed';
  }
  if (
    !link.evidencePresent ||
    !link.occurrencePresent ||
    !link.revisionPresent ||
    !link.approvalPresent ||
    !link.bindingPresent ||
    !link.ingestionPresent
  ) {
    return 'unavailable';
  }
  if (
    link.evidenceOutcome !== 'affected' ||
    link.productOrigin !== FINDING_INSPECTION_ACCEPTED_ORIGIN ||
    link.evaluatorId !== FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID ||
    link.evaluatorVersion !== FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION ||
    link.matchingPolicyId !== FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID ||
    link.matchingPolicyVersion !== FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID ||
    link.productEvidencePolicyId !== FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID ||
    link.productEvidencePolicyVersion !== FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION ||
    link.evidenceSchemaVersion !== FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA ||
    link.findingCreation !== 'unavailable' ||
    link.suppressionAuthority !== false ||
    link.approvalPurpose !== FINDING_INSPECTION_ACCEPTED_APPROVAL_PURPOSE ||
    link.approvalRevisionMatches !== true ||
    link.approvalVulnerabilityMatches !== true ||
    link.occurrenceVersionKnown !== true ||
    link.occurrenceAssetId !== bundle.assetId ||
    link.occurrenceComponentId !== bundle.componentId ||
    link.occurrenceIngestionId !== observation.sbomIngestionId ||
    link.rawObservedVersion !== link.occurrenceVersion ||
    !isDisplayText(link.occurrenceVersion, 256) ||
    link.normalizationVersion !== FINDING_INSPECTION_NORMALIZATION_VERSION
  ) {
    return 'malformed';
  }
  if (link.explanationCodes.length === 0) {
    return 'unavailable';
  }
  if (!explanationAccepted(link.explanationCodes)) {
    return 'malformed';
  }
  if (link.withdrawal === null || link.quarantine === null || link.ingestionState === null) {
    return 'unavailable';
  }
  if (link.withdrawal !== 'not_withdrawn' && link.withdrawal !== 'withdrawn') {
    return 'malformed';
  }
  if (link.quarantine !== 'not_quarantined' && link.quarantine !== 'quarantined') {
    return 'malformed';
  }
  if (link.ingestionState !== COMPLETED_INGESTION) {
    return 'malformed';
  }
  const current =
    link.withdrawal === 'not_withdrawn' &&
    link.quarantine === 'not_quarantined' &&
    link.hasSuccessor === false &&
    link.bindingReviewed === true &&
    link.ingestionState === COMPLETED_INGESTION &&
    bundle.assetCurrentIngestionId === observation.sbomIngestionId;
  return current ? 'current' : 'historical';
}

function explanationAccepted(codes: readonly string[]): boolean {
  return codes.length === 1 && codes[0] === FINDING_INSPECTION_ACCEPTED_RANGE_CODE;
}

function summarizeAffectedVersions(versions: readonly string[]): FindingInspectionAffectedVersions {
  const distinct = [...new Set(versions)].sort(compareDisplay);
  const truncated = distinct.length > FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT;
  const values = truncated
    ? distinct.slice(0, FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT)
    : distinct;
  return {
    values,
    truncated,
    omittedDistinctCount: distinct.length - values.length,
    distinctCount: distinct.length,
  };
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

function failure(status: Exclude<FindingInspectionStatus, 'found'>): FindingInspectionResult {
  return {
    schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
    status,
  };
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}

function isTimestamp(value: string | null): value is string {
  if (value === null || !CREATED_AT_PATTERN.test(value)) {
    return false;
  }
  return new Date(value).toISOString() === value;
}

function isDisplayText(value: string | null, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    !value.includes('\u0000')
  );
}

function isOptionalDisplay(value: string | null, maxLength: number): boolean {
  if (value === null) {
    return true;
  }
  return value.length <= maxLength && !value.includes('\u0000');
}

function isCount(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= 100_000;
}
