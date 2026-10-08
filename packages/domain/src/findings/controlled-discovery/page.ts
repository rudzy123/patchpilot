/**
 * One discovery page from examined pair facts.
 * Eligibility ids come from the creation predicate. This module does not
 * query storage and does not issue creation authority.
 */

import { parseFindingCreationEvidenceSet } from '../controlled-creation/evidence-set.js';
import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
} from '../controlled-creation/policy.js';
import { classifyFindingCreationReplay } from '../controlled-creation/replay.js';
import { encodeFindingDiscoveryCursor } from './cursor.js';
import type {
  FindingDiscoveryLineageFact,
  FindingDiscoveryPairFact,
  FindingDiscoveryQualifyingRow,
  FindingDiscoveryRead,
} from './port.js';
import {
  FINDING_DISCOVERY_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_DISCOVERY_CREATION_METHOD,
  FINDING_DISCOVERY_CREATION_TRANSITION,
  FINDING_DISCOVERY_EXPLANATION_CODES,
  FINDING_DISCOVERY_LIFECYCLE_UPDATE,
  FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE,
  FINDING_DISCOVERY_MAX_OVERSIZED_COUNT,
  FINDING_DISCOVERY_PUBLIC_ID_MAX_LENGTH,
  FINDING_DISCOVERY_VERSION_DISPLAY_MAX_LENGTH,
  type FindingDiscoveryClassification,
  type FindingDiscoveryExplanationCode,
} from './policy.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type FindingDiscoveryAffectedVersions = {
  readonly values: readonly string[];
  readonly truncated: boolean;
  readonly omittedDistinctCount: number;
  readonly distinctCount: number;
};

export type FindingDiscoveryAcknowledgement = {
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly expectedProductMatchEvidenceIds: readonly string[];
};

type DiscoveryCandidateBase = {
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly vulnerabilityPublicId: string;
  readonly affectedVersions: FindingDiscoveryAffectedVersions;
  readonly affectedOccurrenceCount: number;
  readonly otherOccurrenceCount: number;
  readonly explanationCodes: readonly FindingDiscoveryExplanationCode[];
};

export type FindingDiscoveryCandidate =
  | (DiscoveryCandidateBase & {
      readonly classification: 'eligible_for_creation';
      readonly acknowledgement: FindingDiscoveryAcknowledgement;
    })
  | (DiscoveryCandidateBase & {
      readonly classification: 'exact_replay_available';
      readonly acknowledgement: FindingDiscoveryAcknowledgement;
    })
  | (DiscoveryCandidateBase & {
      readonly classification: 'existing_finding';
      readonly lifecycleUpdate: typeof FINDING_DISCOVERY_LIFECYCLE_UPDATE;
    });

export type FindingDiscoveryPage = {
  readonly candidates: readonly FindingDiscoveryCandidate[];
  readonly oversizedCandidateCount: number;
  readonly nextCursor: string | null;
};

export type FindingDiscoveryAssembly =
  | { readonly status: 'page'; readonly page: FindingDiscoveryPage }
  | { readonly status: 'malformed_persisted_state' }
  | { readonly status: 'internal_failure' };

export function assembleFindingDiscoveryPage(input: {
  readonly assetId: string;
  readonly limit: number;
  readonly read: Extract<FindingDiscoveryRead, { status: 'ready' }>;
}): FindingDiscoveryAssembly {
  if (!isUuid(input.assetId) || !isPageLimit(input.limit)) {
    return { status: 'internal_failure' };
  }
  if (input.read.pairs.length > 100) {
    return { status: 'internal_failure' };
  }
  if (input.read.ingestionId !== null && !isUuid(input.read.ingestionId)) {
    return { status: 'internal_failure' };
  }
  if (!pairOrderHolds(input.read.pairs)) {
    return { status: 'internal_failure' };
  }
  const candidates: FindingDiscoveryCandidate[] = [];
  let oversizedCandidateCount = 0;
  let examined = 0;
  for (const pair of input.read.pairs) {
    examined += 1;
    const decision = classifyPair(input.assetId, input.read.ingestionId, pair);
    if (decision === 'malformed' || decision === 'internal') {
      return {
        status: decision === 'malformed' ? 'malformed_persisted_state' : 'internal_failure',
      };
    }
    if (decision === 'oversized') {
      oversizedCandidateCount += 1;
    } else if (decision !== 'skip') {
      candidates.push(decision);
    }
    if (candidates.length === input.limit) {
      break;
    }
  }
  if (
    oversizedCandidateCount < 0 ||
    oversizedCandidateCount > FINDING_DISCOVERY_MAX_OVERSIZED_COUNT ||
    candidates.length > input.limit
  ) {
    return { status: 'internal_failure' };
  }
  const more = examined < input.read.pairs.length || input.read.pairSpaceContinues;
  if (examined === 0) {
    if (more) {
      return { status: 'internal_failure' };
    }
    return {
      status: 'page',
      page: { candidates, oversizedCandidateCount, nextCursor: null },
    };
  }
  const last = input.read.pairs[examined - 1];
  if (last === undefined || input.read.ingestionId === null) {
    return { status: 'internal_failure' };
  }
  if (!more) {
    return {
      status: 'page',
      page: { candidates, oversizedCandidateCount, nextCursor: null },
    };
  }
  return {
    status: 'page',
    page: {
      candidates,
      oversizedCandidateCount,
      nextCursor: encodeFindingDiscoveryCursor({
        ingestionId: input.read.ingestionId,
        componentId: last.componentId,
        vulnerabilityId: last.vulnerabilityId,
      }),
    },
  };
}

function classifyPair(
  assetId: string,
  ingestionId: string | null,
  pair: FindingDiscoveryPairFact,
): FindingDiscoveryCandidate | 'skip' | 'oversized' | 'malformed' | 'internal' {
  if (!isUuid(pair.componentId) || !isUuid(pair.vulnerabilityId)) {
    return 'internal';
  }
  if (
    !Number.isInteger(pair.qualifyingCount) ||
    pair.qualifyingCount < 0 ||
    pair.qualifyingCount > 100_000
  ) {
    return 'internal';
  }
  if (pair.qualifyingCount === 0) {
    if (pair.qualifying.length !== 0) {
      return 'internal';
    }
    return 'skip';
  }
  if (ingestionId === null) {
    return 'internal';
  }
  if (storedLineageMalformed(pair.lineage)) {
    return 'malformed';
  }
  if (pair.qualifyingCount > FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE) {
    if (pair.qualifying.length !== 0) {
      return 'internal';
    }
    return 'oversized';
  }
  if (pair.qualifying.length !== pair.qualifyingCount) {
    return 'internal';
  }
  const ids = pair.qualifying.map((row) => row.id).sort(compareUtf16);
  if (!idsStrictlySorted(ids) || new Set(ids).size !== ids.length) {
    return 'malformed';
  }
  const occurrenceIds = pair.qualifying.map((row) => row.occurrenceId);
  if (
    occurrenceIds.some((id) => !isUuid(id)) ||
    new Set(occurrenceIds).size !== occurrenceIds.length
  ) {
    return 'malformed';
  }
  const parsed = parseFindingCreationEvidenceSet(ids);
  if (!parsed.ok) {
    return 'malformed';
  }
  const publicId = pair.vulnerabilityPublicId;
  if (!isDisplayText(publicId, FINDING_DISCOVERY_PUBLIC_ID_MAX_LENGTH)) {
    return 'malformed';
  }
  if (
    !Number.isInteger(pair.otherOccurrenceCount) ||
    pair.otherOccurrenceCount < 0 ||
    pair.otherOccurrenceCount > 100_000
  ) {
    return 'internal';
  }
  const acknowledgement: FindingDiscoveryAcknowledgement = {
    assetId,
    componentId: pair.componentId,
    vulnerabilityId: pair.vulnerabilityId,
    expectedSbomIngestionId: ingestionId,
    expectedProductMatchEvidenceIds: parsed.evidenceSet.ids,
  };
  const summary = summarizeVersions(pair.qualifying);
  const classification = classifyExisting(
    pair.lineage,
    parsed.evidenceSet.ids,
    parsed.evidenceSet.fingerprint,
    ingestionId,
  );
  if (classification === 'malformed') {
    return 'malformed';
  }
  const base: DiscoveryCandidateBase = {
    componentId: pair.componentId,
    vulnerabilityId: pair.vulnerabilityId,
    vulnerabilityPublicId: publicId,
    affectedVersions: summary,
    affectedOccurrenceCount: pair.qualifying.length,
    otherOccurrenceCount: pair.otherOccurrenceCount,
    explanationCodes: explanationCodes(classification, summary, pair),
  };
  if (classification === 'existing_finding') {
    return {
      ...base,
      classification,
      lifecycleUpdate: FINDING_DISCOVERY_LIFECYCLE_UPDATE,
    };
  }
  return {
    ...base,
    classification,
    acknowledgement,
  };
}

function classifyExisting(
  lineage: FindingDiscoveryLineageFact | null,
  evidenceIds: readonly string[],
  fingerprint: string,
  ingestionId: string,
): FindingDiscoveryClassification | 'malformed' {
  if (lineage === null) {
    return 'eligible_for_creation';
  }
  const comparison = classifyFindingCreationReplay(
    comparisonInput(lineage, evidenceIds, fingerprint, ingestionId),
  );
  if (
    comparison.classification === 'malformed_persisted_state' ||
    comparison.classification === 'comparison_rejected'
  ) {
    return 'malformed';
  }
  if (comparison.classification === 'already_applied') {
    return 'exact_replay_available';
  }
  if (
    comparison.classification === 'immutable_conflict' ||
    comparison.classification === 'finding_already_exists'
  ) {
    return 'existing_finding';
  }
  return 'malformed';
}

function storedLineageMalformed(lineage: FindingDiscoveryLineageFact | null): boolean {
  if (lineage === null) {
    return false;
  }
  const comparison = classifyFindingCreationReplay({
    schemaVersion: FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
    findingPresent: true,
    creationObservationPresent: false,
    evidenceLinksComplete: false,
    naturalIdentityAgrees: true,
    purposeAgrees: false,
    policyAgrees: false,
    evidenceFingerprintAgrees: false,
    ingestionAgrees: false,
    linkSetAgrees: false,
    persistedStateWellFormed: persistedStateWellFormed(lineage),
  });
  return (
    comparison.classification === 'malformed_persisted_state' ||
    comparison.classification === 'comparison_rejected'
  );
}

function comparisonInput(
  lineage: FindingDiscoveryLineageFact,
  evidenceIds: readonly string[],
  fingerprint: string,
  ingestionId: string,
) {
  const observation = lineage.observation;
  const linkIds = [...lineage.linkEvidenceIds];
  const parsedLinks = parseFindingCreationEvidenceSet(linkIds);
  const observationPresent =
    observation !== null &&
    observation.method === FINDING_DISCOVERY_CREATION_METHOD &&
    observation.result === 'present' &&
    observation.occurrenceId === null &&
    observation.transitionClassification === FINDING_DISCOVERY_CREATION_TRANSITION;
  const storedFingerprint = (observation?.replayFingerprint ?? '').trim();
  const linksMatchStoredFingerprint =
    observationPresent &&
    parsedLinks.ok &&
    storedFingerprint === parsedLinks.evidenceSet.fingerprint &&
    observation?.affectedEvidenceCount === linkIds.length;
  return {
    schemaVersion: FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
    findingPresent: true,
    creationObservationPresent: observationPresent,
    evidenceLinksComplete: linksMatchStoredFingerprint && sameIds(linkIds, evidenceIds),
    naturalIdentityAgrees: isUuid(lineage.findingId),
    purposeAgrees: observation?.creationPurpose === FINDING_CREATION_PURPOSE,
    policyAgrees:
      observation?.creationPolicyId === FINDING_CREATION_POLICY_ID &&
      observation?.creationPolicyVersion === FINDING_CREATION_POLICY_VERSION,
    evidenceFingerprintAgrees: storedFingerprint === fingerprint,
    ingestionAgrees: observation?.sbomIngestionId === ingestionId,
    linkSetAgrees: sameIds(linkIds, evidenceIds),
    persistedStateWellFormed: persistedStateWellFormed(lineage),
  };
}

function persistedStateWellFormed(lineage: FindingDiscoveryLineageFact): boolean {
  const observation = lineage.observation;
  const observationPresent =
    observation !== null &&
    observation.method === FINDING_DISCOVERY_CREATION_METHOD &&
    observation.result === 'present' &&
    observation.occurrenceId === null &&
    observation.transitionClassification === FINDING_DISCOVERY_CREATION_TRANSITION;
  const parsedLinks = parseFindingCreationEvidenceSet(lineage.linkEvidenceIds);
  const storedFingerprint = (observation?.replayFingerprint ?? '').trim();
  const linksMatchStoredFingerprint =
    observationPresent &&
    observation !== null &&
    parsedLinks.ok &&
    storedFingerprint === parsedLinks.evidenceSet.fingerprint &&
    observation.affectedEvidenceCount === lineage.linkEvidenceIds.length;
  const findingWellFormed =
    lineage.state === 'open' &&
    lineage.componentOccurrenceId === null &&
    lineage.resolvedAt === null &&
    lineage.reopenedAt === null &&
    lineage.assignedMembershipId === null &&
    lineage.assignedTeamId === null &&
    lineage.dueAt === null &&
    lineage.currentRiskCalculationId === null &&
    lineage.version === 1 &&
    isUuid(lineage.findingId);
  return (
    findingWellFormed &&
    lineage.observationCount <= 1 &&
    lineage.observationCount === (observation === null ? 0 : 1) &&
    (observation === null || linksMatchStoredFingerprint || !observationPresent)
  );
}

function explanationCodes(
  classification: FindingDiscoveryClassification,
  summary: FindingDiscoveryAffectedVersions,
  pair: FindingDiscoveryPairFact,
): readonly FindingDiscoveryExplanationCode[] {
  const selected = new Set<FindingDiscoveryExplanationCode>();
  if (pair.qualifying.length > 1) {
    selected.add('several_affected_occurrences');
  }
  if (summary.truncated) {
    selected.add('affected_version_summary_truncated');
  }
  if (pair.otherOccurrenceCount > 0) {
    selected.add('other_occurrences_present');
  }
  if (classification === 'existing_finding') {
    selected.add('lifecycle_update_unavailable');
  }
  return FINDING_DISCOVERY_EXPLANATION_CODES.filter((code) => selected.has(code));
}

function summarizeVersions(
  rows: readonly FindingDiscoveryQualifyingRow[],
): FindingDiscoveryAffectedVersions {
  const valid = new Set<string>();
  const invalid = new Set<string>();
  for (const row of rows) {
    if (isDisplayText(row.version, FINDING_DISCOVERY_VERSION_DISPLAY_MAX_LENGTH)) {
      valid.add(row.version);
    } else {
      invalid.add(row.version ?? '');
    }
  }
  const sorted = [...valid].sort(compareUtf16);
  const values = sorted.slice(0, FINDING_DISCOVERY_AFFECTED_VERSION_DISPLAY_LIMIT);
  const distinctCount = valid.size + invalid.size;
  const omittedDistinctCount = distinctCount - values.length;
  return {
    values,
    truncated: omittedDistinctCount > 0,
    omittedDistinctCount,
    distinctCount,
  };
}

function pairOrderHolds(pairs: readonly FindingDiscoveryPairFact[]): boolean {
  const seen = new Set<string>();
  let previous = '';
  for (const pair of pairs) {
    const key = `${pair.componentId}\u0000${pair.vulnerabilityId}`;
    if (seen.has(key) || (previous !== '' && compareUtf16(previous, key) >= 0)) {
      return false;
    }
    seen.add(key);
    previous = key;
  }
  return true;
}

function idsStrictlySorted(ids: readonly string[]): boolean {
  for (let index = 0; index < ids.length; index += 1) {
    const id = ids[index];
    if (id === undefined || !isUuid(id)) {
      return false;
    }
    const prior = index === 0 ? undefined : ids[index - 1];
    if (prior !== undefined && compareUtf16(prior, id) >= 0) {
      return false;
    }
  }
  return true;
}

function sameIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function compareUtf16(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function isDisplayText(value: string | null, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    !value.includes('\u0000')
  );
}

function isUuid(value: string): boolean {
  return UUID_LOWER_PATTERN.test(value);
}

function isPageLimit(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 20;
}
