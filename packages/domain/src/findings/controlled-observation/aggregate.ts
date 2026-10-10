/**
 * Deterministic repeated-observation aggregation.
 * No database query is performed. Callers cannot select the aggregate.
 * `absent` is a mapped observation result. It is not the product aggregate.
 */

import type { FindingObservationResult } from '../../lifecycle.js';

import {
  FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY,
  FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
  FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
  type FindingRepeatedObservationAggregate,
  type FindingRepeatedObservationNonAggregateFailure,
} from './policy.js';
import { closedRecord, isHostileProxy, ownDataProperties, ownNames } from './plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const SET_KEYS = ['schemaVersion', 'occurrences'] as const;

const KNOWN_CURRENT_KEYS = [
  'occurrenceId',
  'versionKnown',
  'directness',
  'evidenceStatus',
  'outcome',
] as const;

const KNOWN_INCOMPLETE_KEYS = [
  'occurrenceId',
  'versionKnown',
  'directness',
  'evidenceStatus',
] as const;

const UNKNOWN_VERSION_KEYS = ['occurrenceId', 'versionKnown', 'directness'] as const;

const ABSENCE_FACT_KEYS = [
  'schemaVersion',
  'ingestionStatus',
  'latestSuccessful',
  'strictlyLater',
  'normalizationVersion',
  'graphCompleteness',
  'componentCount',
  'liveOccurrenceCardinality',
  'dependencyEdgeCount',
  'liveDependencyEdgeCardinality',
  'findingComponentOccurrenceCount',
] as const;

const CALLER_SELECTION_KEYS = [
  'aggregate',
  'observationAggregate',
  'observationResult',
  'mappedResult',
  'result',
  'absenceAuthority',
  'callerAssertsAbsent',
] as const;

const DIRECTNESS_VALUES = ['direct', 'transitive', 'unspecified'] as const;

type Directness = (typeof DIRECTNESS_VALUES)[number];

type Contribution = 'affected' | 'unaffected' | 'unknown_outcome' | 'unknown_version';

export type RepeatedObservationOccurrenceContribution = {
  readonly occurrenceId: string;
  readonly directness: Directness;
  readonly contribution: Contribution;
};

export type RepeatedObservationAggregateDerivation =
  | {
      readonly status: 'derived';
      readonly aggregate: FindingRepeatedObservationAggregate;
      readonly mappedResult: FindingObservationResult;
      readonly findingState: 'open';
      readonly persisted: false;
      readonly callerSelectedAggregate: false;
      readonly occurrenceCount: number;
      readonly perOccurrence: readonly RepeatedObservationOccurrenceContribution[];
    }
  | {
      readonly status: FindingRepeatedObservationNonAggregateFailure | 'invalid_command';
      readonly aggregate: null;
      readonly mappedResult: null;
      readonly findingState: 'open';
      readonly persisted: false;
      readonly callerSelectedAggregate: false;
    };

export type ComponentAbsenceClassification =
  | {
      readonly status: 'component_absent';
      readonly aggregate: 'component_absent';
      readonly mappedResult: 'absent';
      readonly findingState: 'open';
      readonly persisted: false;
      readonly callerEstablishedAbsence: false;
      readonly meansRemediated: false;
      readonly meansVerified: false;
      readonly meansResolved: false;
      readonly meansSafe: false;
      readonly meansClosed: false;
    }
  | {
      readonly status: FindingRepeatedObservationNonAggregateFailure | 'invalid_command';
      readonly aggregate: null;
      readonly mappedResult: null;
      readonly findingState: 'open';
      readonly persisted: false;
      readonly callerEstablishedAbsence: false;
    };

type ParsedOccurrence = {
  readonly occurrenceId: string;
  readonly directness: Directness;
  readonly contribution: Contribution | 'missing_evidence' | 'multiple_evidence';
};

export function deriveRepeatedObservationAggregate(
  input: unknown,
): RepeatedObservationAggregateDerivation {
  try {
    return deriveOccurrences(input);
  } catch {
    return aggregateFailure('invalid_command');
  }
}

export function deriveComponentAbsenceClassification(
  input: unknown,
): ComponentAbsenceClassification {
  try {
    return deriveAbsence(input);
  } catch {
    return absenceFailure('invalid_command');
  }
}

function deriveOccurrences(input: unknown): RepeatedObservationAggregateDerivation {
  if (hasCallerSelection(input)) {
    return aggregateFailure('invalid_command');
  }
  const values = closedRecord(input, SET_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION
  ) {
    return aggregateFailure('invalid_command');
  }
  const parsed = readOccurrences(values.get('occurrences'));
  if (!parsed.ok) {
    return aggregateFailure(parsed.status);
  }
  if (parsed.occurrences.length === 0) {
    return aggregateFailure('evidence_unavailable');
  }
  if (parsed.occurrences.length > FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS) {
    return aggregateFailure('evidence_set_oversized');
  }
  if (
    parsed.occurrences.some(
      (occurrence) =>
        occurrence.contribution === 'missing_evidence' ||
        occurrence.contribution === 'multiple_evidence',
    )
  ) {
    return aggregateFailure('evidence_unavailable');
  }
  const contributions = parsed.occurrences.map((occurrence) => {
    const contribution = occurrence.contribution;
    if (contribution === 'missing_evidence' || contribution === 'multiple_evidence') {
      throw new Error('incomplete occurrence reached aggregation');
    }
    return {
      occurrenceId: occurrence.occurrenceId,
      directness: occurrence.directness,
      contribution,
    };
  });
  const aggregate = aggregateContributions(contributions);
  return {
    status: 'derived',
    aggregate,
    mappedResult: FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT[aggregate],
    findingState: 'open',
    persisted: false,
    callerSelectedAggregate: false,
    occurrenceCount: contributions.length,
    perOccurrence: Object.freeze(contributions),
  };
}

function aggregateContributions(
  contributions: readonly RepeatedObservationOccurrenceContribution[],
): Exclude<FindingRepeatedObservationAggregate, 'component_absent'> {
  if (contributions.some((occurrence) => occurrence.contribution === 'affected')) {
    return 'affected';
  }
  if (
    contributions.some(
      (occurrence) =>
        occurrence.contribution === 'unknown_outcome' ||
        occurrence.contribution === 'unknown_version',
    )
  ) {
    return 'unknown';
  }
  return 'unaffected';
}

function deriveAbsence(input: unknown): ComponentAbsenceClassification {
  if (hasCallerSelection(input)) {
    return absenceFailure('invalid_command');
  }
  const values = closedRecord(input, ABSENCE_FACT_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION
  ) {
    return absenceFailure('invalid_command');
  }
  const ingestionStatus = values.get('ingestionStatus');
  if (
    typeof ingestionStatus !== 'string' ||
    ingestionStatus.length === 0 ||
    ingestionStatus.length > 32
  ) {
    return absenceFailure('invalid_command');
  }
  if (ingestionStatus !== 'completed') {
    return absenceFailure('ingestion_not_completed');
  }
  if (values.get('latestSuccessful') !== true) {
    return values.get('latestSuccessful') === false
      ? absenceFailure('ingestion_not_latest')
      : absenceFailure('invalid_command');
  }
  if (values.get('strictlyLater') !== true) {
    return values.get('strictlyLater') === false
      ? absenceFailure('ingestion_not_later')
      : absenceFailure('invalid_command');
  }
  const normalizationVersion = values.get('normalizationVersion');
  if (!Object.is(normalizationVersion, FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION)) {
    return typeof normalizationVersion === 'number'
      ? absenceFailure('unsupported_normalization_version')
      : absenceFailure('invalid_command');
  }
  const graphCompleteness = values.get('graphCompleteness');
  if (
    typeof graphCompleteness !== 'string' ||
    graphCompleteness.length === 0 ||
    graphCompleteness.length > 32
  ) {
    return absenceFailure('invalid_command');
  }
  if (graphCompleteness !== 'complete' && graphCompleteness !== 'no_dependencies') {
    return absenceFailure('evidence_unavailable');
  }
  const componentCount = readCount(values.get('componentCount'));
  const liveOccurrenceCardinality = readCount(values.get('liveOccurrenceCardinality'));
  const dependencyEdgeCount = readCount(values.get('dependencyEdgeCount'));
  const liveDependencyEdgeCardinality = readCount(values.get('liveDependencyEdgeCardinality'));
  const findingComponentOccurrenceCount = readCount(values.get('findingComponentOccurrenceCount'));
  if (
    componentCount === null ||
    liveOccurrenceCardinality === null ||
    dependencyEdgeCount === null ||
    liveDependencyEdgeCardinality === null ||
    findingComponentOccurrenceCount === null
  ) {
    return absenceFailure('invalid_command');
  }
  if (
    componentCount < 1 ||
    componentCount !== liveOccurrenceCardinality ||
    findingComponentOccurrenceCount !== 0 ||
    (graphCompleteness === 'complete' &&
      (dependencyEdgeCount < 1 ||
        liveDependencyEdgeCardinality !== dependencyEdgeCount ||
        liveDependencyEdgeCardinality < 1)) ||
    (graphCompleteness === 'no_dependencies' &&
      (dependencyEdgeCount !== 0 || liveDependencyEdgeCardinality !== 0))
  ) {
    return absenceFailure('evidence_unavailable');
  }
  return {
    status: 'component_absent',
    aggregate: 'component_absent',
    mappedResult: 'absent',
    findingState: 'open',
    persisted: false,
    callerEstablishedAbsence:
      FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY.callerEstablishesAbsence,
    meansRemediated: false,
    meansVerified: false,
    meansResolved: false,
    meansSafe: false,
    meansClosed: false,
  };
}

function readOccurrences(value: unknown):
  | { readonly ok: true; readonly occurrences: readonly ParsedOccurrence[] }
  | {
      readonly ok: false;
      readonly status: 'invalid_command' | 'evidence_set_oversized';
    } {
  if (
    typeof value !== 'object' ||
    value === null ||
    isHostileProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return { ok: false, status: 'invalid_command' };
  }
  const owned = ownDataProperties(value as unknown as Record<string, unknown>);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    !owned.ok ||
    lengthDescriptor === undefined ||
    lengthDescriptor.get !== undefined ||
    typeof lengthDescriptor.value !== 'number' ||
    !Number.isInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    return { ok: false, status: 'invalid_command' };
  }
  const length = lengthDescriptor.value;
  if (length > FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS) {
    return { ok: false, status: 'evidence_set_oversized' };
  }
  const allowed = new Set<string>(['length']);
  for (let index = 0; index < length; index += 1) {
    allowed.add(String(index));
  }
  for (const key of owned.keys) {
    if (!allowed.has(key)) {
      return { ok: false, status: 'invalid_command' };
    }
  }
  const occurrences: ParsedOccurrence[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
      return { ok: false, status: 'invalid_command' };
    }
    const parsed = parseOccurrence(descriptor.value);
    if (parsed === null || seen.has(parsed.occurrenceId)) {
      return { ok: false, status: 'invalid_command' };
    }
    seen.add(parsed.occurrenceId);
    occurrences.push(parsed);
  }
  return { ok: true, occurrences };
}

function parseOccurrence(value: unknown): ParsedOccurrence | null {
  if (hasCallerSelection(value)) {
    return null;
  }
  const versionKnown = readData(value, 'versionKnown');
  if (versionKnown === false) {
    const values = closedRecord(value, UNKNOWN_VERSION_KEYS);
    if (values === null) {
      return null;
    }
    const occurrenceId = readUuid(values.get('occurrenceId'));
    const directness = readDirectness(values.get('directness'));
    if (occurrenceId === null || directness === null) {
      return null;
    }
    return { occurrenceId, directness, contribution: 'unknown_version' };
  }
  if (versionKnown !== true) {
    return null;
  }
  const evidenceStatus = readData(value, 'evidenceStatus');
  if (evidenceStatus === 'missing' || evidenceStatus === 'multiple') {
    const values = closedRecord(value, KNOWN_INCOMPLETE_KEYS);
    if (values === null || values.get('versionKnown') !== true) {
      return null;
    }
    const occurrenceId = readUuid(values.get('occurrenceId'));
    const directness = readDirectness(values.get('directness'));
    if (occurrenceId === null || directness === null) {
      return null;
    }
    return {
      occurrenceId,
      directness,
      contribution: evidenceStatus === 'missing' ? 'missing_evidence' : 'multiple_evidence',
    };
  }
  if (evidenceStatus !== 'one_current') {
    return null;
  }
  const values = closedRecord(value, KNOWN_CURRENT_KEYS);
  if (
    values === null ||
    values.get('versionKnown') !== true ||
    values.get('evidenceStatus') !== 'one_current'
  ) {
    return null;
  }
  const occurrenceId = readUuid(values.get('occurrenceId'));
  const directness = readDirectness(values.get('directness'));
  const outcome = values.get('outcome');
  if (occurrenceId === null || directness === null) {
    return null;
  }
  if (outcome !== 'affected' && outcome !== 'unaffected' && outcome !== 'unknown') {
    return null;
  }
  const contribution: Contribution =
    outcome === 'affected' ? 'affected' : outcome === 'unknown' ? 'unknown_outcome' : 'unaffected';
  return { occurrenceId, directness, contribution };
}

function hasCallerSelection(input: unknown): boolean {
  const names = ownNames(input);
  if (names === null) {
    return false;
  }
  const blocked = new Set<string>(CALLER_SELECTION_KEYS);
  return names.some((name) => blocked.has(name));
}

function readData(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null || isHostileProxy(value)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
    return undefined;
  }
  return descriptor.value;
}

function readUuid(value: unknown): string | null {
  if (typeof value !== 'string' || !UUID_LOWER_PATTERN.test(value)) {
    return null;
  }
  return value;
}

function readDirectness(value: unknown): Directness | null {
  if (typeof value !== 'string' || !(DIRECTNESS_VALUES as readonly string[]).includes(value)) {
    return null;
  }
  if (value === 'direct' || value === 'transitive' || value === 'unspecified') {
    return value;
  }
  return null;
}

function readCount(value: unknown): number | null {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0
  ) {
    return null;
  }
  return value;
}

function aggregateFailure(
  status: FindingRepeatedObservationNonAggregateFailure | 'invalid_command',
): RepeatedObservationAggregateDerivation {
  return {
    status,
    aggregate: null,
    mappedResult: null,
    findingState: 'open',
    persisted: false,
    callerSelectedAggregate: false,
  };
}

function absenceFailure(
  status: FindingRepeatedObservationNonAggregateFailure | 'invalid_command',
): ComponentAbsenceClassification {
  return {
    status,
    aggregate: null,
    mappedResult: null,
    findingState: 'open',
    persisted: false,
    callerEstablishedAbsence: false,
  };
}
