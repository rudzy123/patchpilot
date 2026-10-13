/**
 * Maps one committed latest-observation read outcome onto the closed
 * application result. Selection stays in the injected port. This module
 * copies the bounded projection. Any other field fails closed.
 */

import {
  FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
  FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
  FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS,
  FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION,
  type FindingLatestObservationAbsenceEvidence,
  type FindingLatestObservationEvidenceProjection,
  type FindingLatestObservationOccurrenceEvidence,
  type FindingLatestObservationProjection,
} from '../controlled-inspection/latest-observation-selection.js';
import {
  closedRecord,
  isHostileProxy,
  ownDataProperties,
} from '../controlled-observation/plain.js';
import { mapRepeatedObservationAggregate } from '../controlled-observation/policy.js';
import {
  CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS,
  type ControlledFindingLatestObservationReadDiagnostic,
} from './port.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/;
const MONTH_LENGTHS: readonly number[] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const SUPPORT_COUNT_LIMIT = 16;
const ABSENCE_COUNT_LIMIT = 100_000;
const VERSION_LIMIT = 256;

const OCCURRENCE_EVIDENCE_KEYS = [
  'kind',
  'affectedSupportCount',
  'unaffectedSupportCount',
  'unknownSupportCount',
  'unknownVersionSupportCount',
  'knownVersions',
] as const;

const ABSENCE_EVIDENCE_KEYS = [
  'kind',
  'graphCompleteness',
  'componentCount',
  'dependencyEdgeCount',
] as const;

const SAFE_FOUND_KEYS = ['schemaVersion', 'status', 'projection'] as const;
const SAFE_TERMINAL_KEYS = ['schemaVersion', 'status'] as const;
const OUTCOME_KEYS = ['safe', 'diagnostic'] as const;

export type ControlledFindingLatestObservationApplicationResult =
  | { readonly status: 'authority_required' }
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION;
      readonly status: 'found';
      readonly projection: FindingLatestObservationProjection;
    }
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION;
      readonly status: 'not_found';
    }
  | {
      readonly schemaVersion: typeof FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION;
      readonly status: 'unavailable';
    };

export function authorityRequired(): ControlledFindingLatestObservationApplicationResult {
  return Object.freeze({ status: 'authority_required' });
}

export function unavailableResult(): ControlledFindingLatestObservationApplicationResult {
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
    status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
  });
}

export function mapControlledFindingLatestObservationRead(
  outcome: unknown,
  requestedFindingId: string,
): ControlledFindingLatestObservationApplicationResult {
  const values = closedRecord(outcome, OUTCOME_KEYS);
  if (values === null) {
    return unavailableResult();
  }
  const diagnostic = values.get('diagnostic');
  if (!isDiagnostic(diagnostic)) {
    return unavailableResult();
  }
  switch (diagnostic) {
    case 'found':
      return mapFound(values.get('safe'), requestedFindingId);
    case 'not_found':
      return mapNotFound(values.get('safe'));
    case 'malformed_persisted_state':
    case 'evidence_unavailable':
    case 'unsupported_envelope':
    case 'integrity_failure':
    case 'database_unavailable':
    case 'internal_failure':
      return mapUnavailable(values.get('safe'));
    default: {
      const exhaustive: never = diagnostic;
      return exhaustive;
    }
  }
}

function mapFound(
  safe: unknown,
  requestedFindingId: string,
): ControlledFindingLatestObservationApplicationResult {
  const values = closedRecord(safe, SAFE_FOUND_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION ||
    values.get('status') !== 'found'
  ) {
    return unavailableResult();
  }
  const projection = copyProjection(values.get('projection'), requestedFindingId);
  if (projection === null) {
    return unavailableResult();
  }
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
    status: 'found',
    projection,
  });
}

function mapNotFound(safe: unknown): ControlledFindingLatestObservationApplicationResult {
  const values = closedRecord(safe, SAFE_TERMINAL_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION ||
    values.get('status') !== 'not_found'
  ) {
    return unavailableResult();
  }
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
    status: 'not_found',
  });
}

function mapUnavailable(safe: unknown): ControlledFindingLatestObservationApplicationResult {
  const values = closedRecord(safe, SAFE_TERMINAL_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION ||
    values.get('status') !== FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE
  ) {
    return unavailableResult();
  }
  return unavailableResult();
}

function copyProjection(
  input: unknown,
  requestedFindingId: string,
): FindingLatestObservationProjection | null {
  const values = closedRecord(input, FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS);
  if (
    values === null ||
    values.get('schemaVersion') !== FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION
  ) {
    return null;
  }
  const findingId = readUuid(values.get('findingId'));
  const assetId = readUuid(values.get('assetId'));
  const componentId = readUuid(values.get('componentId'));
  const vulnerabilityId = readUuid(values.get('vulnerabilityId'));
  const observedAt = readInstant(values.get('observedAt'));
  const source = readSource(values.get('observationSource'));
  const aggregate = readAggregate(values.get('aggregate'));
  if (
    findingId === null ||
    findingId !== requestedFindingId ||
    assetId === null ||
    componentId === null ||
    vulnerabilityId === null ||
    observedAt === null ||
    source === null ||
    aggregate === null ||
    values.get('mappedResult') !== mapRepeatedObservationAggregate(aggregate)
  ) {
    return null;
  }
  const evidence = copyEvidence(values.get('evidence'), source, aggregate);
  if (evidence === null) {
    return null;
  }
  return Object.freeze({
    schemaVersion: FINDING_LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION,
    findingId,
    assetId,
    componentId,
    vulnerabilityId,
    observationSource: source,
    observedAt,
    aggregate,
    mappedResult: mapRepeatedObservationAggregate(aggregate),
    evidence,
  });
}

function copyEvidence(
  input: unknown,
  source: 'creation' | 'latest_repeated',
  aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent',
): FindingLatestObservationEvidenceProjection | null {
  if (aggregate === 'component_absent') {
    if (source !== 'latest_repeated') {
      return null;
    }
    return copyAbsence(input);
  }
  const evidence = copyOccurrence(input);
  if (evidence === null) {
    return null;
  }
  if (
    source === 'creation' &&
    (aggregate !== 'affected' ||
      evidence.affectedSupportCount < 1 ||
      evidence.unaffectedSupportCount !== 0 ||
      evidence.unknownSupportCount !== 0 ||
      evidence.unknownVersionSupportCount !== 0)
  ) {
    return null;
  }
  return evidence;
}

function copyOccurrence(input: unknown): FindingLatestObservationOccurrenceEvidence | null {
  const values = closedRecord(input, OCCURRENCE_EVIDENCE_KEYS);
  if (values === null || values.get('kind') !== 'occurrence_support') {
    return null;
  }
  const affectedSupportCount = readCount(values.get('affectedSupportCount'), SUPPORT_COUNT_LIMIT);
  const unaffectedSupportCount = readCount(
    values.get('unaffectedSupportCount'),
    SUPPORT_COUNT_LIMIT,
  );
  const unknownSupportCount = readCount(values.get('unknownSupportCount'), SUPPORT_COUNT_LIMIT);
  const unknownVersionSupportCount = readCount(
    values.get('unknownVersionSupportCount'),
    SUPPORT_COUNT_LIMIT,
  );
  const knownVersions = readVersions(values.get('knownVersions'));
  if (
    affectedSupportCount === null ||
    unaffectedSupportCount === null ||
    unknownSupportCount === null ||
    unknownVersionSupportCount === null ||
    knownVersions === null
  ) {
    return null;
  }
  return Object.freeze({
    kind: 'occurrence_support',
    affectedSupportCount,
    unaffectedSupportCount,
    unknownSupportCount,
    unknownVersionSupportCount,
    knownVersions,
  });
}

function copyAbsence(input: unknown): FindingLatestObservationAbsenceEvidence | null {
  const values = closedRecord(input, ABSENCE_EVIDENCE_KEYS);
  if (values === null || values.get('kind') !== 'component_absence') {
    return null;
  }
  const graph = values.get('graphCompleteness');
  const componentCount = readCount(values.get('componentCount'), ABSENCE_COUNT_LIMIT);
  const dependencyEdgeCount = readCount(values.get('dependencyEdgeCount'), ABSENCE_COUNT_LIMIT);
  if (componentCount === null || componentCount < 1 || dependencyEdgeCount === null) {
    return null;
  }
  if (graph === 'complete' && dependencyEdgeCount >= 1) {
    return Object.freeze({
      kind: 'component_absence',
      graphCompleteness: 'complete',
      componentCount,
      dependencyEdgeCount,
    });
  }
  if (graph === 'no_dependencies' && dependencyEdgeCount === 0) {
    return Object.freeze({
      kind: 'component_absence',
      graphCompleteness: 'no_dependencies',
      componentCount,
      dependencyEdgeCount,
    });
  }
  return null;
}

function readVersions(value: unknown): readonly string[] | null {
  const items = readClosedArray(value, SUPPORT_COUNT_LIMIT);
  if (items === null) {
    return null;
  }
  const versions: string[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    if (!isVersion(item) || seen.has(item)) {
      return null;
    }
    seen.add(item);
    versions.push(item);
  }
  return Object.freeze(versions);
}

function readClosedArray(value: unknown, limit: number): readonly unknown[] | null {
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
    lengthDescriptor.value > limit
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

function readSource(value: unknown): 'creation' | 'latest_repeated' | null {
  if (value === 'creation' || value === 'latest_repeated') {
    return value;
  }
  return null;
}

function readAggregate(
  value: unknown,
): 'affected' | 'unaffected' | 'unknown' | 'component_absent' | null {
  if (
    value === 'affected' ||
    value === 'unaffected' ||
    value === 'unknown' ||
    value === 'component_absent'
  ) {
    return value;
  }
  return null;
}

function readUuid(value: unknown): string | null {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value) ? value : null;
}

function readCount(value: unknown, max: number): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) {
    return null;
  }
  return value;
}

function isVersion(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= VERSION_LIMIT &&
    !value.includes('\u0000')
  );
}

function readInstant(value: unknown): string | null {
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
  return value;
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

function isDiagnostic(value: unknown): value is ControlledFindingLatestObservationReadDiagnostic {
  return (
    typeof value === 'string' &&
    (CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS as readonly string[]).includes(value)
  );
}
