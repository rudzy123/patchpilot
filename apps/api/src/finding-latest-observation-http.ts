/**
 * HTTP translation for one latest-observation read.
 * The application service remains the selection authority. This module copies
 * the closed transport fields and fails closed on any other shape.
 */

import { types as nodeUtilTypes } from 'node:util';

import { PERMISSION_DENIED } from '@patchpilot/auth';
import {
  controlledFindingLatestObservationResponseSchema,
  FINDING_LATEST_OBSERVATION_TRANSPORT_SCHEMA_VERSION,
  type ControlledFindingLatestObservationResponse,
} from '@patchpilot/contracts';
import type { AppError } from '@patchpilot/domain';

import { FINDING_NOT_FOUND } from './finding-http.js';
import { FINDING_OPERATOR_UNAVAILABLE } from './http-errors.js';

export const LATEST_OBSERVATION_ROUTE = '/findings/:findingId/latest-observation';

/** Committed application envelope. An unsupported version is unavailable. */
const LATEST_OBSERVATION_APPLICATION_SCHEMA_VERSION =
  'finding_latest_observation_external_result_v1';

/** Committed internal projection. Transport does not republish this literal. */
const LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION = 'finding_latest_observation_projection_v1';

const APPLICATION_FOUND_KEYS = ['schemaVersion', 'status', 'projection'] as const;
const APPLICATION_TERMINAL_KEYS = ['schemaVersion', 'status'] as const;
const APPLICATION_AUTHORITY_KEYS = ['status'] as const;

const DISPLAY_LIMIT = 8;
const DISTINCT_LIMIT = 16;
const SUPPORT_LIMIT = 16;
const VERSION_LIMIT = 256;

const OCCURRENCE_FIELDS = [
  'affectedSupportCount',
  'unaffectedSupportCount',
  'unknownSupportCount',
  'unknownVersionSupportCount',
  'knownVersions',
] as const;

const ABSENCE_FIELDS = ['graphCompleteness', 'componentCount', 'dependencyEdgeCount'] as const;

export const LATEST_OBSERVATION_METRIC_LABEL_KEYS = [
  'route',
  'method',
  'outcome',
  'statusClass',
] as const;

export type LatestObservationPublicOutcome =
  | 'found'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'unavailable';

export type LatestObservationTranslation =
  | { readonly ok: true; readonly body: ControlledFindingLatestObservationResponse }
  | { readonly ok: false; readonly error: AppError };

export function latestObservationOutcomeForError(error: AppError): LatestObservationPublicOutcome {
  switch (error.code) {
    case 'validation':
      return 'validation';
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    case 'not_found':
      return 'not_found';
    case 'rate_limited':
      return 'rate_limited';
    case 'internal':
      return 'unavailable';
    default:
      return 'unavailable';
  }
}

export function latestObservationMetricLabels(input: {
  readonly outcome: LatestObservationPublicOutcome;
  readonly statusCode: number;
}): Readonly<Record<(typeof LATEST_OBSERVATION_METRIC_LABEL_KEYS)[number], string>> {
  const statusClass = `${Math.trunc(input.statusCode / 100)}xx`;
  return Object.freeze({
    route: LATEST_OBSERVATION_ROUTE,
    method: 'GET',
    outcome: input.outcome,
    statusClass,
  });
}

export function translateLatestObservationResult(
  result: unknown,
  findingId: string,
): LatestObservationTranslation {
  const record = plainRecord(result);
  if (record === null) {
    return unavailable();
  }
  const status = record['status'];
  if (status === 'authority_required') {
    return hasExactKeys(record, APPLICATION_AUTHORITY_KEYS)
      ? { ok: false, error: PERMISSION_DENIED }
      : unavailable();
  }
  if (status === 'not_found') {
    return hasExactKeys(record, APPLICATION_TERMINAL_KEYS) &&
      record['schemaVersion'] === LATEST_OBSERVATION_APPLICATION_SCHEMA_VERSION
      ? { ok: false, error: FINDING_NOT_FOUND }
      : unavailable();
  }
  if (status === 'unavailable') {
    return unavailable();
  }
  if (status !== 'found') {
    return unavailable();
  }
  if (
    !hasExactKeys(record, APPLICATION_FOUND_KEYS) ||
    record['schemaVersion'] !== LATEST_OBSERVATION_APPLICATION_SCHEMA_VERSION
  ) {
    return unavailable();
  }
  const body = transportBody(record['projection'], findingId);
  if (body === null) {
    return unavailable();
  }
  const parsed = controlledFindingLatestObservationResponseSchema.safeParse(body);
  if (!parsed.success) {
    return unavailable();
  }
  return { ok: true, body: parsed.data };
}

function unavailable(): LatestObservationTranslation {
  return { ok: false, error: FINDING_OPERATOR_UNAVAILABLE };
}

function transportBody(
  projection: unknown,
  findingId: string,
): ControlledFindingLatestObservationResponse | null {
  const record = plainRecord(projection);
  if (
    record === null ||
    record['schemaVersion'] !== LATEST_OBSERVATION_PROJECTION_SCHEMA_VERSION ||
    record['findingId'] !== findingId
  ) {
    return null;
  }
  const observationSource = record['observationSource'];
  const aggregate = record['aggregate'];
  const observedAt = record['observedAt'];
  if (
    (observationSource !== 'creation' && observationSource !== 'latest_repeated') ||
    (aggregate !== 'affected' &&
      aggregate !== 'unaffected' &&
      aggregate !== 'unknown' &&
      aggregate !== 'component_absent') ||
    typeof observedAt !== 'string'
  ) {
    return null;
  }
  const evidence = transportEvidence(record['evidence'], observationSource, aggregate);
  if (evidence === null) {
    return null;
  }
  return {
    schemaVersion: FINDING_LATEST_OBSERVATION_TRANSPORT_SCHEMA_VERSION,
    findingId,
    observationSource,
    observedAt,
    aggregate,
    evidence,
  } as ControlledFindingLatestObservationResponse;
}

function transportEvidence(
  evidence: unknown,
  observationSource: 'creation' | 'latest_repeated',
  aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent',
): ControlledFindingLatestObservationResponse['evidence'] | null {
  const record = plainRecord(evidence);
  if (record === null || hybridEvidence(record)) {
    return null;
  }
  if (aggregate === 'component_absent') {
    if (observationSource !== 'latest_repeated' || record['kind'] !== 'component_absence') {
      return null;
    }
    const graphCompleteness = record['graphCompleteness'];
    if (graphCompleteness !== 'complete' && graphCompleteness !== 'no_dependencies') {
      return null;
    }
    return { kind: 'component_absence', graphCompleteness };
  }
  if (record['kind'] !== 'occurrence_support') {
    return null;
  }
  const affectedSupportCount = supportCount(record['affectedSupportCount']);
  const unaffectedSupportCount = supportCount(record['unaffectedSupportCount']);
  const unknownSupportCount = supportCount(record['unknownSupportCount']);
  const unknownVersionSupportCount = supportCount(record['unknownVersionSupportCount']);
  const knownVersions = knownVersionSummary(record['knownVersions']);
  if (
    affectedSupportCount === null ||
    unaffectedSupportCount === null ||
    unknownSupportCount === null ||
    unknownVersionSupportCount === null ||
    knownVersions === null
  ) {
    return null;
  }
  return {
    kind: 'occurrence_support',
    affectedSupportCount,
    unaffectedSupportCount,
    unknownSupportCount,
    unknownVersionSupportCount,
    knownVersions,
  };
}

function hybridEvidence(record: Record<string, unknown>): boolean {
  return hasOwn(record, OCCURRENCE_FIELDS) && hasOwn(record, ABSENCE_FIELDS);
}

function hasOwn(record: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.some((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const owned = Object.keys(record);
  return owned.length === keys.length && keys.every((key) => Object.hasOwn(record, key));
}

function knownVersionSummary(value: unknown): {
  readonly values: string[];
  readonly truncated: boolean;
  readonly omittedDistinctCount: number;
  readonly distinctCount: number;
} | null {
  if (!Array.isArray(value) || nodeUtilTypes.isProxy(value) || value.length > DISTINCT_LIMIT) {
    return null;
  }
  const versions: string[] = [];
  for (const item of value) {
    if (!isVersion(item)) {
      return null;
    }
    const previous = versions[versions.length - 1];
    if (previous !== undefined && previous >= item) {
      return null;
    }
    versions.push(item);
  }
  const distinctCount = versions.length;
  const displayed = versions.slice(0, DISPLAY_LIMIT);
  const omittedDistinctCount = distinctCount - displayed.length;
  return {
    values: displayed,
    truncated: omittedDistinctCount > 0,
    omittedDistinctCount,
    distinctCount,
  };
}

function supportCount(value: unknown): number | null {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > SUPPORT_LIMIT
  ) {
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

function plainRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  if (nodeUtilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return null;
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    return null;
  }
  const record: Record<string, unknown> = {};
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !Object.hasOwn(value, key)
    ) {
      return null;
    }
    record[key] = descriptor.value;
  }
  return record;
}
