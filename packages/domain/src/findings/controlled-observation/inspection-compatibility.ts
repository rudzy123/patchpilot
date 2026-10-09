/**
 * Future inspection compatibility for a legal repeated observation.
 * Session 1 does not change safe Finding inspection.
 * A legal later observation must not invalidate the creation observation.
 * The existing projection remains creation based. Later history stays unavailable.
 * A missing or malformed creation observation remains malformed persisted state.
 */

import {
  FINDING_INSPECTION_CREATION_METHOD,
  FINDING_INSPECTION_CREATION_POLICY_ID,
  FINDING_INSPECTION_CREATION_POLICY_VERSION,
  FINDING_INSPECTION_CREATION_PURPOSE,
  FINDING_INSPECTION_CREATION_TRANSITION,
} from '../controlled-inspection/policy.js';
import { closedRecord, isHostileProxy, ownDataProperties } from './plain.js';
import {
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_METHOD,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_TRANSITION,
  isFindingRepeatedObservationAggregate,
  mapRepeatedObservationAggregate,
} from './policy.js';

const COMPATIBILITY_INPUT_LIMIT = 32;

const COMPATIBILITY_KEYS = ['schemaVersion', 'creationObservation', 'laterObservations'] as const;

const SHAPE_KEYS = [
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
] as const;

export const FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY = Object.freeze({
  schemaVersion: FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
  legalRepeatedObservationInvalidatesCreationObservation: false,
  inspectionProjection: 'creation_based',
  laterHistoryAvailable: false,
  creationObservationIdentifiedByStrictCreationShape: true,
  missingOrMalformedCreationObservation: 'malformed_persisted_state',
  observationCountOtherThanOneIsMalformationWhenLaterRowsAreLegal: false,
  sessionImplementsInspectionCorrection: false,
} as const);

export type FindingObservationInspectionShape =
  | {
      readonly role: 'creation_observation';
      readonly wellFormed: true;
      readonly projected: true;
    }
  | {
      readonly role: 'later_observation';
      readonly wellFormed: true;
      readonly projected: false;
      readonly invalidatesCreationObservation: false;
      readonly historyExposed: false;
    }
  | {
      readonly role: 'malformed_persisted_state';
      readonly wellFormed: false;
      readonly projected: false;
    };

export type FindingInspectionCompatibilityResult =
  | {
      readonly status: 'compatible';
      readonly projection: 'creation_based';
      readonly laterHistoryAvailable: false;
      readonly creationInvalidated: false;
      readonly laterObservationCount: number;
      readonly lengthOtherThanOneIsMalformation: false;
    }
  | {
      readonly status: 'malformed_persisted_state';
      readonly projection: 'unavailable';
      readonly laterHistoryAvailable: false;
      readonly creationInvalidated: false;
    }
  | {
      readonly status: 'invalid_command';
      readonly projection: 'unavailable';
      readonly laterHistoryAvailable: false;
      readonly creationInvalidated: false;
    };

export function classifyInspectionObservationShape(
  input: unknown,
): FindingObservationInspectionShape {
  try {
    return classifyShape(input);
  } catch {
    return { role: 'malformed_persisted_state', wellFormed: false, projected: false };
  }
}

export function classifyInspectionCompatibility(
  input: unknown,
): FindingInspectionCompatibilityResult {
  try {
    return classifyCompatibility(input);
  } catch {
    return invalidCompatibility();
  }
}

function classifyShape(input: unknown): FindingObservationInspectionShape {
  const values = closedRecord(input, SHAPE_KEYS);
  if (values === null) {
    return { role: 'malformed_persisted_state', wellFormed: false, projected: false };
  }
  if (isCreationShape(values)) {
    return { role: 'creation_observation', wellFormed: true, projected: true };
  }
  if (isRepeatedShape(values)) {
    return {
      role: 'later_observation',
      wellFormed: true,
      projected: false,
      invalidatesCreationObservation: false,
      historyExposed: false,
    };
  }
  return { role: 'malformed_persisted_state', wellFormed: false, projected: false };
}

function isCreationShape(values: ReadonlyMap<string, unknown>): boolean {
  return (
    values.get('method') === FINDING_INSPECTION_CREATION_METHOD &&
    values.get('result') === 'present' &&
    values.get('occurrenceId') === null &&
    values.get('transitionClassification') === FINDING_INSPECTION_CREATION_TRANSITION &&
    values.get('creationPurpose') === FINDING_INSPECTION_CREATION_PURPOSE &&
    values.get('creationPolicyId') === FINDING_INSPECTION_CREATION_POLICY_ID &&
    Object.is(values.get('creationPolicyVersion'), FINDING_INSPECTION_CREATION_POLICY_VERSION) &&
    values.get('observationPurpose') === null &&
    values.get('observationPolicyId') === null &&
    values.get('observationPolicyVersion') === null &&
    values.get('aggregate') === null
  );
}

function isRepeatedShape(values: ReadonlyMap<string, unknown>): boolean {
  const aggregate = values.get('aggregate');
  if (!isFindingRepeatedObservationAggregate(aggregate)) {
    return false;
  }
  return (
    values.get('method') === FINDING_REPEATED_OBSERVATION_METHOD &&
    values.get('result') === mapRepeatedObservationAggregate(aggregate) &&
    values.get('occurrenceId') === null &&
    values.get('transitionClassification') === FINDING_REPEATED_OBSERVATION_TRANSITION &&
    values.get('creationPurpose') === null &&
    values.get('creationPolicyId') === null &&
    values.get('creationPolicyVersion') === null &&
    values.get('observationPurpose') === FINDING_REPEATED_OBSERVATION_PURPOSE &&
    values.get('observationPolicyId') === FINDING_REPEATED_OBSERVATION_POLICY_ID &&
    Object.is(values.get('observationPolicyVersion'), FINDING_REPEATED_OBSERVATION_POLICY_VERSION)
  );
}

function classifyCompatibility(input: unknown): FindingInspectionCompatibilityResult {
  const values = closedRecord(input, COMPATIBILITY_KEYS);
  if (values === null) {
    return invalidCompatibility();
  }
  if (
    values.get('schemaVersion') !==
    FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION
  ) {
    return invalidCompatibility();
  }
  const creation = values.get('creationObservation');
  if (creation === null || classifyShape(creation).role !== 'creation_observation') {
    return malformedCompatibility();
  }
  const later = readLaterObservations(values.get('laterObservations'));
  if (later === null) {
    return invalidCompatibility();
  }
  for (const observation of later) {
    if (classifyShape(observation).role !== 'later_observation') {
      return malformedCompatibility();
    }
  }
  return {
    status: 'compatible',
    projection: 'creation_based',
    laterHistoryAvailable: false,
    creationInvalidated: false,
    laterObservationCount: later.length,
    lengthOtherThanOneIsMalformation: false,
  };
}

function readLaterObservations(value: unknown): readonly unknown[] | null {
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
    lengthDescriptor.value > COMPATIBILITY_INPUT_LIMIT
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
  const observations: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
      return null;
    }
    observations.push(descriptor.value);
  }
  return observations;
}

function malformedCompatibility(): FindingInspectionCompatibilityResult {
  return {
    status: 'malformed_persisted_state',
    projection: 'unavailable',
    laterHistoryAvailable: false,
    creationInvalidated: false,
  };
}

function invalidCompatibility(): FindingInspectionCompatibilityResult {
  return {
    status: 'invalid_command',
    projection: 'unavailable',
    laterHistoryAvailable: false,
    creationInvalidated: false,
  };
}
