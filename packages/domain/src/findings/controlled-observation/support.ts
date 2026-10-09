/**
 * Canonical repeated-observation support.
 * Evidence-set support and component-absence support are mutually exclusive.
 * The fingerprint is a binding input. It is not observation authority.
 * SHA-256 equality does not replace full semantic validation.
 * This module does not query storage and does not establish absence.
 */

import { createHash } from 'node:crypto';

import {
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
  type FindingRepeatedObservationReason,
} from './policy.js';
import { closedRecord, isHostileProxy, ownDataProperties, ownNames } from './plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const EVIDENCE_SUPPORT_KEYS = [
  'schemaVersion',
  'kind',
  'productMatchEvidenceIds',
  'unknownVersionOccurrenceIds',
] as const;

const ABSENCE_SUPPORT_KEYS = [
  'schemaVersion',
  'kind',
  'sbomIngestionId',
  'graphCompleteness',
  'componentCount',
  'occurrenceCardinality',
  'dependencyEdgeCount',
  'expectedFindingComponentOccurrenceCount',
  'normalizationVersion',
] as const;

const EVIDENCE_ONLY_KEYS = ['productMatchEvidenceIds', 'unknownVersionOccurrenceIds'] as const;

const ABSENCE_ONLY_KEYS = [
  'graphCompleteness',
  'componentCount',
  'occurrenceCardinality',
  'dependencyEdgeCount',
  'expectedFindingComponentOccurrenceCount',
  'normalizationVersion',
  'sbomIngestionId',
] as const;

const ACCEPTED_ABSENCE_GRAPHS = ['complete', 'no_dependencies'] as const;

export type FindingRepeatedObservationAbsenceGraph = (typeof ACCEPTED_ABSENCE_GRAPHS)[number];

function isAcceptedAbsenceGraph(value: string): value is FindingRepeatedObservationAbsenceGraph {
  return (ACCEPTED_ABSENCE_GRAPHS as readonly string[]).includes(value);
}

export type FindingRepeatedObservationEvidenceSupport = {
  readonly kind: 'evidence_set';
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION;
  readonly productMatchEvidenceIds: readonly string[];
  readonly unknownVersionOccurrenceIds: readonly string[];
  readonly supportCount: number;
  readonly fingerprint: string;
};

export type FindingRepeatedObservationAbsenceSupport = {
  readonly kind: 'component_absence';
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION;
  readonly sbomIngestionId: string;
  readonly graphCompleteness: FindingRepeatedObservationAbsenceGraph;
  readonly componentCount: number;
  readonly occurrenceCardinality: number;
  readonly dependencyEdgeCount: number;
  readonly expectedFindingComponentOccurrenceCount: 0;
  readonly normalizationVersion: typeof FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION;
  readonly fingerprint: string;
  readonly callerEstablishesAbsence: false;
};

export type FindingRepeatedObservationSupport =
  FindingRepeatedObservationEvidenceSupport | FindingRepeatedObservationAbsenceSupport;

export type FindingRepeatedObservationSupportParse =
  | { readonly ok: true; readonly support: FindingRepeatedObservationSupport }
  | { readonly ok: false; readonly reason: FindingRepeatedObservationReason };

type ListRead =
  | { readonly ok: true; readonly ids: readonly string[] }
  | {
      readonly ok: false;
      readonly failure: 'hostile' | 'malformed' | 'duplicate' | 'unsorted' | 'oversized';
    };

export function parseFindingRepeatedObservationSupport(
  value: unknown,
  boundIngestionId: string,
): FindingRepeatedObservationSupportParse {
  const names = ownNames(value);
  if (names === null) {
    return fail('evidence_set_hostile');
  }
  const nameSet = new Set(names);
  const hasEvidence = EVIDENCE_ONLY_KEYS.some((key) => nameSet.has(key));
  const hasAbsence = ABSENCE_ONLY_KEYS.some((key) => nameSet.has(key));
  if (hasEvidence && hasAbsence) {
    return fail('support_mutually_exclusive');
  }
  const kind = readKind(value);
  if (kind === 'evidence_set') {
    return parseEvidenceSupport(value);
  }
  if (kind === 'component_absence') {
    return parseAbsenceSupport(value, boundIngestionId);
  }
  return fail('command_rejected');
}

export function repeatedObservationSupportsMatch(
  left: FindingRepeatedObservationSupport,
  right: FindingRepeatedObservationSupport,
): FindingRepeatedObservationReason | null {
  if (left.kind !== right.kind) {
    return 'absence_proof_mismatch';
  }
  if (left.kind === 'evidence_set' && right.kind === 'evidence_set') {
    if (!idsEqual(left.productMatchEvidenceIds, right.productMatchEvidenceIds)) {
      return 'evidence_set_mismatch';
    }
    if (!idsEqual(left.unknownVersionOccurrenceIds, right.unknownVersionOccurrenceIds)) {
      return 'unknown_version_set_mismatch';
    }
    if (left.supportCount !== right.supportCount || left.fingerprint !== right.fingerprint) {
      return 'evidence_set_mismatch';
    }
    return null;
  }
  if (left.kind === 'component_absence' && right.kind === 'component_absence') {
    if (
      left.sbomIngestionId !== right.sbomIngestionId ||
      left.graphCompleteness !== right.graphCompleteness ||
      left.componentCount !== right.componentCount ||
      left.occurrenceCardinality !== right.occurrenceCardinality ||
      left.dependencyEdgeCount !== right.dependencyEdgeCount ||
      left.expectedFindingComponentOccurrenceCount !==
        right.expectedFindingComponentOccurrenceCount ||
      left.normalizationVersion !== right.normalizationVersion ||
      left.fingerprint !== right.fingerprint
    ) {
      return 'absence_proof_mismatch';
    }
    return null;
  }
  return 'absence_proof_mismatch';
}

function parseEvidenceSupport(value: unknown): FindingRepeatedObservationSupportParse {
  const values = closedRecord(value, EVIDENCE_SUPPORT_KEYS);
  if (values === null || values.get('kind') !== 'evidence_set') {
    return fail('command_rejected');
  }
  if (
    values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION
  ) {
    return fail('schema_mismatch');
  }
  const evidence = readCanonicalUuidList(values.get('productMatchEvidenceIds'));
  if (!evidence.ok) {
    return fail(evidenceListReason(evidence.failure));
  }
  const unknownVersions = readCanonicalUuidList(values.get('unknownVersionOccurrenceIds'));
  if (!unknownVersions.ok) {
    return fail(unknownVersionListReason(unknownVersions.failure));
  }
  const supportCount = evidence.ids.length + unknownVersions.ids.length;
  if (supportCount === 0) {
    return fail('evidence_set_empty');
  }
  if (supportCount > FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS) {
    return fail('evidence_set_oversized');
  }
  const unknownVersionIds = new Set(unknownVersions.ids);
  if (evidence.ids.some((id) => unknownVersionIds.has(id))) {
    // Product Match Evidence ids and ComponentOccurrence ids are different
    // facts. One value cannot occupy both collections in one support set.
    return fail('evidence_set_duplicate');
  }
  const support: FindingRepeatedObservationEvidenceSupport = Object.freeze({
    kind: 'evidence_set',
    schemaVersion: FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
    productMatchEvidenceIds: evidence.ids,
    unknownVersionOccurrenceIds: unknownVersions.ids,
    supportCount,
    fingerprint: fingerprintEvidenceSupport(evidence.ids, unknownVersions.ids, supportCount),
  });
  return { ok: true, support };
}

function parseAbsenceSupport(
  value: unknown,
  boundIngestionId: string,
): FindingRepeatedObservationSupportParse {
  const values = closedRecord(value, ABSENCE_SUPPORT_KEYS);
  if (values === null || values.get('kind') !== 'component_absence') {
    return fail('command_rejected');
  }
  if (values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION) {
    return fail('schema_mismatch');
  }
  const sbomIngestionId = values.get('sbomIngestionId');
  if (typeof sbomIngestionId !== 'string' || !UUID_LOWER_PATTERN.test(sbomIngestionId)) {
    return fail('command_rejected');
  }
  if (sbomIngestionId !== boundIngestionId) {
    return fail('ingestion_mismatch');
  }
  const graphCompleteness = values.get('graphCompleteness');
  if (typeof graphCompleteness !== 'string' || !isAcceptedAbsenceGraph(graphCompleteness)) {
    return fail('absence_graph_rejected');
  }
  const componentCount = readPositiveCount(values.get('componentCount'));
  const occurrenceCardinality = readPositiveCount(values.get('occurrenceCardinality'));
  const dependencyEdgeCount = readNonNegativeCount(values.get('dependencyEdgeCount'));
  if (componentCount === null || occurrenceCardinality === null || dependencyEdgeCount === null) {
    return fail('absence_count_rejected');
  }
  if (componentCount !== occurrenceCardinality) {
    return fail('absence_count_rejected');
  }
  if (graphCompleteness === 'complete' && dependencyEdgeCount < 1) {
    return fail('absence_graph_rejected');
  }
  if (graphCompleteness === 'no_dependencies' && dependencyEdgeCount !== 0) {
    return fail('absence_graph_rejected');
  }
  if (!Object.is(values.get('expectedFindingComponentOccurrenceCount'), 0)) {
    return fail('absence_count_rejected');
  }
  const normalizationVersion = values.get('normalizationVersion');
  if (!Object.is(normalizationVersion, FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION)) {
    return fail(
      typeof normalizationVersion === 'number'
        ? 'unsupported_normalization_version'
        : 'absence_count_rejected',
    );
  }
  const support: FindingRepeatedObservationAbsenceSupport = Object.freeze({
    kind: 'component_absence',
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
    sbomIngestionId,
    graphCompleteness,
    componentCount,
    occurrenceCardinality,
    dependencyEdgeCount,
    expectedFindingComponentOccurrenceCount: 0,
    normalizationVersion: FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
    fingerprint: fingerprintAbsenceSupport({
      sbomIngestionId,
      graphCompleteness,
      componentCount,
      occurrenceCardinality,
      dependencyEdgeCount,
    }),
    callerEstablishesAbsence: false,
  });
  return { ok: true, support };
}

function fingerprintEvidenceSupport(
  evidenceIds: readonly string[],
  unknownVersionOccurrenceIds: readonly string[],
  supportCount: number,
): string {
  const fields: string[] = [
    lengthPrefixed('schema', FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION),
    lengthPrefixed('kind', 'evidence_set'),
    lengthPrefixed('count', String(supportCount)),
    lengthPrefixed('evidence.count', String(evidenceIds.length)),
  ];
  for (let index = 0; index < evidenceIds.length; index += 1) {
    const id = evidenceIds[index];
    if (id === undefined) {
      throw new Error('repeated observation evidence id missing');
    }
    fields.push(lengthPrefixed(`evidence.${String(index)}`, id));
  }
  fields.push(lengthPrefixed('unknown.count', String(unknownVersionOccurrenceIds.length)));
  for (let index = 0; index < unknownVersionOccurrenceIds.length; index += 1) {
    const id = unknownVersionOccurrenceIds[index];
    if (id === undefined) {
      throw new Error('repeated observation unknown-version id missing');
    }
    fields.push(lengthPrefixed(`unknown.${String(index)}`, id));
  }
  return sha256(fields.join('|'));
}

function fingerprintAbsenceSupport(input: {
  readonly sbomIngestionId: string;
  readonly graphCompleteness: FindingRepeatedObservationAbsenceGraph;
  readonly componentCount: number;
  readonly occurrenceCardinality: number;
  readonly dependencyEdgeCount: number;
}): string {
  const fields = [
    lengthPrefixed('schema', FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION),
    lengthPrefixed('kind', 'component_absence'),
    lengthPrefixed('ingestion', input.sbomIngestionId),
    lengthPrefixed('graph', input.graphCompleteness),
    lengthPrefixed('componentCount', String(input.componentCount)),
    lengthPrefixed('occurrenceCardinality', String(input.occurrenceCardinality)),
    lengthPrefixed('dependencyEdgeCount', String(input.dependencyEdgeCount)),
    lengthPrefixed('findingComponentOccurrenceCount', '0'),
    lengthPrefixed(
      'normalizationVersion',
      String(FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION),
    ),
  ];
  return sha256(fields.join('|'));
}

function sha256(material: string): string {
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

function lengthPrefixed(name: string, value: string): string {
  return `${String(name.length)}:${name}${String(value.length)}:${value}`;
}

function readKind(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || isHostileProxy(value)) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'kind');
  if (
    descriptor === undefined ||
    descriptor.get !== undefined ||
    descriptor.set !== undefined ||
    typeof descriptor.value !== 'string'
  ) {
    return null;
  }
  return descriptor.value;
}

function readCanonicalUuidList(value: unknown): ListRead {
  if (
    typeof value !== 'object' ||
    value === null ||
    isHostileProxy(value) ||
    !Array.isArray(value)
  ) {
    return { ok: false, failure: 'hostile' };
  }
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    return { ok: false, failure: 'hostile' };
  }
  const owned = ownDataProperties(value as unknown as Record<string, unknown>);
  if (!owned.ok) {
    return { ok: false, failure: 'hostile' };
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (
    lengthDescriptor === undefined ||
    lengthDescriptor.get !== undefined ||
    lengthDescriptor.set !== undefined ||
    typeof lengthDescriptor.value !== 'number' ||
    !Number.isInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    return { ok: false, failure: 'hostile' };
  }
  const length = lengthDescriptor.value;
  if (length > FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS) {
    return { ok: false, failure: 'oversized' };
  }
  const allowed = new Set<string>(['length']);
  for (let index = 0; index < length; index += 1) {
    allowed.add(String(index));
  }
  for (const key of owned.keys) {
    if (!allowed.has(key)) {
      return { ok: false, failure: 'hostile' };
    }
  }
  const ids: string[] = [];
  const seen = new Set<string>();
  let previous: string | null = null;
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      typeof descriptor.value !== 'string'
    ) {
      return { ok: false, failure: 'hostile' };
    }
    const id = descriptor.value;
    if (!UUID_LOWER_PATTERN.test(id)) {
      return { ok: false, failure: 'malformed' };
    }
    if (seen.has(id)) {
      return { ok: false, failure: 'duplicate' };
    }
    seen.add(id);
    if (previous !== null && id <= previous) {
      return { ok: false, failure: 'unsorted' };
    }
    previous = id;
    ids.push(id);
  }
  return { ok: true, ids: Object.freeze(ids) };
}

function idsEqual(left: readonly string[], right: readonly string[]): boolean {
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

function readPositiveCount(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return null;
  }
  return value;
}

function readNonNegativeCount(value: unknown): number | null {
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

function evidenceListReason(
  failure: 'hostile' | 'malformed' | 'duplicate' | 'unsorted' | 'oversized',
): FindingRepeatedObservationReason {
  switch (failure) {
    case 'hostile':
      return 'evidence_set_hostile';
    case 'malformed':
      return 'evidence_set_malformed';
    case 'duplicate':
      return 'evidence_set_duplicate';
    case 'unsorted':
      return 'evidence_set_unsorted';
    case 'oversized':
      return 'evidence_set_oversized';
    default:
      return 'command_rejected';
  }
}

function unknownVersionListReason(
  failure: 'hostile' | 'malformed' | 'duplicate' | 'unsorted' | 'oversized',
): FindingRepeatedObservationReason {
  switch (failure) {
    case 'hostile':
      return 'unknown_version_hostile';
    case 'malformed':
      return 'unknown_version_malformed';
    case 'duplicate':
      return 'unknown_version_duplicate';
    case 'unsorted':
      return 'unknown_version_unsorted';
    case 'oversized':
      return 'evidence_set_oversized';
    default:
      return 'command_rejected';
  }
}

function fail(reason: FindingRepeatedObservationReason): FindingRepeatedObservationSupportParse {
  return { ok: false, reason };
}
