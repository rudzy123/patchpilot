/**
 * Canonical Product Match Evidence identity sets.
 * The fingerprint is a binding input. It is not Finding authority.
 * SHA-256 equality does not replace full evidence-row validation.
 */

import { createHash } from 'node:crypto';

import {
  FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION,
  FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
} from './policy.js';
import { isHostileProxy, ownDataProperties } from './plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type FindingCreationEvidenceSet = {
  readonly ids: readonly string[];
  readonly fingerprint: string;
};

export type FindingCreationEvidenceSetFailure = {
  readonly ok: false;
  readonly reason:
    | 'evidence_set_empty'
    | 'evidence_set_duplicate'
    | 'evidence_set_unsorted'
    | 'evidence_set_malformed'
    | 'evidence_set_oversized'
    | 'evidence_set_hostile';
};

export type FindingCreationEvidenceSetParse =
  | { readonly ok: true; readonly evidenceSet: FindingCreationEvidenceSet }
  | FindingCreationEvidenceSetFailure;

export function parseFindingCreationEvidenceSet(value: unknown): FindingCreationEvidenceSetParse {
  const ids = readCanonicalIds(value);
  if (!ids.ok) {
    return ids;
  }
  return {
    ok: true,
    evidenceSet: Object.freeze({
      ids: ids.ids,
      fingerprint: fingerprintEvidenceIds(ids.ids),
    }),
  };
}

export function evidenceSetsMatch(
  left: FindingCreationEvidenceSet,
  right: FindingCreationEvidenceSet,
): boolean {
  if (left.fingerprint !== right.fingerprint || left.ids.length !== right.ids.length) {
    return false;
  }
  for (let index = 0; index < left.ids.length; index += 1) {
    if (left.ids[index] !== right.ids[index]) {
      return false;
    }
  }
  return true;
}

function fingerprintEvidenceIds(ids: readonly string[]): string {
  return createHash('sha256').update(canonicalEvidenceMaterial(ids), 'utf8').digest('hex');
}

function canonicalEvidenceMaterial(ids: readonly string[]): string {
  const fields: string[] = [
    lengthPrefixed('schema', FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION),
    lengthPrefixed('count', String(ids.length)),
  ];
  for (let index = 0; index < ids.length; index += 1) {
    const id = ids[index];
    if (id === undefined) {
      throw new Error('finding creation evidence id missing');
    }
    fields.push(lengthPrefixed(`id.${String(index)}`, id));
  }
  return fields.join('|');
}

function lengthPrefixed(name: string, value: string): string {
  return `${String(name.length)}:${name}${String(value.length)}:${value}`;
}

function readCanonicalIds(
  value: unknown,
): { readonly ok: true; readonly ids: readonly string[] } | FindingCreationEvidenceSetFailure {
  if (
    typeof value !== 'object' ||
    value === null ||
    isHostileProxy(value) ||
    !Array.isArray(value)
  ) {
    return fail('evidence_set_hostile');
  }
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    return fail('evidence_set_hostile');
  }
  const owned = ownDataProperties(value as unknown as Record<string, unknown>);
  if (!owned.ok) {
    return fail('evidence_set_hostile');
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
    return fail('evidence_set_hostile');
  }
  const length = lengthDescriptor.value;
  if (length === 0) {
    return fail('evidence_set_empty');
  }
  if (length > FINDING_CREATION_MAX_EVIDENCE_SET_SIZE) {
    return fail('evidence_set_oversized');
  }
  const allowed = new Set<string>(['length']);
  for (let index = 0; index < length; index += 1) {
    allowed.add(String(index));
  }
  for (const key of owned.keys) {
    if (!allowed.has(key)) {
      return fail('evidence_set_hostile');
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
      return fail('evidence_set_hostile');
    }
    const id = descriptor.value;
    if (!UUID_LOWER_PATTERN.test(id)) {
      return fail('evidence_set_malformed');
    }
    if (seen.has(id)) {
      return fail('evidence_set_duplicate');
    }
    seen.add(id);
    if (previous !== null && id <= previous) {
      return fail('evidence_set_unsorted');
    }
    previous = id;
    ids.push(id);
  }
  return { ok: true, ids: Object.freeze(ids) };
}

function fail(
  reason: FindingCreationEvidenceSetFailure['reason'],
): FindingCreationEvidenceSetFailure {
  return { ok: false, reason };
}
