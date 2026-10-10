/**
 * Closed finding_repeated_observation_command_v1 field parser.
 * Expected identifiers are conflict checks. They do not establish authority.
 */

import {
  FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS,
  FINDING_REPEATED_OBSERVATION_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  type FindingRepeatedObservationReason,
} from './policy.js';
import { closedRecord, isHostileProxy, recordHasAmbientKey } from './plain.js';
import {
  parseFindingRepeatedObservationSupport,
  type FindingRepeatedObservationSupport,
} from './support.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type ParsedFindingRepeatedObservationCommandFields = {
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION;
  readonly purpose: typeof FINDING_REPEATED_OBSERVATION_PURPOSE;
  readonly policyId: typeof FINDING_REPEATED_OBSERVATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_REPEATED_OBSERVATION_POLICY_VERSION;
  readonly expectedFindingId: string;
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly support: FindingRepeatedObservationSupport;
  readonly correlationId: string;
  readonly authorization: object;
};

export type FindingRepeatedObservationCommandFieldParse =
  | { readonly ok: true; readonly fields: ParsedFindingRepeatedObservationCommandFields }
  | { readonly ok: false; readonly reason: FindingRepeatedObservationReason };

export function parseFindingRepeatedObservationCommandFields(
  input: unknown,
): FindingRepeatedObservationCommandFieldParse {
  if (recordHasAmbientKey(input, FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS)) {
    return { ok: false, reason: 'ambient_authority_rejected' };
  }
  const prohibited = prohibitedReason(input);
  if (prohibited !== null) {
    return { ok: false, reason: prohibited };
  }
  const values = closedRecord(input, FINDING_REPEATED_OBSERVATION_COMMAND_FIELDS);
  if (values === null) {
    return { ok: false, reason: 'command_rejected' };
  }
  if (values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION) {
    return { ok: false, reason: 'schema_mismatch' };
  }
  if (values.get('purpose') !== FINDING_REPEATED_OBSERVATION_PURPOSE) {
    return { ok: false, reason: 'purpose_mismatch' };
  }
  if (
    values.get('policyId') !== FINDING_REPEATED_OBSERVATION_POLICY_ID ||
    !Object.is(values.get('policyVersion'), FINDING_REPEATED_OBSERVATION_POLICY_VERSION)
  ) {
    return { ok: false, reason: 'policy_mismatch' };
  }
  const expectedFindingId = values.get('expectedFindingId');
  const expectedAssetId = values.get('expectedAssetId');
  const expectedComponentId = values.get('expectedComponentId');
  const expectedVulnerabilityId = values.get('expectedVulnerabilityId');
  const expectedSbomIngestionId = values.get('expectedSbomIngestionId');
  const correlationId = values.get('correlationId');
  if (
    !isUuid(expectedFindingId) ||
    !isUuid(expectedAssetId) ||
    !isUuid(expectedComponentId) ||
    !isUuid(expectedVulnerabilityId) ||
    !isUuid(expectedSbomIngestionId) ||
    !isUuid(correlationId)
  ) {
    return { ok: false, reason: 'command_rejected' };
  }
  const support = parseFindingRepeatedObservationSupport(
    values.get('support'),
    expectedSbomIngestionId,
  );
  if (!support.ok) {
    return support;
  }
  const authorization = values.get('authorization');
  if (authorization === null || authorization === undefined) {
    return { ok: false, reason: 'authorization_missing' };
  }
  if (
    typeof authorization !== 'object' ||
    Array.isArray(authorization) ||
    isHostileProxy(authorization)
  ) {
    return { ok: false, reason: 'authorization_unrecognized' };
  }
  return {
    ok: true,
    fields: {
      schemaVersion: FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
      purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
      policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
      policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
      expectedFindingId,
      expectedAssetId,
      expectedComponentId,
      expectedVulnerabilityId,
      expectedSbomIngestionId,
      support: support.support,
      correlationId,
      authorization,
    },
  };
}

function prohibitedReason(input: unknown): FindingRepeatedObservationReason | null {
  if (typeof input !== 'object' || input === null || isHostileProxy(input)) {
    return null;
  }
  const names = new Set(Object.getOwnPropertyNames(input));
  if (names.has('aggregate') || names.has('observationAggregate')) {
    return 'caller_selected_aggregate';
  }
  if (names.has('observationResult') || names.has('mappedResult') || names.has('result')) {
    return 'caller_selected_result';
  }
  const prohibited = new Set<string>(FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS);
  for (const name of names) {
    if (prohibited.has(name)) {
      return 'command_rejected';
    }
  }
  return null;
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
