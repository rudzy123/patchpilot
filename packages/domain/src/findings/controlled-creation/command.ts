/**
 * Closed finding_creation_command_v1 field parser.
 * Expected identifiers are conflict checks. They do not establish authority.
 */

import {
  FINDING_CREATION_AMBIENT_CLAIMS,
  FINDING_CREATION_COMMAND_FIELDS,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  type FindingCreationReason,
} from './policy.js';
import {
  parseFindingCreationEvidenceSet,
  type FindingCreationEvidenceSet,
} from './evidence-set.js';
import { closedRecord, recordHasAmbientKey } from './plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type ParsedFindingCreationCommandFields = {
  readonly schemaVersion: typeof FINDING_CREATION_COMMAND_SCHEMA_VERSION;
  readonly purpose: typeof FINDING_CREATION_PURPOSE;
  readonly policyId: typeof FINDING_CREATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_CREATION_POLICY_VERSION;
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly evidenceSet: FindingCreationEvidenceSet;
  readonly correlationId: string;
  readonly authorization: object;
};

export type FindingCreationCommandFieldParse =
  | { readonly ok: true; readonly fields: ParsedFindingCreationCommandFields }
  | { readonly ok: false; readonly reason: FindingCreationReason };

export function parseFindingCreationCommandFields(
  input: unknown,
): FindingCreationCommandFieldParse {
  if (recordHasAmbientKey(input, FINDING_CREATION_AMBIENT_CLAIMS)) {
    return { ok: false, reason: 'ambient_authority_rejected' };
  }
  const values = closedRecord(input, FINDING_CREATION_COMMAND_FIELDS);
  if (values === null) {
    return { ok: false, reason: 'command_rejected' };
  }
  const schemaVersion = values.get('schemaVersion');
  if (schemaVersion !== FINDING_CREATION_COMMAND_SCHEMA_VERSION) {
    return { ok: false, reason: 'schema_mismatch' };
  }
  const purpose = values.get('purpose');
  if (purpose !== FINDING_CREATION_PURPOSE) {
    return { ok: false, reason: 'purpose_mismatch' };
  }
  const policyId = values.get('policyId');
  const policyVersion = values.get('policyVersion');
  if (
    policyId !== FINDING_CREATION_POLICY_ID ||
    !Object.is(policyVersion, FINDING_CREATION_POLICY_VERSION)
  ) {
    return { ok: false, reason: 'policy_mismatch' };
  }
  const expectedAssetId = values.get('expectedAssetId');
  const expectedComponentId = values.get('expectedComponentId');
  const expectedVulnerabilityId = values.get('expectedVulnerabilityId');
  const expectedSbomIngestionId = values.get('expectedSbomIngestionId');
  const correlationId = values.get('correlationId');
  if (
    !isUuid(expectedAssetId) ||
    !isUuid(expectedComponentId) ||
    !isUuid(expectedVulnerabilityId) ||
    !isUuid(expectedSbomIngestionId) ||
    !isUuid(correlationId)
  ) {
    return { ok: false, reason: 'command_rejected' };
  }
  const evidence = parseFindingCreationEvidenceSet(values.get('expectedProductMatchEvidenceIds'));
  if (!evidence.ok) {
    return evidence;
  }
  const authorization = values.get('authorization');
  if (authorization === null || authorization === undefined) {
    return { ok: false, reason: 'authorization_missing' };
  }
  if (typeof authorization !== 'object' || Array.isArray(authorization)) {
    return { ok: false, reason: 'authorization_unrecognized' };
  }
  return {
    ok: true,
    fields: {
      schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
      purpose: FINDING_CREATION_PURPOSE,
      policyId: FINDING_CREATION_POLICY_ID,
      policyVersion: FINDING_CREATION_POLICY_VERSION,
      expectedAssetId,
      expectedComponentId,
      expectedVulnerabilityId,
      expectedSbomIngestionId,
      evidenceSet: evidence.evidenceSet,
      correlationId,
      authorization,
    },
  };
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
