/**
 * Closed finding_inspection_command_v1 parser.
 * Organization scope comes only from trusted context.
 */

import { closedRecord, recordHasAmbientKey } from '../controlled-creation/plain.js';
import {
  FINDING_INSPECTION_AMBIENT_CLAIMS,
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from './policy.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const COMMAND_KEYS = ['schemaVersion', 'trustedContext', 'findingId'] as const;
const CONTEXT_KEYS = ['schemaVersion', 'organizationId'] as const;

export type ParsedFindingInspectionCommand = {
  readonly schemaVersion: typeof FINDING_INSPECTION_COMMAND_SCHEMA_VERSION;
  readonly organizationId: string;
  readonly findingId: string;
};

export type FindingInspectionCommandParse =
  { readonly ok: true; readonly command: ParsedFindingInspectionCommand } | { readonly ok: false };

export function parseFindingInspectionCommand(input: unknown): FindingInspectionCommandParse {
  if (recordHasAmbientKey(input, FINDING_INSPECTION_AMBIENT_CLAIMS)) {
    return { ok: false };
  }
  const values = closedRecord(input, COMMAND_KEYS);
  if (values === null) {
    return { ok: false };
  }
  if (values.get('schemaVersion') !== FINDING_INSPECTION_COMMAND_SCHEMA_VERSION) {
    return { ok: false };
  }
  const findingId = values.get('findingId');
  const trusted = parseTrustedContext(values.get('trustedContext'));
  if (!isUuid(findingId) || trusted === null) {
    return { ok: false };
  }
  return {
    ok: true,
    command: {
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      organizationId: trusted,
      findingId,
    },
  };
}

function parseTrustedContext(input: unknown): string | null {
  if (recordHasAmbientKey(input, FINDING_INSPECTION_AMBIENT_CLAIMS)) {
    return null;
  }
  const values = closedRecord(input, CONTEXT_KEYS);
  if (values === null) {
    return null;
  }
  if (values.get('schemaVersion') !== FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION) {
    return null;
  }
  const organizationId = values.get('organizationId');
  return isUuid(organizationId) ? organizationId : null;
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
