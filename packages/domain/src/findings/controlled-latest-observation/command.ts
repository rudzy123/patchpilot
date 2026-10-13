/**
 * Closed inspect_controlled_finding_latest_observation_v1 command.
 * The command carries one Finding ID. Organization authority stays on the
 * trusted actor and is rejected when the command tries to supply it.
 */

import { closedRecord, recordHasAmbientKey } from '../controlled-observation/plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION =
  'inspect_controlled_finding_latest_observation_v1' as const;

const COMMAND_KEYS = ['schemaVersion', 'findingId'] as const;

const AUTHORITY_CLAIMS = [
  'actor',
  'admin',
  'administrator',
  'authorized',
  'isAdmin',
  'maintainer',
  'member',
  'membershipId',
  'membershipRole',
  'membershipStatus',
  'organization',
  'organizationId',
  'owner',
  'permission',
  'permissions',
  'role',
  'roles',
  'sessionId',
  'userId',
  'viewer',
] as const;

export type InspectControlledFindingLatestObservationCommand = {
  readonly schemaVersion: typeof INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION;
  readonly findingId: string;
};

export type ParsedInspectControlledFindingLatestObservationCommand =
  | { readonly ok: true; readonly command: InspectControlledFindingLatestObservationCommand }
  | { readonly ok: false; readonly status: 'authority_required' | 'unavailable' };

export function parseInspectControlledFindingLatestObservationCommand(
  input: unknown,
): ParsedInspectControlledFindingLatestObservationCommand {
  if (recordHasAmbientKey(input, AUTHORITY_CLAIMS)) {
    return { ok: false, status: 'authority_required' };
  }
  const values = closedRecord(input, COMMAND_KEYS);
  if (
    values === null ||
    values.get('schemaVersion') !==
      INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION
  ) {
    return { ok: false, status: 'unavailable' };
  }
  const findingId = values.get('findingId');
  if (!isUuid(findingId)) {
    return { ok: false, status: 'unavailable' };
  }
  return {
    ok: true,
    command: {
      schemaVersion: INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
      findingId,
    },
  };
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
