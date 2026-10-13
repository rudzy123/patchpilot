/**
 * Internal latest-observation application service.
 * Requires finding:inspect. Organization scope comes from the trusted actor.
 * The injected read port is the committed selector and adapter. Construction
 * performs no I/O. This module does not compose production inspection.
 */

import { closedRecord, recordHasAmbientKey } from '../controlled-observation/plain.js';
import {
  parseControlledFindingOperatorActor,
  type ControlledFindingOperatorActor,
} from '../controlled-operator/actor.js';
import {
  FINDING_INSPECT_PERMISSION,
  roleGrantsControlledFindingOperatorPermission,
} from '../controlled-operator/permissions.js';
import {
  parseInspectControlledFindingLatestObservationCommand,
  type InspectControlledFindingLatestObservationCommand,
} from './command.js';
import type { ControlledFindingLatestObservationReadPort } from './port.js';
import {
  authorityRequired,
  mapControlledFindingLatestObservationRead,
  unavailableResult,
  type ControlledFindingLatestObservationApplicationResult,
} from './result.js';

const INPUT_KEYS = ['actor', 'command'] as const;

const INPUT_AUTHORITY_CLAIMS = [
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

export type ControlledFindingLatestObservationApplicationDependencies = {
  readonly read: ControlledFindingLatestObservationReadPort;
};

export type ControlledFindingLatestObservationApplicationInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly command: InspectControlledFindingLatestObservationCommand;
};

export type { ControlledFindingLatestObservationApplicationResult };

export function createControlledFindingLatestObservationApplication(
  dependencies: ControlledFindingLatestObservationApplicationDependencies,
) {
  const read = dependencies.read;
  return {
    async execute(input: unknown): Promise<ControlledFindingLatestObservationApplicationResult> {
      try {
        return await executeLatestObservation(read, input);
      } catch {
        return unavailableResult();
      }
    },
  };
}

async function executeLatestObservation(
  read: ControlledFindingLatestObservationReadPort,
  input: unknown,
): Promise<ControlledFindingLatestObservationApplicationResult> {
  if (recordHasAmbientKey(input, INPUT_AUTHORITY_CLAIMS)) {
    return authorityRequired();
  }
  const envelope = closedRecord(input, INPUT_KEYS);
  if (envelope === null) {
    return authorityRequired();
  }
  const actor = parseControlledFindingOperatorActor(envelope.get('actor'));
  if (
    actor === null ||
    !roleGrantsControlledFindingOperatorPermission(actor.role, FINDING_INSPECT_PERMISSION)
  ) {
    return authorityRequired();
  }
  const command = parseInspectControlledFindingLatestObservationCommand(envelope.get('command'));
  if (!command.ok) {
    return command.status === 'authority_required' ? authorityRequired() : unavailableResult();
  }
  if (typeof read.read !== 'function') {
    return unavailableResult();
  }
  let outcome: unknown;
  try {
    outcome = await read.read({
      organizationId: actor.organizationId,
      findingId: command.command.findingId,
    });
  } catch {
    return unavailableResult();
  }
  return mapControlledFindingLatestObservationRead(outcome, command.command.findingId);
}
