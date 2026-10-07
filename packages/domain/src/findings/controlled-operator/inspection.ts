/**
 * Controlled Finding inspection application.
 * Requires finding:inspect. Construction performs no I/O.
 * This module does not mint creation authority and does not change a Finding.
 */

import {
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from '../controlled-inspection/policy.js';
import type { FindingInspectionPort } from '../controlled-inspection/port.js';
import type { FindingInspectionResult } from '../controlled-inspection/projection.js';
import { openFindingInspection } from '../controlled-inspection/service.js';
import {
  parseControlledFindingOperatorActor,
  type ControlledFindingOperatorActor,
} from './actor.js';
import {
  FINDING_INSPECT_PERMISSION,
  roleGrantsControlledFindingOperatorPermission,
} from './permissions.js';

export type ControlledFindingInspectionApplicationDependencies = {
  readonly inspection: FindingInspectionPort;
};

export type ControlledFindingInspectionApplicationInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly findingId: unknown;
};

export type ControlledFindingInspectionApplicationResult =
  { readonly status: 'authority_required' } | FindingInspectionResult;

export function createControlledFindingInspectionApplication(
  dependencies: ControlledFindingInspectionApplicationDependencies,
) {
  const inspection = openFindingInspection(dependencies.inspection);
  return {
    async execute(
      input: ControlledFindingInspectionApplicationInput,
    ): Promise<ControlledFindingInspectionApplicationResult> {
      const actor = parseControlledFindingOperatorActor(input.actor);
      if (
        actor === null ||
        !roleGrantsControlledFindingOperatorPermission(actor.role, FINDING_INSPECT_PERMISSION)
      ) {
        return Object.freeze({ status: 'authority_required' });
      }
      return inspection.inspect({
        schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
        trustedContext: {
          schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
          organizationId: actor.organizationId,
        },
        findingId: input.findingId,
      });
    },
  };
}
