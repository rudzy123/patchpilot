/**
 * API-process composition root for controlled Finding creation, creation
 * inspection, and latest-observation inspection. Route modules receive the
 * constructed services. They do not import persistence factories.
 */

import { randomUUID } from 'node:crypto';

import {
  createControlledFindingCreationPersistence,
  createControlledFindingInspectionPersistence,
} from '@patchpilot/database/controlled-finding-persistence';
import { createControlledFindingLatestObservationRead } from '@patchpilot/database/controlled-finding-latest-observation-persistence';
import {
  createControlledFindingLatestObservationApplication,
  type ControlledFindingLatestObservationApplicationResult,
  type InspectControlledFindingLatestObservationCommand,
} from '@patchpilot/domain/controlled-finding-latest-observation';
import {
  createControlledFindingCreationApplication,
  createControlledFindingInspectionApplication,
  type ControlledFindingCreationApplicationResult,
  type ControlledFindingInspectionApplicationResult,
  type ControlledFindingOperatorActor,
} from '@patchpilot/domain/controlled-finding-operator';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type FindingCreationExecuteInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly request: unknown;
  readonly correlationId: string;
};

export type FindingInspectionExecuteInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly findingId: unknown;
};

export type FindingLatestObservationExecuteInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly command: InspectControlledFindingLatestObservationCommand;
};

export type FindingOperatorRuntime = {
  readonly creation: {
    execute(
      input: FindingCreationExecuteInput,
    ): Promise<ControlledFindingCreationApplicationResult>;
  };
  readonly inspection: {
    execute(
      input: FindingInspectionExecuteInput,
    ): Promise<ControlledFindingInspectionApplicationResult>;
  };
  readonly latestObservation: {
    execute(
      input: FindingLatestObservationExecuteInput,
    ): Promise<ControlledFindingLatestObservationApplicationResult>;
  };
};

export function composeControlledFindingOperatorRuntime(
  client: Parameters<typeof createControlledFindingCreationPersistence>[0],
): FindingOperatorRuntime {
  const creationPersistence = createControlledFindingCreationPersistence(client);
  const inspection = createControlledFindingInspectionApplication({
    inspection: createControlledFindingInspectionPersistence(client),
  });
  const latestObservation = createControlledFindingLatestObservationApplication({
    read: createControlledFindingLatestObservationRead(client),
  });
  return {
    creation: {
      async execute(input) {
        const correlationId = LOWERCASE_UUID.test(input.correlationId)
          ? input.correlationId
          : randomUUID();
        return createControlledFindingCreationApplication({
          persistence: creationPersistence,
          createCorrelationId: () => correlationId,
        }).execute({
          actor: input.actor,
          request: input.request,
        });
      },
    },
    inspection,
    latestObservation,
  };
}

export function denyFindingOperatorRuntime(): FindingOperatorRuntime {
  return {
    creation: {
      async execute() {
        return { status: 'authority_required' };
      },
    },
    inspection: {
      async execute() {
        return { status: 'authority_required' };
      },
    },
    latestObservation: {
      async execute() {
        return { status: 'authority_required' };
      },
    },
  };
}
