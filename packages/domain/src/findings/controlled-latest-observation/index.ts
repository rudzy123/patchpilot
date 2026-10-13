/**
 * Latest-observation application contracts.
 * The API composition root is the only production importer.
 * Creation inspection does not import this module.
 */

export {
  INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
  type InspectControlledFindingLatestObservationCommand,
} from './command.js';

export {
  type ControlledFindingLatestObservationReadOutcome,
  type ControlledFindingLatestObservationReadPort,
  type ControlledFindingLatestObservationReadQuery,
} from './port.js';

export {
  createControlledFindingLatestObservationApplication,
  type ControlledFindingLatestObservationApplicationDependencies,
  type ControlledFindingLatestObservationApplicationInput,
  type ControlledFindingLatestObservationApplicationResult,
} from './service.js';
