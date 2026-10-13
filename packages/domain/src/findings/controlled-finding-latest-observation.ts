/**
 * Package entry for API latest-observation composition.
 * Creation inspection does not import this module. The selector and the
 * repeated-observation writer stay out of this entry.
 */

export {
  INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
  type InspectControlledFindingLatestObservationCommand,
} from './controlled-latest-observation/command.js';

export {
  createControlledFindingLatestObservationApplication,
  type ControlledFindingLatestObservationApplicationDependencies,
  type ControlledFindingLatestObservationApplicationInput,
  type ControlledFindingLatestObservationApplicationResult,
} from './controlled-latest-observation/service.js';
