/**
 * Narrow read port for one tenant-scoped latest-observation inspection.
 * The port matches the committed adapter outcome. Diagnostic values stay on
 * this port and are not an application result.
 */

import type { FindingLatestObservationExternalResult } from '../controlled-inspection/latest-observation-selection.js';

export const CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS = [
  'found',
  'not_found',
  'malformed_persisted_state',
  'evidence_unavailable',
  'unsupported_envelope',
  'integrity_failure',
  'database_unavailable',
  'internal_failure',
] as const;

export type ControlledFindingLatestObservationReadDiagnostic =
  (typeof CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS)[number];

export type ControlledFindingLatestObservationReadQuery = {
  readonly organizationId: string;
  readonly findingId: string;
};

export type ControlledFindingLatestObservationReadOutcome = {
  readonly safe: FindingLatestObservationExternalResult;
  readonly diagnostic: ControlledFindingLatestObservationReadDiagnostic;
};

export type ControlledFindingLatestObservationReadPort = {
  read(
    query: ControlledFindingLatestObservationReadQuery,
  ): Promise<ControlledFindingLatestObservationReadOutcome>;
};
