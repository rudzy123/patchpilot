import { controlledFindingLatestObservationResponseSchema } from '@patchpilot/contracts';
import type { ControlledFindingLatestObservationResponse } from '@patchpilot/contracts';

import { isCanonicalUuid } from './resource-id';

export const LATEST_OBSERVATION_HEADING = 'Latest observation evidence';

export const LATEST_OBSERVATION_LOADING = 'Loading latest observation evidence';

export const LATEST_OBSERVATION_NOT_FOUND =
  'Latest observation evidence is unavailable for this Finding.';

export const LATEST_OBSERVATION_UNAVAILABLE =
  'Latest observation evidence is temporarily unavailable.';

export const LATEST_OBSERVATION_RATE_LIMITED =
  'Too many latest-observation requests. Try again later.';

export const LATEST_OBSERVATION_REFRESH = 'Refresh latest observation evidence';

export const CREATION_SOURCE_TEXT =
  'Creation evidence is the latest available observation evidence for this Finding.';

export const LATEST_REPEATED_SOURCE_TEXT =
  'This section shows the latest legal repeated-observation evidence recorded for this Finding.';

export const OBSERVATION_RECORDED_LABEL = 'Observation recorded';

export const KNOWN_VERSIONS_HEADING = 'Known versions represented';

export const KNOWN_VERSIONS_TRUNCATED = 'The known-version summary is truncated.';

export const KNOWN_VERSIONS_COMPLETE = 'The known-version summary is complete.';

export const KNOWN_VERSIONS_NONE = 'None listed';

export const GRAPH_COMPLETENESS_LABEL = 'Graph completeness';

export const GRAPH_COMPLETENESS_TEXT =
  'This is the graph-completeness label recorded for the selected ingestion.';

export const NO_DEPENDENCIES_TEXT =
  'no_dependencies does not prove the software has no dependencies.';

export const AGGREGATE_COPY = {
  affected: {
    label: 'Affected evidence',
    explanation: 'The selected observation contains governed affected evidence.',
  },
  unaffected: {
    label: 'Unaffected evidence',
    explanation:
      'All relevant present occurrences were legally classified as unaffected in the selected ingestion.',
  },
  unknown: {
    label: 'Unknown evidence',
    explanation:
      'The evidence could not establish affected or unaffected for every relevant occurrence.',
  },
  component_absent: {
    label: 'Component absent in selected ingestion',
    explanation:
      'Governed evidence found no occurrence of the Component in the selected ingestion graph.',
  },
} as const;

export const SUPPORT_LABELS = {
  affected: 'Affected support',
  unaffected: 'Unaffected support',
  unknown: 'Unknown support',
  unknownVersion: 'Unknown-version support',
} as const;

/**
 * Accepts one closed latest-observation transport body for the requested Finding.
 * A mismatch or any unsupported shape returns null. Callers render unavailable.
 */
export function readLatestObservation(
  value: unknown,
  findingId: string,
): ControlledFindingLatestObservationResponse | null {
  if (!isCanonicalUuid(findingId)) {
    return null;
  }
  const parsed = controlledFindingLatestObservationResponseSchema.safeParse(value);
  if (!parsed.success || parsed.data.findingId !== findingId) {
    return null;
  }
  return parsed.data;
}
