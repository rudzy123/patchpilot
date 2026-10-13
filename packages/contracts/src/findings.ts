import {
  FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_DISCOVERY_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_DISCOVERY_EXPLANATION_CODES,
  FINDING_DISCOVERY_LIFECYCLE_UPDATE,
  FINDING_DISCOVERY_MAX_CURSOR_LENGTH,
  FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE,
  FINDING_DISCOVERY_MAX_OVERSIZED_COUNT,
  FINDING_DISCOVERY_MAX_PAGE_SIZE,
  FINDING_DISCOVERY_PUBLIC_ID_MAX_LENGTH,
  FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_INSPECTION_APPLICABILITY,
  FINDING_INSPECTION_EXPLANATION_CODES,
  FINDING_INSPECTION_OTHER_OCCURRENCE_CLASSIFICATIONS,
  FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
} from '@patchpilot/domain';
import { z } from 'zod';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const lowercaseUuidSchema = z.string().regex(LOWERCASE_UUID);

const evidenceIdSchema = z
  .array(lowercaseUuidSchema)
  .min(1)
  .max(FINDING_CREATION_MAX_EVIDENCE_SET_SIZE)
  .superRefine((ids, context) => {
    for (let index = 1; index < ids.length; index += 1) {
      const previous = ids[index - 1];
      const current = ids[index];
      if (previous === undefined || current === undefined || previous >= current) {
        context.addIssue({
          code: 'custom',
          message: 'evidence ids must be strictly ascending',
        });
        return;
      }
    }
  });

export const controlledFindingCreationRequestSchema = z.strictObject({
  assetId: lowercaseUuidSchema,
  componentId: lowercaseUuidSchema,
  vulnerabilityId: lowercaseUuidSchema,
  expectedSbomIngestionId: lowercaseUuidSchema,
  expectedProductMatchEvidenceIds: evidenceIdSchema,
});

export const controlledFindingCreationResponseSchema = z.strictObject({
  status: z.enum(['created', 'already_applied']),
  findingId: lowercaseUuidSchema,
});

export const controlledFindingIdParamSchema = z.strictObject({
  findingId: lowercaseUuidSchema,
});

const createdAtSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

export const controlledFindingInspectionResponseSchema = z.strictObject({
  schemaVersion: z.literal(FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION),
  findingId: lowercaseUuidSchema,
  state: z.literal('open'),
  asset: z.strictObject({
    id: lowercaseUuidSchema,
    displayName: z.string().min(1).max(200),
  }),
  component: z.strictObject({
    id: lowercaseUuidSchema,
    ecosystem: z.string().min(1).max(64).nullable(),
    namespace: z.string().min(1).max(512).nullable(),
    name: z.string().min(1).max(512),
  }),
  vulnerability: z.strictObject({
    id: lowercaseUuidSchema,
    publicId: z.string().min(1).max(128),
  }),
  affectedVersions: z.strictObject({
    values: z.array(z.string()).max(FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT),
    truncated: z.boolean(),
    omittedDistinctCount: z.number().int().nonnegative(),
    distinctCount: z.number().int().nonnegative(),
  }),
  affectedOccurrenceCount: z.number().int().nonnegative(),
  otherOccurrenceCount: z.number().int().nonnegative(),
  otherOccurrenceClassification: z.enum(FINDING_INSPECTION_OTHER_OCCURRENCE_CLASSIFICATIONS),
  createdAt: createdAtSchema,
  creationObservationPolicy: z.strictObject({
    policyId: z.literal(FINDING_CREATION_POLICY_ID),
    policyVersion: z.literal(FINDING_CREATION_POLICY_VERSION),
  }),
  explanationCodes: z.array(z.enum(FINDING_INSPECTION_EXPLANATION_CODES)),
  creationEvidenceApplicability: z.enum(FINDING_INSPECTION_APPLICABILITY),
});

export type ControlledFindingCreationRequest = z.infer<
  typeof controlledFindingCreationRequestSchema
>;
export type ControlledFindingCreationResponse = z.infer<
  typeof controlledFindingCreationResponseSchema
>;
export type ControlledFindingInspectionResponse = z.infer<
  typeof controlledFindingInspectionResponseSchema
>;

export const FINDING_LATEST_OBSERVATION_TRANSPORT_SCHEMA_VERSION =
  'finding_latest_observation_transport_v1' as const;

const LATEST_OBSERVATION_VERSION_LIMIT = 256;
const LATEST_OBSERVATION_DISPLAY_LIMIT = 8;
const LATEST_OBSERVATION_DISTINCT_LIMIT = 16;
const LATEST_OBSERVATION_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

const latestObservationVersionSchema = z
  .string()
  .min(1)
  .max(LATEST_OBSERVATION_VERSION_LIMIT)
  .refine((value) => !value.includes('\u0000'));

const latestObservationKnownVersionsSchema = z
  .strictObject({
    values: z.array(latestObservationVersionSchema).max(LATEST_OBSERVATION_DISPLAY_LIMIT),
    truncated: z.boolean(),
    omittedDistinctCount: z.number().int().min(0).max(LATEST_OBSERVATION_DISTINCT_LIMIT),
    distinctCount: z.number().int().min(0).max(LATEST_OBSERVATION_DISTINCT_LIMIT),
  })
  .superRefine((summary, context) => {
    if (summary.values.length + summary.omittedDistinctCount !== summary.distinctCount) {
      context.addIssue({ code: 'custom', message: 'version summary disagrees' });
    }
    if (summary.truncated !== summary.omittedDistinctCount > 0) {
      context.addIssue({ code: 'custom', message: 'truncated disagrees' });
    }
    for (let index = 1; index < summary.values.length; index += 1) {
      const previous = summary.values[index - 1];
      const current = summary.values[index];
      if (previous === undefined || current === undefined || previous >= current) {
        context.addIssue({ code: 'custom', message: 'versions are not ordered' });
        return;
      }
    }
  });

const latestObservationSupportCountSchema = z.number().int().min(0).max(16);

const latestObservationOccurrenceEvidenceSchema = z.strictObject({
  kind: z.literal('occurrence_support'),
  affectedSupportCount: latestObservationSupportCountSchema,
  unaffectedSupportCount: latestObservationSupportCountSchema,
  unknownSupportCount: latestObservationSupportCountSchema,
  unknownVersionSupportCount: latestObservationSupportCountSchema,
  knownVersions: latestObservationKnownVersionsSchema,
});

const latestObservationAbsenceEvidenceSchema = z.strictObject({
  kind: z.literal('component_absence'),
  graphCompleteness: z.enum(['complete', 'no_dependencies']),
});

const latestObservationBase = {
  schemaVersion: z.literal(FINDING_LATEST_OBSERVATION_TRANSPORT_SCHEMA_VERSION),
  findingId: lowercaseUuidSchema,
  observedAt: z.string().regex(LATEST_OBSERVATION_TIMESTAMP),
};

export const controlledFindingLatestObservationResponseSchema = z.discriminatedUnion('aggregate', [
  z
    .strictObject({
      ...latestObservationBase,
      observationSource: z.enum(['creation', 'latest_repeated']),
      aggregate: z.literal('affected'),
      evidence: latestObservationOccurrenceEvidenceSchema,
    })
    .superRefine((value, context) => {
      if (value.observationSource !== 'creation') {
        return;
      }
      const evidence = value.evidence;
      if (
        evidence.affectedSupportCount < 1 ||
        evidence.unaffectedSupportCount !== 0 ||
        evidence.unknownSupportCount !== 0 ||
        evidence.unknownVersionSupportCount !== 0
      ) {
        context.addIssue({ code: 'custom', message: 'creation evidence disagrees' });
      }
    }),
  z.strictObject({
    ...latestObservationBase,
    observationSource: z.literal('latest_repeated'),
    aggregate: z.literal('unaffected'),
    evidence: latestObservationOccurrenceEvidenceSchema,
  }),
  z.strictObject({
    ...latestObservationBase,
    observationSource: z.literal('latest_repeated'),
    aggregate: z.literal('unknown'),
    evidence: latestObservationOccurrenceEvidenceSchema,
  }),
  z.strictObject({
    ...latestObservationBase,
    observationSource: z.literal('latest_repeated'),
    aggregate: z.literal('component_absent'),
    evidence: latestObservationAbsenceEvidenceSchema,
  }),
]);

export type ControlledFindingLatestObservationResponse = z.infer<
  typeof controlledFindingLatestObservationResponseSchema
>;

const discoveryVersionSummarySchema = z.strictObject({
  values: z.array(z.string().min(1).max(256)).max(FINDING_DISCOVERY_AFFECTED_VERSION_DISPLAY_LIMIT),
  truncated: z.boolean(),
  omittedDistinctCount: z.number().int().nonnegative(),
  distinctCount: z.number().int().nonnegative(),
});

const discoveryCandidateBase = {
  componentId: lowercaseUuidSchema,
  vulnerabilityId: lowercaseUuidSchema,
  vulnerabilityPublicId: z.string().min(1).max(FINDING_DISCOVERY_PUBLIC_ID_MAX_LENGTH),
  affectedVersions: discoveryVersionSummarySchema,
  affectedOccurrenceCount: z.number().int().min(1).max(FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE),
  otherOccurrenceCount: z.number().int().nonnegative(),
  explanationCodes: z.array(z.enum(FINDING_DISCOVERY_EXPLANATION_CODES)),
};

export const controlledFindingDiscoveryResponseSchema = z.strictObject({
  candidates: z
    .array(
      z.discriminatedUnion('classification', [
        z.strictObject({
          classification: z.literal('eligible_for_creation'),
          ...discoveryCandidateBase,
          acknowledgement: controlledFindingCreationRequestSchema,
        }),
        z.strictObject({
          classification: z.literal('exact_replay_available'),
          ...discoveryCandidateBase,
          acknowledgement: controlledFindingCreationRequestSchema,
        }),
        z.strictObject({
          classification: z.literal('existing_finding'),
          ...discoveryCandidateBase,
          lifecycleUpdate: z.literal(FINDING_DISCOVERY_LIFECYCLE_UPDATE),
        }),
      ]),
    )
    .max(FINDING_DISCOVERY_MAX_PAGE_SIZE),
  oversizedCandidateCount: z.number().int().min(0).max(FINDING_DISCOVERY_MAX_OVERSIZED_COUNT),
  nextCursor: z.string().min(1).max(FINDING_DISCOVERY_MAX_CURSOR_LENGTH).nullable(),
});

export type ControlledFindingDiscoveryResponse = z.infer<
  typeof controlledFindingDiscoveryResponseSchema
>;
