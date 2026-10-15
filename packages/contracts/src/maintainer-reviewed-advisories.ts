import { z } from 'zod';

const LOWERCASE_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_TRANSPORT_SCHEMA_VERSION =
  'maintainer_reviewed_advisory_submission_transport_v1' as const;

export const MAINTAINER_REVIEWED_ADVISORY_APPROVAL_TRANSPORT_SCHEMA_VERSION =
  'maintainer_reviewed_advisory_approval_transport_v1' as const;

export const maintainerReviewedAdvisorySubmissionResponseSchema = z.strictObject({
  schemaVersion: z.literal(MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_TRANSPORT_SCHEMA_VERSION),
  result: z.enum(['submitted', 'already_applied']),
  advisoryRevisionId: z.string().regex(LOWERCASE_UUID_V4),
});

export const maintainerReviewedAdvisoryApprovalResponseSchema = z.strictObject({
  schemaVersion: z.literal(MAINTAINER_REVIEWED_ADVISORY_APPROVAL_TRANSPORT_SCHEMA_VERSION),
  result: z.enum(['approved', 'already_applied']),
  advisoryRevisionId: z.string().regex(LOWERCASE_UUID_V4),
});

export const maintainerReviewedAdvisoryRevisionParamSchema = z.strictObject({
  revisionId: z.string().regex(LOWERCASE_UUID_V4),
});

export type MaintainerReviewedAdvisorySubmissionResponse = z.infer<
  typeof maintainerReviewedAdvisorySubmissionResponseSchema
>;
export type MaintainerReviewedAdvisoryApprovalResponse = z.infer<
  typeof maintainerReviewedAdvisoryApprovalResponseSchema
>;
