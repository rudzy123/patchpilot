import { PRIORITY_BANDS } from '@patchpilot/domain';
import { z } from 'zod';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OBSERVED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const lowercaseUuidSchema = z.string().regex(LOWERCASE_UUID);
const reasonSchema = z.string().min(1).max(2000);
const bandSchema = z.enum(PRIORITY_BANDS);
const expiresSchema = z.string().regex(OBSERVED_AT);

const noneSchema = z
  .object({
    status: z.literal('none'),
    priorReviewExists: z.literal(false),
  })
  .strict();

const noneForCurrentSchema = z
  .object({
    status: z.literal('none_for_current_calculation'),
    priorReviewExists: z.literal(true),
  })
  .strict();

export const priorityReviewMarkerSchema = z.discriminatedUnion('status', [
  noneSchema,
  noneForCurrentSchema,
  z
    .object({
      status: z.literal('accepted'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal('withdrawn'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal('corrected'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      correctedBand: bandSchema,
      expiresAt: expiresSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal('expired'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      correctedBand: bandSchema,
      expiresAt: expiresSchema,
    })
    .strict(),
]);

export const findingPriorityReviewSchema = z.discriminatedUnion('status', [
  noneSchema,
  noneForCurrentSchema,
  z
    .object({
      status: z.literal('accepted'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      reason: reasonSchema.nullable(),
    })
    .strict(),
  z
    .object({
      status: z.literal('withdrawn'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      reason: reasonSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal('corrected'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      correctedBand: bandSchema,
      expiresAt: expiresSchema,
      reason: reasonSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal('expired'),
      priorReviewExists: z.boolean(),
      reviewId: lowercaseUuidSchema,
      correctedBand: bandSchema,
      expiresAt: expiresSchema,
      reason: reasonSchema,
    })
    .strict(),
]);

export const priorityReviewRequestSchema = z
  .object({
    schemaVersion: z.literal('priority_review_v1'),
    riskCalculationId: lowercaseUuidSchema,
    supersedesReviewId: lowercaseUuidSchema.nullable(),
    decision: z.enum(['accepted', 'corrected', 'withdrawn']),
    correctedBand: bandSchema.optional(),
    expiresAt: expiresSchema.optional(),
    reason: reasonSchema.optional(),
  })
  .strict();

export const priorityReviewResponseSchema = z
  .object({
    schemaVersion: z.literal('priority_review_v1'),
    status: z.enum(['recorded', 'already_applied']),
    reviewId: lowercaseUuidSchema,
    findingId: lowercaseUuidSchema,
    riskCalculationId: lowercaseUuidSchema,
  })
  .strict();

export type PriorityReviewRequest = z.infer<typeof priorityReviewRequestSchema>;
export type PriorityReviewResponse = z.infer<typeof priorityReviewResponseSchema>;
