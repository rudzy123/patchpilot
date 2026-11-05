import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  PRIORITY_BANDS,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_INPUT_CHANGE_SIGNALS,
  REMEDIATION_QUEUE_COMPARISON_MESSAGE,
} from '@patchpilot/domain';
import { z } from 'zod';

import { priorityReviewMarkerSchema } from './priority-review.js';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const OBSERVED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const lowercaseUuidSchema = z.string().regex(LOWERCASE_UUID);

const inputsChangedSchema = z
  .object({
    status: z.enum(['none_detected', 'detected']),
    signals: z.array(z.enum(PRIORITY_INPUT_CHANGE_SIGNALS)),
  })
  .strict()
  .superRefine((value, context) => {
    let previous = -1;
    for (const signal of value.signals) {
      const index = PRIORITY_INPUT_CHANGE_SIGNALS.indexOf(signal);
      if (index <= previous) {
        context.addIssue({ code: 'custom', message: 'signal order', path: ['signals'] });
        return;
      }
      previous = index;
    }
    const detected = value.signals.length > 0;
    if ((value.status === 'detected') !== detected) {
      context.addIssue({ code: 'custom', message: 'signal status', path: ['status'] });
    }
  });

const identitySchema = {
  findingId: lowercaseUuidSchema,
  assetId: lowercaseUuidSchema,
  assetName: z.string().min(1).max(200),
  componentName: z.string().min(1).max(512),
  componentVersion: z.string().min(1).max(256),
  vulnerabilityPublicId: z.string().min(1).max(128),
  humanReview: priorityReviewMarkerSchema,
};

const policySchema = z
  .object({
    riskPolicyId: lowercaseUuidSchema,
    policyKey: z.string().min(1).max(128),
    policyVersion: z.number().int().positive(),
    policyDefinitionSha256: z.string().regex(SHA256_HEX),
  })
  .strict();

const calculatedFields = {
  ...identitySchema,
  priorityBand: z.enum(PRIORITY_BANDS),
  priority: z.number().finite(),
  policy: policySchema,
  calculatedAt: z.string().regex(OBSERVED_AT),
  inputsChanged: inputsChangedSchema,
};

const rankedRowSchema = z.object(calculatedFields).strict();

const incomparableRowSchema = rankedRowSchema
  .extend({
    comparisonMessage: z.literal(REMEDIATION_QUEUE_COMPARISON_MESSAGE),
  })
  .strict();

const notCalculatedRowSchema = z.object(identitySchema).strict();

const referenceSchema = z
  .object({
    policyKey: z.literal(BUILTIN_PRIORITY_POLICY_KEY),
    policyVersion: z.literal(BUILTIN_PRIORITY_POLICY_VERSION),
    policyDefinitionSha256: z.string().regex(SHA256_HEX),
    engineVersion: z.literal(PRIORITY_CALCULATION_ENGINE_VERSION),
  })
  .strict();

const countsSchema = z
  .object({
    ranked: z.number().int().nonnegative(),
    incomparable: z.number().int().nonnegative(),
    not_calculated: z.number().int().nonnegative(),
  })
  .strict();

const sharedResponse = {
  schemaVersion: z.literal('remediation_queue_v1'),
  asOf: z.string().regex(OBSERVED_AT),
  reference: referenceSchema,
  counts: countsSchema,
  limit: z.number().int().min(1).max(50),
  nextCursor: z.string().min(1).max(2048).nullable(),
};

export const remediationQueueResponseSchema = z.discriminatedUnion('section', [
  z
    .object({
      ...sharedResponse,
      section: z.literal('ranked'),
      rows: z.array(rankedRowSchema),
    })
    .strict(),
  z
    .object({
      ...sharedResponse,
      section: z.literal('incomparable'),
      rows: z.array(incomparableRowSchema),
    })
    .strict(),
  z
    .object({
      ...sharedResponse,
      section: z.literal('not_calculated'),
      rows: z.array(notCalculatedRowSchema),
    })
    .strict(),
]);

export type RemediationQueueResponse = z.infer<typeof remediationQueueResponseSchema>;
