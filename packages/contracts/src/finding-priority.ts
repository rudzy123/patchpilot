import {
  PERSISTED_RISK_CALCULATION_REASONS,
  PRIORITY_BANDS,
  PRIORITY_ESCALATION_REASONS,
  PRIORITY_FACTOR_EXPLANATION_CODES,
  PRIORITY_FACTOR_IDS,
  PRIORITY_FACTOR_INPUT_STATES,
  PRIORITY_FACTOR_STATUSES,
  PRIORITY_INPUT_CHANGE_SIGNALS,
  PRIORITY_RULE_EXPLANATION_CODES,
  PRIORITY_RULE_IDS,
} from '@patchpilot/domain';
import { z } from 'zod';

import { findingPriorityReviewSchema } from './priority-review.js';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const CALCULATED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const lowercaseUuidSchema = z.string().regex(LOWERCASE_UUID);

export const findingRiskCalculationRequestSchema = z.object({}).strict();

export const findingRiskCalculationResponseSchema = z
  .object({
    schemaVersion: z.literal('finding_risk_calculation_v1'),
    status: z.enum(['calculated', 'already_applied']),
    findingId: lowercaseUuidSchema,
    riskCalculationId: lowercaseUuidSchema,
    calculationReason: z.enum(PERSISTED_RISK_CALCULATION_REASONS),
  })
  .strict();

const factorRowSchema = z
  .object({
    factorId: z.enum(PRIORITY_FACTOR_IDS),
    ordinal: z.number().int().nonnegative(),
    inputState: z.enum(PRIORITY_FACTOR_INPUT_STATES),
    observedValue: z.union([z.string().max(512), z.number().finite(), z.null()]),
    normalizedPercent: z.number().finite(),
    weight: z.number().finite(),
    contributionCenti: z.number().finite(),
    status: z.enum(PRIORITY_FACTOR_STATUSES),
    explanationCode: z.enum(PRIORITY_FACTOR_EXPLANATION_CODES),
  })
  .strict();

const ruleRowSchema = z
  .object({
    ruleId: z.enum(PRIORITY_RULE_IDS),
    triggered: z.boolean(),
    upliftCenti: z.number().finite(),
    explanationCode: z.enum(PRIORITY_RULE_EXPLANATION_CODES),
  })
  .strict();

const calculationSchema = z
  .object({
    riskCalculationId: lowercaseUuidSchema,
    calculatedAt: z.string().regex(CALCULATED_AT),
    calculationReason: z.enum(PERSISTED_RISK_CALCULATION_REASONS),
    engineVersion: z.string().min(1).max(64),
    riskPolicyId: lowercaseUuidSchema,
    policyKey: z.string().min(1).max(128),
    policyVersion: z.number().int().positive(),
    policyDefinitionSha256: z.string().regex(SHA256_HEX),
    priority: z.number().finite(),
    priorityBand: z.enum(PRIORITY_BANDS),
    escalationRecommendation: z.boolean(),
    escalationReasons: z.array(z.enum(PRIORITY_ESCALATION_REASONS)),
    dueDateRecommendationDays: z.number().int().nonnegative(),
    factors: z.array(factorRowSchema),
    rules: z.array(ruleRowSchema),
  })
  .strict();

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

const notCalculatedSchema = z
  .object({
    schemaVersion: z.literal('finding_priority_v1'),
    status: z.literal('not_calculated'),
    findingId: lowercaseUuidSchema,
  })
  .strict();

const calculatedSchema = z
  .object({
    schemaVersion: z.literal('finding_priority_v1'),
    status: z.literal('calculated'),
    findingId: lowercaseUuidSchema,
    calculation: calculationSchema,
    comparability: z.enum(['reference', 'incomparable']),
    inputsChanged: inputsChangedSchema,
    review: findingPriorityReviewSchema,
  })
  .strict();

export const findingPriorityResponseSchema = z.discriminatedUnion('status', [
  notCalculatedSchema,
  calculatedSchema,
]);

export type FindingRiskCalculationRequest = z.infer<typeof findingRiskCalculationRequestSchema>;
export type FindingRiskCalculationResponse = z.infer<typeof findingRiskCalculationResponseSchema>;
export type FindingPriorityResponse = z.infer<typeof findingPriorityResponseSchema>;
