/**
 * Read port for the remediation queue.
 * The adapter orders stored rows. This module stays free of infrastructure clients.
 */

import type { PriorityPolicyLookup } from './persistence-port.js';
import type { FindingPriorityReviewMarker } from './priority-review.js';
import type { RemediationQueueCursor } from './remediation-queue-cursor.js';

export const REMEDIATION_QUEUE_SECTIONS = ['ranked', 'incomparable', 'not_calculated'] as const;

export type RemediationQueueSection = (typeof REMEDIATION_QUEUE_SECTIONS)[number];

export const REMEDIATION_QUEUE_DEFAULT_LIMIT = 20;

export const REMEDIATION_QUEUE_MAX_LIMIT = 50;

export type RemediationQueueCounts = {
  readonly ranked: number;
  readonly incomparable: number;
  readonly not_calculated: number;
};

export type RemediationQueueIdentity = {
  readonly findingId: string;
  readonly assetId: string;
  readonly assetName: string;
  readonly componentName: string;
  readonly componentVersion: string;
  readonly vulnerabilityPublicId: string;
  readonly firstObservedAt: string;
};

export type RemediationQueueCalculationFields = {
  readonly riskPolicyId: string;
  readonly policyKey: string;
  readonly policyVersion: number;
  readonly policyDefinitionSha256: string;
  readonly calculatedAt: string;
  readonly calculationEngineVersion: string;
  readonly priorityText: string;
  readonly priority: number;
  readonly priorityBand: 'P1' | 'P2' | 'P3' | 'P4';
  readonly escalationRecommended: boolean;
  readonly kevListed: boolean;
  readonly severityText: string;
  readonly severityPercent: number;
  readonly storedKevGenerationId: string | null;
  readonly lastObservedAt: string;
  readonly assetUpdatedAt: string;
};

export type RemediationQueueRawRow = RemediationQueueIdentity & {
  readonly section: RemediationQueueSection;
  readonly calculation: RemediationQueueCalculationFields | null;
  readonly humanReview: FindingPriorityReviewMarker;
};

export type RemediationQueueReadQuery = {
  readonly organizationId: string;
  readonly section: RemediationQueueSection;
  readonly referencePolicyDefinitionSha256: string;
  readonly referenceEngineVersion: string;
  readonly limit: number;
  readonly cursor: RemediationQueueCursor | null;
};

export type RemediationQueueReadResult =
  | {
      readonly kind: 'page';
      readonly asOf: string;
      readonly publishedPolicyId: string;
      readonly publishedPolicyKey: string;
      readonly publishedPolicyVersion: number;
      readonly publishedDefinition: unknown;
      readonly activeKevGenerationId: string | null;
      readonly counts: RemediationQueueCounts;
      readonly findingCount: number;
      readonly rows: readonly RemediationQueueRawRow[];
      readonly hasMore: boolean;
    }
  | { readonly kind: 'policy_absent' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'unavailable' };

export type RemediationQueuePersistencePort = {
  readonly findPublishedBuiltinPriorityPolicy: () => Promise<PriorityPolicyLookup>;
  readonly readRemediationQueue: (
    input: RemediationQueueReadQuery,
  ) => Promise<RemediationQueueReadResult>;
};
