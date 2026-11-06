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

/** ADR 0051. Three queue sections times the page cap. This is not the page size. */
export const REMEDIATION_QUEUE_EXPORT_CAP = 150;

export const REMEDIATION_QUEUE_EXPORT_FORMATS = ['json', 'csv'] as const;

export type RemediationQueueExportFormat = (typeof REMEDIATION_QUEUE_EXPORT_FORMATS)[number];

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

export type RemediationQueueExportQuery = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly correlationId: string;
  readonly format: RemediationQueueExportFormat;
  readonly referenceEngineVersion: string;
};

export type RemediationQueueExportRawSnapshot = {
  readonly asOf: string;
  readonly publishedDefinition: unknown;
  readonly referencePolicyDefinitionSha256: string;
  readonly referenceEngineVersion: string;
  readonly activeKevGenerationId: string | null;
  readonly counts: RemediationQueueCounts;
  readonly findingCount: number;
  readonly ranked: readonly RemediationQueueRawRow[];
  readonly incomparable: readonly RemediationQueueRawRow[];
  readonly not_calculated: readonly RemediationQueueRawRow[];
};

export type RemediationQueueExportAdmit =
  { readonly ok: true; readonly hash: string } | { readonly ok: false };

/**
 * Both hooks run inside the export transaction and must not perform I/O.
 * `complete` returns the exact response bytes, or null when the snapshot is malformed.
 */
export type RemediationQueueExportHooks = {
  readonly admit: (definition: unknown) => RemediationQueueExportAdmit;
  readonly complete: (snapshot: RemediationQueueExportRawSnapshot) => Uint8Array | null;
};

export type RemediationQueueExportPersistenceResult =
  | {
      readonly kind: 'exported';
      readonly body: Uint8Array;
      readonly sha256: string;
      readonly byteLength: number;
      readonly asOf: string;
      readonly counts: RemediationQueueCounts;
      readonly findingCount: number;
      readonly referencePolicyDefinitionSha256: string;
    }
  | { readonly kind: 'policy_absent' }
  | { readonly kind: 'policy_rejected' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'cap_exceeded' }
  | { readonly kind: 'correlation_conflict' }
  | { readonly kind: 'unavailable' };

export type RemediationQueueExportPersistencePort = {
  readonly exportRemediationQueue: (
    input: RemediationQueueExportQuery,
    hooks: RemediationQueueExportHooks,
  ) => Promise<RemediationQueueExportPersistenceResult>;
};
