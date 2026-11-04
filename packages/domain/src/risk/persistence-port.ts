/**
 * Persistence port for uncomposed priority calculation.
 * The database adapter wraps the existing risk-calculation functions.
 * This module does not import that adapter.
 */

import type {
  RiskCalculationFactorsV2Json,
  RiskCalculationResultV1Json,
} from '../json-documents.js';
import type { RiskCalculationReason } from '../lifecycle.js';
import type { Result } from '../result.js';
import type { ActiveKevMembership } from '../vulnerability/kev-membership.js';
import type { FindingRiskSourceSnapshot } from './fact-assembly.js';
import { PRIORITY_CALCULATION_ENGINE_VERSION } from './catalog.js';

export const BUILTIN_PRIORITY_POLICY_KEY = 'patchpilot.builtin.v0' as const;

export const BUILTIN_PRIORITY_POLICY_VERSION = 2 as const;

export const PERSISTED_RISK_CALCULATION_REASONS = [
  'initial',
  'rescan',
  'intel_refresh',
  'policy_change',
  'asset_change',
] as const satisfies readonly RiskCalculationReason[];

export type PersistedRiskCalculationReason = (typeof PERSISTED_RISK_CALCULATION_REASONS)[number];

export type StoredRiskCalculation = {
  readonly id: string;
  readonly organizationId: string;
  readonly findingId: string;
  readonly riskPolicyId: string;
  readonly policyVersion: number;
  readonly policyDefinitionSha256: string;
  readonly calculatedAt: Date;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly calculationEngineVersion: typeof PRIORITY_CALCULATION_ENGINE_VERSION;
  readonly calculationReason: PersistedRiskCalculationReason;
  readonly inputFingerprint: string;
};

export type RiskCalculationScope = {
  readonly organizationId: string;
  readonly findingId: string;
};

/**
 * `asOf` is the loader timestamp. Callers pass that same value as
 * `calculatedAt` so finding age and the stored instant match.
 * `snapshot` is the loader's `FindingRiskSourceSnapshot`.
 */
export type RiskCalculationFactGraphRead =
  | {
      readonly kind: 'found';
      readonly asOf: Date;
      readonly snapshot: FindingRiskSourceSnapshot;
    }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'unavailable' };

export type StoredPriorityPolicyView = {
  readonly id: string;
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly version: number;
  readonly definition: Readonly<Record<string, unknown>>;
};

export type PriorityPolicyLookup =
  | { readonly kind: 'found'; readonly policy: StoredPriorityPolicyView }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'unavailable' };

export type CurrentRiskCalculationRead =
  | { readonly kind: 'found'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'unavailable' };

export type FindingPriorityPublishedBuiltin = {
  readonly id: string;
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly version: number;
  readonly definition: Readonly<Record<string, unknown>>;
};

/**
 * One stored calculation plus the identifiers the read compares.
 * `calculationEngineVersion` is the stored string. It is not limited to the
 * current engine constant, so a later engine can be reported as changed.
 */
export type FindingPriorityCalculationRecord = {
  readonly id: string;
  readonly riskPolicyId: string;
  readonly policyKey: string;
  readonly policyVersion: number;
  readonly policyDefinitionSha256: string;
  readonly calculatedAt: Date;
  readonly calculationEngineVersion: string;
  readonly calculationReason: PersistedRiskCalculationReason;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly lastObservedAt: Date;
  readonly assetUpdatedAt: Date;
  readonly activeKevGenerationId: string | null;
};

/**
 * One tenant-scoped read. `finding_absent` covers a missing Finding and a
 * Finding owned by another organization. `not_calculated` is only returned
 * after the Finding is in the actor's organization.
 */
export type FindingPriorityRead =
  | { readonly kind: 'finding_absent' }
  | {
      readonly kind: 'not_calculated';
      readonly findingId: string;
      readonly publishedBuiltin: FindingPriorityPublishedBuiltin | null;
    }
  | {
      readonly kind: 'calculated';
      readonly findingId: string;
      readonly publishedBuiltin: FindingPriorityPublishedBuiltin | null;
      readonly calculation: FindingPriorityCalculationRecord;
    }
  | { readonly kind: 'unavailable' };

export type PersistFindingRiskCalculationCommand = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly findingId: string;
  readonly riskPolicyId: string;
  readonly policyDefinitionSha256: string;
  readonly inputFingerprint: string;
  readonly calculationReason: PersistedRiskCalculationReason;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly correlationId: string;
  readonly calculatedAt: Date;
};

export type PersistFindingRiskCalculationResult =
  | { readonly kind: 'persisted'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'replay'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'immutable_conflict' }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'ineligible' }
  | { readonly kind: 'policy_unavailable' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'unavailable' };

export type PublishOrganizationPriorityOverrideCommand = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly definition: unknown;
  readonly policySchemaVersion: number;
  readonly policyKey: string;
};

export type PublishOrganizationPriorityOverridePersistenceResult =
  | {
      readonly kind: 'published';
      readonly policy: { readonly id: string; readonly version: number };
    }
  | { readonly kind: 'membership_not_found' }
  | { readonly kind: 'version_conflict' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'unavailable' };

export type LockedPriorityCalculationScope = RiskCalculationScope & {
  readonly actorUserId: string;
  readonly membershipId: string;
};

/**
 * Rows loaded after the Finding lock, before the engine runs.
 * `asOf` is null when the fact graph was not found. When the graph is found,
 * `asOf` is the database timestamp used both for finding age and `calculatedAt`.
 * `queryActiveKevMembership` reads KEV through the same database transaction.
 */
export type LockedPriorityCalculationContext = {
  readonly asOf: Date | null;
  readonly graph: RiskCalculationFactGraphRead;
  readonly builtin: PriorityPolicyLookup;
  readonly override: PriorityPolicyLookup;
  readonly current: CurrentRiskCalculationRead;
  readonly queryActiveKevMembership: (input: unknown) => Promise<Result<ActiveKevMembership>>;
};

export type LockedPriorityCalculationDecision<TStop> =
  | { readonly kind: 'persist'; readonly command: PersistFindingRiskCalculationCommand }
  | { readonly kind: 'stop'; readonly result: TStop };

export type LockedPriorityCalculationOutcome<TStop> =
  | { readonly kind: 'write'; readonly result: PersistFindingRiskCalculationResult }
  | { readonly kind: 'stop'; readonly result: TStop }
  | { readonly kind: 'unavailable' };

/**
 * Methods the calculation use cases call.
 * `executeLockedPriorityCalculation` is the one calculation transaction:
 * lock, load, invoke `work` (eligibility, KEV, policy, engine, fingerprint),
 * then insert and audit. The other read methods stay available for the
 * current-calculation query and for direct inserts of an already evaluated
 * document.
 */
export type RiskCalculationPersistencePort = {
  readonly loadPriorityCalculationFactGraph: (
    input: RiskCalculationScope,
  ) => Promise<RiskCalculationFactGraphRead>;
  readonly findPublishedBuiltinPriorityPolicy: () => Promise<PriorityPolicyLookup>;
  readonly findSelectedOrganizationPriorityOverride: (
    organizationId: string,
  ) => Promise<PriorityPolicyLookup>;
  readonly findCurrentRiskCalculation: (
    input: RiskCalculationScope,
  ) => Promise<CurrentRiskCalculationRead>;
  readonly readFindingPriority: (input: RiskCalculationScope) => Promise<FindingPriorityRead>;
  readonly persistRiskCalculation: (
    input: PersistFindingRiskCalculationCommand,
  ) => Promise<PersistFindingRiskCalculationResult>;
  readonly executeLockedPriorityCalculation: <TStop>(
    scope: LockedPriorityCalculationScope,
    work: (
      context: LockedPriorityCalculationContext,
    ) => Promise<LockedPriorityCalculationDecision<TStop>>,
  ) => Promise<LockedPriorityCalculationOutcome<TStop>>;
  readonly publishOrganizationPriorityOverride: (
    input: PublishOrganizationPriorityOverrideCommand,
  ) => Promise<PublishOrganizationPriorityOverridePersistenceResult>;
};
