/**
 * JSON documents stored in PostgreSQL. Each document includes `schemaVersion`.
 * Application code must validate against the matching version before trusting fields.
 * These shapes are persistence-neutral; they are not Prisma types.
 * Priority policy definition v2, calculation factors v2, and the precise
 * calculation result v1 are defined in this module. The version 1 placeholders
 * stay in place. Numerical weights, band thresholds, and normalization stay
 * out of this module.
 */

import type {
  PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS,
  PRIORITY_BANDS,
  PRIORITY_BUSINESS_CRITICALITY_TOKENS,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_DIRECT_DEPENDENCY_TOKENS,
  PRIORITY_ENGINE_CONTRACT,
  PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS,
  PRIORITY_FIX_AVAILABLE_TOKENS,
  PRIORITY_INTERNET_EXPOSURE_TOKENS,
  PRIORITY_KEV_ESCALATION_RULE,
  PRIORITY_KEV_OBSERVED_TOKENS,
  PRIORITY_SEVERITY_RATINGS,
  PriorityBand,
  PriorityEscalationReason,
  PriorityFactorExplanationCode,
  PriorityFactorId,
  PriorityFactorInputState,
  PriorityFactorStatus,
  PriorityKevCatalogFreshness,
  PriorityKevUnavailableReason,
  PriorityRuleExplanationCode,
  PriorityRuleId,
} from './risk/catalog.js';

export const JSON_SCHEMA_VERSION_V1 = 1;

export type VersionedJsonDocument = {
  schemaVersion: number;
};

export type RiskPolicyDefinitionJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  policyKey: string;
  factorCatalog: ReadonlyArray<{
    factorId: string;
    description: string;
  }>;
  weights: Readonly<Record<string, number>>;
};

export type RiskCalculationFactorsJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  factors: ReadonlyArray<{
    factorId: string;
    inputKind: 'observed' | 'unavailable';
    rawValue: string | number | boolean | null;
    contribution: number;
    notes: string;
  }>;
};

export type RiskCalculationResultJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  priority: number;
  priorityBand: string;
  dueDateRecommendationDays: number;
  escalationRecommendation: boolean | string;
};

export type AuditPayloadJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type OutboxPayloadJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  ids: Readonly<Record<string, string>>;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type EvidenceMetadataJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type VulnerabilityNormalizedJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  summary: string | null;
  severity: string | null;
  affectedPackages: ReadonlyArray<{
    ecosystem: string;
    namespace: string | null;
    name: string;
    versionRange: string | null;
  }>;
};

export type FindingObservationEvidenceJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type IdempotencyResponseJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
};

export type IntegrationConfigJson = VersionedJsonDocument & {
  schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  refreshIntervalSeconds: number | null;
  endpointAllowlist: ReadonlyArray<string>;
};

export const RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2 = 2 as const;

export const RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2 = 2 as const;

export type PriorityAgeBucket = {
  readonly minDays: number;
  readonly percent: number;
};

export type PriorityFactorCatalogEntry = {
  readonly factorId: PriorityFactorId;
  readonly description: string;
};

export type PriorityPolicyWeights = { readonly [K in PriorityFactorId]: number };

export type PriorityPolicyNormalization = {
  readonly source_severity: { readonly [T in (typeof PRIORITY_SEVERITY_RATINGS)[number]]: number };
  readonly kev_listed: { readonly [T in (typeof PRIORITY_KEV_OBSERVED_TOKENS)[number]]: number };
  readonly environment_sensitivity: {
    readonly [T in (typeof PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS)[number]]: number;
  };
  readonly internet_exposure: {
    readonly [T in (typeof PRIORITY_INTERNET_EXPOSURE_TOKENS)[number]]: number;
  };
  readonly business_criticality: {
    readonly [T in (typeof PRIORITY_BUSINESS_CRITICALITY_TOKENS)[number]]: number;
  };
  readonly asset_data_classification: {
    readonly [T in (typeof PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS)[number]]: number;
  };
  readonly direct_dependency: {
    readonly [T in (typeof PRIORITY_DIRECT_DEPENDENCY_TOKENS)[number]]: number;
  };
  readonly fix_available: {
    readonly [T in (typeof PRIORITY_FIX_AVAILABLE_TOKENS)[number]]: number;
  };
  readonly finding_age_days: readonly PriorityAgeBucket[];
};

export type PriorityPolicyBand = {
  readonly band: PriorityBand;
  readonly minPriority: number;
  readonly dueDateRecommendationDays: number;
};

export type PriorityPolicyRules = {
  readonly kevMinimumBand: PriorityBand;
  readonly kevEscalation: typeof PRIORITY_KEV_ESCALATION_RULE;
};

/**
 * Policy definition document v2. It carries the version 1 keys `policyKey`,
 * `factorCatalog`, and `weights`, plus the engine contract, normalization,
 * bands, and rules. The policy version stays a column, not a field.
 * `RiskPolicyDefinitionJson` remains the version 1 placeholder shape.
 * `schemaVersion` 2 is not assignable to that placeholder.
 */
export type RiskPolicyDefinitionV2Json = {
  readonly schemaVersion: typeof RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2;
  readonly policyKey: string;
  readonly engineContract: typeof PRIORITY_ENGINE_CONTRACT;
  readonly factorCatalog: readonly PriorityFactorCatalogEntry[];
  readonly weights: PriorityPolicyWeights;
  readonly normalization: PriorityPolicyNormalization;
  readonly bands: readonly PriorityPolicyBand[];
  readonly rules: PriorityPolicyRules;
};

export type PriorityFactorRow = {
  readonly factorId: PriorityFactorId;
  readonly ordinal: number;
  readonly inputState: PriorityFactorInputState;
  readonly observedValue: string | number | null;
  readonly normalizedPercent: number;
  readonly weight: number;
  readonly contributionCenti: number;
  readonly status: PriorityFactorStatus;
  readonly explanationCode: PriorityFactorExplanationCode;
};

export type PriorityRuleRow = {
  readonly ruleId: PriorityRuleId;
  readonly triggered: boolean;
  readonly upliftCenti: number;
  readonly explanationCode: PriorityRuleExplanationCode;
};

export type PriorityEvidenceSummary = {
  readonly observed: number;
  readonly unknown: number;
  readonly unavailable: number;
};

/**
 * Engine evaluation document. It has no `schemaVersion` and no `sources`.
 * Persistence copies rows and `escalation.reasons` into
 * `RiskCalculationFactorsV2Json` and the four result fields into
 * `RiskCalculationResultV1Json`.
 */
export type PriorityEvaluationDocument = {
  readonly engineVersion: typeof PRIORITY_CALCULATION_ENGINE_VERSION;
  readonly policyKey: string;
  readonly weightedScoreCenti: number;
  readonly upliftCenti: number;
  readonly priority: number;
  readonly priorityBand: (typeof PRIORITY_BANDS)[number];
  readonly dueDateRecommendationDays: number;
  readonly escalation: {
    readonly recommended: boolean;
    readonly reasons: readonly PriorityEscalationReason[];
  };
  readonly factors: readonly PriorityFactorRow[];
  readonly rules: readonly PriorityRuleRow[];
  readonly evidenceSummary: PriorityEvidenceSummary;
};

/**
 * Catalog identity stored beside a calculation. Due dates, required action,
 * and ransomware text are not fields. `generationId` and `snapshotSha256` are
 * null when the membership read cannot supply them. `catalogReleasedAt` is a
 * UTC timestamp serialized as a string.
 */
export type RiskCalculationKevSourceV2 =
  | {
      readonly state: 'unavailable';
      readonly reason: PriorityKevUnavailableReason;
    }
  | {
      readonly state: 'catalog';
      readonly catalogVersion: string;
      readonly catalogReleasedAt: string;
      readonly freshness: PriorityKevCatalogFreshness;
      readonly generationId: string | null;
      readonly snapshotSha256: string | null;
    };

export type RiskCalculationFactorSourcesV2 = {
  readonly evidenceIds: readonly string[];
  readonly advisoryRevisionIds: readonly string[];
  readonly componentOccurrenceIds: readonly string[];
  readonly intelligenceSourceRecordIds: readonly string[];
  readonly kev: RiskCalculationKevSourceV2;
};

/**
 * Factors document v2. `escalationReasons` is the engine's closed list
 * (`kev_production`, `kev_internet_facing`) in that order, or an empty array.
 * It is not a second copy of the `kev_escalation` rule. Result v1 keeps only
 * the boolean `escalationRecommendation`.
 */
export type RiskCalculationFactorsV2Json = {
  readonly schemaVersion: typeof RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2;
  readonly factors: readonly PriorityFactorRow[];
  readonly rules: readonly PriorityRuleRow[];
  readonly escalationReasons: readonly PriorityEscalationReason[];
  readonly evidenceSummary: PriorityEvidenceSummary;
  readonly weightedScoreCenti: number;
  readonly upliftCenti: number;
  readonly sources: RiskCalculationFactorSourcesV2;
};

/**
 * Calculation result document v1. Escalation reasons stay in the factors
 * document. This is the precise shape written from an evaluation. The
 * historical `RiskCalculationResultJson` remains the wider placeholder.
 */
export type RiskCalculationResultV1Json = {
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  readonly priority: number;
  readonly priorityBand: PriorityBand;
  readonly dueDateRecommendationDays: number;
  readonly escalationRecommendation: boolean;
};
