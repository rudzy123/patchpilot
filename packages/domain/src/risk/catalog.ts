/**
 * Closed vocabulary for ADR 0045 priority documents.
 * These literals name the same tokens as the uncomposed policy engine. This
 * module does not import that package. The engine remains the evaluator.
 * Weights, override bounds, normalization percents, band thresholds, and
 * due-day tables are not defined here.
 */

export const PRIORITY_CALCULATION_ENGINE_VERSION = '@patchpilot/policy-engine@1' as const;

export const PRIORITY_ENGINE_CONTRACT = 'patchpilot.priority.p1p4/1' as const;

export const PRIORITY_FACTOR_IDS = [
  'source_severity',
  'kev_listed',
  'environment_sensitivity',
  'internet_exposure',
  'business_criticality',
  'asset_data_classification',
  'direct_dependency',
  'fix_available',
  'finding_age_days',
  'advisory_withdrawn',
] as const;
export type PriorityFactorId = (typeof PRIORITY_FACTOR_IDS)[number];

export const PRIORITY_FACTOR_INPUT_STATES = ['observed', 'unknown', 'unavailable'] as const;
export type PriorityFactorInputState = (typeof PRIORITY_FACTOR_INPUT_STATES)[number];

export const PRIORITY_FACTOR_STATUSES = [
  'decisive',
  'contributing',
  'non_contributing',
  'informational',
] as const;
export type PriorityFactorStatus = (typeof PRIORITY_FACTOR_STATUSES)[number];

export const PRIORITY_BANDS = ['P1', 'P2', 'P3', 'P4'] as const;
export type PriorityBand = (typeof PRIORITY_BANDS)[number];

export const PRIORITY_SEVERITY_RATINGS = ['critical', 'high', 'medium', 'low', 'none'] as const;
export type PrioritySeverityRating = (typeof PRIORITY_SEVERITY_RATINGS)[number];
export const PRIORITY_SEVERITY_UNKNOWN_TOKENS = ['unrated'] as const;
export type PrioritySeverityUnknownToken = (typeof PRIORITY_SEVERITY_UNKNOWN_TOKENS)[number];
export const PRIORITY_SEVERITY_MAX_VALUES = 16;

export const PRIORITY_KEV_LISTED_TOKENS = [
  'listed_catalog_current',
  'listed_catalog_stale',
  'listed_catalog_disabled_with_history',
] as const;
export type PriorityKevListedToken = (typeof PRIORITY_KEV_LISTED_TOKENS)[number];

export const PRIORITY_KEV_OBSERVED_TOKENS = [
  'listed_catalog_current',
  'listed_catalog_stale',
  'listed_catalog_disabled_with_history',
  'not_listed_catalog_current',
] as const;
export type PriorityKevObservedToken = (typeof PRIORITY_KEV_OBSERVED_TOKENS)[number];

export const PRIORITY_KEV_UNKNOWN_TOKENS = [
  'absent_catalog_stale',
  'absent_catalog_disabled_with_history',
] as const;
export type PriorityKevUnknownToken = (typeof PRIORITY_KEV_UNKNOWN_TOKENS)[number];

export const PRIORITY_KEV_UNAVAILABLE_REASONS = [
  'no_canonical_cve',
  'no_active_generation',
] as const;
export type PriorityKevUnavailableReason = (typeof PRIORITY_KEV_UNAVAILABLE_REASONS)[number];

export const PRIORITY_KEV_CATALOG_FRESHNESS = [
  'current',
  'stale',
  'disabled_with_history',
] as const;
export type PriorityKevCatalogFreshness = (typeof PRIORITY_KEV_CATALOG_FRESHNESS)[number];

export const PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS = ['production', 'non_production'] as const;
export type PriorityEnvironmentSensitivityToken =
  (typeof PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS)[number];

export const PRIORITY_INTERNET_EXPOSURE_TOKENS = ['internet_facing', 'internal'] as const;
export type PriorityInternetExposureToken = (typeof PRIORITY_INTERNET_EXPOSURE_TOKENS)[number];
export const PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS = ['unknown'] as const;
export type PriorityInternetExposureUnknownToken =
  (typeof PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS)[number];

export const PRIORITY_BUSINESS_CRITICALITY_TOKENS = ['critical', 'high', 'medium', 'low'] as const;
export type PriorityBusinessCriticalityToken =
  (typeof PRIORITY_BUSINESS_CRITICALITY_TOKENS)[number];
export const PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS = ['unspecified'] as const;
export type PriorityBusinessCriticalityUnknownToken =
  (typeof PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS)[number];

export const PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS = [
  'restricted',
  'confidential',
  'internal',
  'public',
] as const;
export type PriorityAssetDataClassificationToken =
  (typeof PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS)[number];
export const PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS = ['unspecified'] as const;
export type PriorityAssetDataClassificationUnknownToken =
  (typeof PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS)[number];

export const PRIORITY_DIRECT_DEPENDENCY_TOKENS = ['direct', 'transitive'] as const;
export type PriorityDirectDependencyToken = (typeof PRIORITY_DIRECT_DEPENDENCY_TOKENS)[number];

export const PRIORITY_FIX_AVAILABLE_TOKENS = ['available', 'not_available'] as const;
export type PriorityFixAvailableToken = (typeof PRIORITY_FIX_AVAILABLE_TOKENS)[number];
export const PRIORITY_FIX_AVAILABLE_UNKNOWN_TOKENS = ['undetermined'] as const;
export type PriorityFixAvailableUnknownToken =
  (typeof PRIORITY_FIX_AVAILABLE_UNKNOWN_TOKENS)[number];

export const PRIORITY_ADVISORY_WITHDRAWN_TOKENS = ['withdrawn', 'not_withdrawn'] as const;
export type PriorityAdvisoryWithdrawnToken = (typeof PRIORITY_ADVISORY_WITHDRAWN_TOKENS)[number];

export const PRIORITY_FINDING_AGE_DAYS_MAX = 36500;

export const PRIORITY_KEV_ESCALATION_RULE = 'listed_and_production_or_internet_facing' as const;

export const PRIORITY_RULE_IDS = ['kev_minimum_band', 'kev_escalation'] as const;
export type PriorityRuleId = (typeof PRIORITY_RULE_IDS)[number];

export const PRIORITY_ESCALATION_REASONS = ['kev_production', 'kev_internet_facing'] as const;
export type PriorityEscalationReason = (typeof PRIORITY_ESCALATION_REASONS)[number];

export const PRIORITY_FACTOR_EXPLANATION_CODES = [
  'severity_critical',
  'severity_high',
  'severity_medium',
  'severity_low',
  'severity_none',
  'severity_unrated',
  'severity_unavailable',
  'kev_listed_catalog_current',
  'kev_listed_catalog_stale',
  'kev_listed_catalog_disabled_with_history',
  'kev_not_listed_catalog_current',
  'kev_absent_catalog_stale',
  'kev_absent_catalog_disabled_with_history',
  'kev_unavailable_no_canonical_cve',
  'kev_unavailable_no_active_generation',
  'environment_production',
  'environment_non_production',
  'environment_unavailable',
  'exposure_internet_facing',
  'exposure_internal',
  'exposure_unknown',
  'exposure_unavailable',
  'criticality_critical',
  'criticality_high',
  'criticality_medium',
  'criticality_low',
  'criticality_unspecified',
  'criticality_unavailable',
  'data_restricted',
  'data_confidential',
  'data_internal',
  'data_public',
  'data_unspecified',
  'data_unavailable',
  'dependency_direct',
  'dependency_transitive',
  'dependency_unavailable',
  'fix_available',
  'fix_not_available',
  'fix_undetermined',
  'fix_unavailable',
  'age_under_30_days',
  'age_30_to_89_days',
  'age_90_days_or_more',
  'age_unavailable',
  'advisory_withdrawn_review_required',
  'advisory_not_withdrawn',
  'advisory_withdrawal_unavailable',
] as const;
export type PriorityFactorExplanationCode = (typeof PRIORITY_FACTOR_EXPLANATION_CODES)[number];

export const PRIORITY_RULE_EXPLANATION_CODES = [
  'kev_minimum_band_raised',
  'kev_minimum_band_already_met',
  'kev_minimum_band_not_triggered',
  'kev_escalation_recommended',
  'kev_escalation_context_not_observed',
  'kev_escalation_not_triggered',
] as const;
export type PriorityRuleExplanationCode = (typeof PRIORITY_RULE_EXPLANATION_CODES)[number];
