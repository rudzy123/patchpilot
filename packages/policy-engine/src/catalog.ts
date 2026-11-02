/**
 * Closed catalog for the deterministic P1-P4 priority policy (ADR 0045).
 * Factor identifiers, tokens, states, bands, rules, explanation codes, and
 * override bounds are engine code. Numbers that a policy may vary live in the
 * versioned definition, not here.
 */

export const POLICY_ENGINE_VERSION = '@patchpilot/policy-engine@1' as const;
export const PRIORITY_ENGINE_CONTRACT = 'patchpilot.priority.p1p4/1' as const;
export const PRIORITY_POLICY_SCHEMA_VERSION = 2 as const;

export const FACTOR_IDS = [
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
export type FactorId = (typeof FACTOR_IDS)[number];

export const INFORMATIONAL_FACTOR_ID = 'advisory_withdrawn' as const;

export const FACTOR_INPUT_STATES = ['observed', 'unknown', 'unavailable'] as const;
export type FactorInputState = (typeof FACTOR_INPUT_STATES)[number];

export const FACTOR_STATUSES = [
  'decisive',
  'contributing',
  'non_contributing',
  'informational',
] as const;
export type FactorStatus = (typeof FACTOR_STATUSES)[number];

export const PRIORITY_BANDS = ['P1', 'P2', 'P3', 'P4'] as const;
export type PriorityBand = (typeof PRIORITY_BANDS)[number];

export const SEVERITY_RATINGS = ['critical', 'high', 'medium', 'low', 'none'] as const;
export type SeverityRating = (typeof SEVERITY_RATINGS)[number];
export const SEVERITY_UNKNOWN_TOKENS = ['unrated'] as const;
export const SEVERITY_MAX_VALUES = 16;

export const KEV_LISTED_TOKENS = [
  'listed_catalog_current',
  'listed_catalog_stale',
  'listed_catalog_disabled_with_history',
] as const;
export type KevListedToken = (typeof KEV_LISTED_TOKENS)[number];
export const KEV_OBSERVED_TOKENS = [...KEV_LISTED_TOKENS, 'not_listed_catalog_current'] as const;
export type KevObservedToken = (typeof KEV_OBSERVED_TOKENS)[number];
export const KEV_UNKNOWN_TOKENS = [
  'absent_catalog_stale',
  'absent_catalog_disabled_with_history',
] as const;
export type KevUnknownToken = (typeof KEV_UNKNOWN_TOKENS)[number];
export const KEV_UNAVAILABLE_REASONS = ['no_canonical_cve', 'no_active_generation'] as const;
export type KevUnavailableReason = (typeof KEV_UNAVAILABLE_REASONS)[number];

export const ENVIRONMENT_SENSITIVITY_TOKENS = ['production', 'non_production'] as const;
export type EnvironmentSensitivityToken = (typeof ENVIRONMENT_SENSITIVITY_TOKENS)[number];

export const INTERNET_EXPOSURE_TOKENS = ['internet_facing', 'internal'] as const;
export type InternetExposureToken = (typeof INTERNET_EXPOSURE_TOKENS)[number];
export const INTERNET_EXPOSURE_UNKNOWN_TOKENS = ['unknown'] as const;

export const BUSINESS_CRITICALITY_TOKENS = ['critical', 'high', 'medium', 'low'] as const;
export type BusinessCriticalityToken = (typeof BUSINESS_CRITICALITY_TOKENS)[number];
export const BUSINESS_CRITICALITY_UNKNOWN_TOKENS = ['unspecified'] as const;

export const ASSET_DATA_CLASSIFICATION_TOKENS = [
  'restricted',
  'confidential',
  'internal',
  'public',
] as const;
export type AssetDataClassificationToken = (typeof ASSET_DATA_CLASSIFICATION_TOKENS)[number];
export const ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS = ['unspecified'] as const;

export const DIRECT_DEPENDENCY_TOKENS = ['direct', 'transitive'] as const;
export type DirectDependencyToken = (typeof DIRECT_DEPENDENCY_TOKENS)[number];

export const FIX_AVAILABLE_TOKENS = ['available', 'not_available'] as const;
export type FixAvailableToken = (typeof FIX_AVAILABLE_TOKENS)[number];
export const FIX_AVAILABLE_UNKNOWN_TOKENS = ['undetermined'] as const;

export const ADVISORY_WITHDRAWN_TOKENS = ['withdrawn', 'not_withdrawn'] as const;
export type AdvisoryWithdrawnToken = (typeof ADVISORY_WITHDRAWN_TOKENS)[number];

export const FINDING_AGE_DAYS_MAX = 36500;
export const FINDING_AGE_BUCKETS_MAX = 16;

/**
 * Observed tokens for every factor normalized by a token-to-percent map, in
 * the order the definition's percents must be non-increasing. The last token
 * is the favorable extreme and must normalize to 0.
 */
export const NORMALIZED_TOKEN_FACTORS = {
  source_severity: SEVERITY_RATINGS,
  kev_listed: KEV_OBSERVED_TOKENS,
  environment_sensitivity: ENVIRONMENT_SENSITIVITY_TOKENS,
  internet_exposure: INTERNET_EXPOSURE_TOKENS,
  business_criticality: BUSINESS_CRITICALITY_TOKENS,
  asset_data_classification: ASSET_DATA_CLASSIFICATION_TOKENS,
  direct_dependency: DIRECT_DEPENDENCY_TOKENS,
  fix_available: FIX_AVAILABLE_TOKENS,
} as const;
export type NormalizedTokenFactorId = keyof typeof NORMALIZED_TOKEN_FACTORS;

export const NORMALIZED_TOKEN_FACTOR_IDS = [
  'source_severity',
  'kev_listed',
  'environment_sensitivity',
  'internet_exposure',
  'business_criticality',
  'asset_data_classification',
  'direct_dependency',
  'fix_available',
] as const satisfies readonly NormalizedTokenFactorId[];

export const NORMALIZATION_KEYS = [...NORMALIZED_TOKEN_FACTOR_IDS, 'finding_age_days'] as const;

export const KEV_ESCALATION_RULE = 'listed_and_production_or_internet_facing' as const;

export const RULE_IDS = ['kev_minimum_band', 'kev_escalation'] as const;
export type RuleId = (typeof RULE_IDS)[number];

export const ESCALATION_REASONS = ['kev_production', 'kev_internet_facing'] as const;
export type EscalationReason = (typeof ESCALATION_REASONS)[number];

export const POLICY_KEY_MAX_LENGTH = 128;
export const FACTOR_DESCRIPTION_MAX_LENGTH = 256;
export const PRIORITY_MAX = 100;
export const WEIGHT_SUM = 100;
export const PERCENT_MAX = 100;
export const DUE_DATE_RECOMMENDATION_DAYS_MIN = 1;
export const DUE_DATE_RECOMMENDATION_DAYS_MAX = 3650;

/** Organization overrides may vary weights only, inside these inclusive bounds. */
export const OVERRIDE_WEIGHT_BOUNDS: { readonly [K in FactorId]: readonly [number, number] } = {
  source_severity: [30, 50],
  kev_listed: [10, 30],
  environment_sensitivity: [0, 20],
  internet_exposure: [0, 20],
  business_criticality: [0, 15],
  asset_data_classification: [0, 10],
  direct_dependency: [0, 5],
  fix_available: [0, 5],
  finding_age_days: [0, 5],
  advisory_withdrawn: [0, 0],
};

export const FACTOR_EXPLANATION_CODES = [
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
export type FactorExplanationCode = (typeof FACTOR_EXPLANATION_CODES)[number];

export const RULE_EXPLANATION_CODES = [
  'kev_minimum_band_raised',
  'kev_minimum_band_already_met',
  'kev_minimum_band_not_triggered',
  'kev_escalation_recommended',
  'kev_escalation_context_not_observed',
  'kev_escalation_not_triggered',
] as const;
export type RuleExplanationCode = (typeof RULE_EXPLANATION_CODES)[number];

export const EXPLANATION_CODES = [...FACTOR_EXPLANATION_CODES, ...RULE_EXPLANATION_CODES] as const;
export type ExplanationCode = (typeof EXPLANATION_CODES)[number];

const MISSING_EVIDENCE = 'It contributes nothing to priority and does not indicate low risk.';
const KEV_ENRICHMENT = 'This is catalog enrichment, not proof of exploitation or affectedness.';

/**
 * Static human-readable text for every explanation code. Only codes are
 * persisted. Text has no interpolation and never carries tenant data, and it
 * avoids numbers the versioned definition controls.
 */
export const EXPLANATION_TEXT: Readonly<Record<ExplanationCode, string>> = Object.freeze({
  severity_critical: 'The highest source severity rating is critical.',
  severity_high: 'The highest source severity rating is high.',
  severity_medium: 'The highest source severity rating is medium.',
  severity_low: 'The highest source severity rating is low.',
  severity_none: 'The highest source severity rating is none.',
  severity_unrated: `Source severity records exist, but none maps to a rating. ${MISSING_EVIDENCE}`,
  severity_unavailable: `No source severity record is available. ${MISSING_EVIDENCE}`,
  kev_listed_catalog_current: `Listed in the current CISA KEV catalog snapshot. ${KEV_ENRICHMENT}`,
  kev_listed_catalog_stale: `Listed in a stale CISA KEV catalog snapshot. The listing counts until a later accepted snapshot removes it. ${KEV_ENRICHMENT}`,
  kev_listed_catalog_disabled_with_history: `Listed in the last retained CISA KEV catalog snapshot while synchronization is disabled. The listing counts until a later accepted snapshot removes it. ${KEV_ENRICHMENT}`,
  kev_not_listed_catalog_current: 'Not listed in the current CISA KEV catalog snapshot.',
  kev_absent_catalog_stale: `Not listed in a stale CISA KEV catalog snapshot, so absence is unconfirmed. ${MISSING_EVIDENCE}`,
  kev_absent_catalog_disabled_with_history: `Not listed in the last retained CISA KEV catalog snapshot while synchronization is disabled, so absence is unconfirmed. ${MISSING_EVIDENCE}`,
  kev_unavailable_no_canonical_cve: `No canonical CVE is linked, so CISA KEV membership cannot be determined. ${MISSING_EVIDENCE}`,
  kev_unavailable_no_active_generation: `No active CISA KEV catalog snapshot exists, so membership cannot be determined. ${MISSING_EVIDENCE}`,
  environment_production: 'The asset environment is production.',
  environment_non_production: 'The asset environment is non-production.',
  environment_unavailable: `The asset has no environment. ${MISSING_EVIDENCE}`,
  exposure_internet_facing: 'The asset is recorded as internet facing.',
  exposure_internal: 'The asset is recorded as internal.',
  exposure_unknown: `The asset internet exposure is recorded as unknown. ${MISSING_EVIDENCE}`,
  exposure_unavailable: `No asset internet exposure evidence is available. ${MISSING_EVIDENCE}`,
  criticality_critical: 'The asset business criticality is critical.',
  criticality_high: 'The asset business criticality is high.',
  criticality_medium: 'The asset business criticality is medium.',
  criticality_low: 'The asset business criticality is low.',
  criticality_unspecified: `The asset business criticality is unspecified. ${MISSING_EVIDENCE}`,
  criticality_unavailable: `No asset business criticality evidence is available. ${MISSING_EVIDENCE}`,
  data_restricted: 'The asset data classification is restricted.',
  data_confidential: 'The asset data classification is confidential.',
  data_internal: 'The asset data classification is internal.',
  data_public: 'The asset data classification is public.',
  data_unspecified: `The asset data classification is unspecified. ${MISSING_EVIDENCE}`,
  data_unavailable: `No asset data classification evidence is available. ${MISSING_EVIDENCE}`,
  dependency_direct: 'The component occurrence is a direct dependency.',
  dependency_transitive: 'The component occurrence is a transitive dependency.',
  dependency_unavailable: `Whether the component occurrence is a direct dependency is not recorded. ${MISSING_EVIDENCE}`,
  fix_available: 'The matched advisory range closes with a fixed version.',
  fix_not_available:
    'The matched advisory range is open ended, so no fixed version is recorded. This does not reduce priority.',
  fix_undetermined: `The matched advisory range closes only with a last affected version, so fix availability is undetermined. ${MISSING_EVIDENCE}`,
  fix_unavailable: `No fix availability evidence is available. ${MISSING_EVIDENCE}`,
  age_under_30_days: 'First observed fewer than 30 days ago.',
  age_30_to_89_days: 'First observed between 30 and 89 days ago.',
  age_90_days_or_more: 'First observed 90 or more days ago.',
  age_unavailable: `No first observation time is available. ${MISSING_EVIDENCE}`,
  advisory_withdrawn_review_required:
    'The advisory is withdrawn. Review is required. Withdrawal does not change priority.',
  advisory_not_withdrawn: 'The advisory is not withdrawn.',
  advisory_withdrawal_unavailable: 'No advisory withdrawal status is available.',
  kev_minimum_band_raised: `CISA KEV listing raised priority to the minimum of the policy floor band. ${KEV_ENRICHMENT}`,
  kev_minimum_band_already_met: `CISA KEV listed, and the weighted score already meets the policy floor band. ${KEV_ENRICHMENT}`,
  kev_minimum_band_not_triggered: 'Not CISA KEV listed, so the minimum band rule does not apply.',
  kev_escalation_recommended:
    'Escalation is recommended because the vulnerability is CISA KEV listed with observed production or internet-facing context. Escalation does not change priority, band, or due date.',
  kev_escalation_context_not_observed:
    'CISA KEV listed, but neither production nor internet-facing context is observed, so escalation is not recommended.',
  kev_escalation_not_triggered: 'Not CISA KEV listed, so escalation is not recommended.',
} satisfies Record<ExplanationCode, string>);

/** Age explanation codes describe the fact, independent of the definition's buckets. */
export const AGE_EXPLANATION_THRESHOLDS = { under30: 30, under90: 90 } as const;

export function factorOrdinal(factorId: FactorId): number {
  return FACTOR_IDS.indexOf(factorId) + 1;
}

export function isKevListedToken(value: KevObservedToken): value is KevListedToken {
  return (KEV_LISTED_TOKENS as readonly string[]).includes(value);
}
