/**
 * Frozen built-in priority policy (ADR 0045). `policyKey` is
 * `patchpilot.builtin.v0`. The policy version is not embedded; the persistence
 * session chooses it. Validated at load so evaluation and override checks
 * accept this object.
 */
import { PRIORITY_ENGINE_CONTRACT, PRIORITY_POLICY_SCHEMA_VERSION } from './catalog.js';
import { validatePolicyDefinition, type ValidatedPriorityPolicyDefinition } from './definition.js';

function loadBuiltinPriorityPolicyDefinition(): ValidatedPriorityPolicyDefinition {
  const result = validatePolicyDefinition({
    schemaVersion: PRIORITY_POLICY_SCHEMA_VERSION,
    policyKey: 'patchpilot.builtin.v0',
    engineContract: PRIORITY_ENGINE_CONTRACT,
    factorCatalog: [
      { factorId: 'source_severity', description: 'Highest source severity rating' },
      { factorId: 'kev_listed', description: 'CISA KEV catalog membership' },
      { factorId: 'environment_sensitivity', description: 'Environment sensitivity class' },
      { factorId: 'internet_exposure', description: 'Asset internet exposure' },
      { factorId: 'business_criticality', description: 'Asset business criticality' },
      { factorId: 'asset_data_classification', description: 'Asset data classification' },
      { factorId: 'direct_dependency', description: 'Direct or transitive dependency' },
      { factorId: 'fix_available', description: 'Fixed version availability' },
      { factorId: 'finding_age_days', description: 'Days since first observation' },
      { factorId: 'advisory_withdrawn', description: 'Advisory withdrawal flag' },
    ],
    weights: {
      source_severity: 40,
      kev_listed: 20,
      environment_sensitivity: 10,
      internet_exposure: 10,
      business_criticality: 8,
      asset_data_classification: 5,
      direct_dependency: 3,
      fix_available: 2,
      finding_age_days: 2,
      advisory_withdrawn: 0,
    },
    normalization: {
      source_severity: { critical: 100, high: 75, medium: 50, low: 25, none: 0 },
      kev_listed: {
        listed_catalog_current: 100,
        listed_catalog_stale: 100,
        listed_catalog_disabled_with_history: 100,
        not_listed_catalog_current: 0,
      },
      environment_sensitivity: { production: 100, non_production: 0 },
      internet_exposure: { internet_facing: 100, internal: 0 },
      business_criticality: { critical: 100, high: 50, medium: 25, low: 0 },
      asset_data_classification: { restricted: 100, confidential: 60, internal: 20, public: 0 },
      direct_dependency: { direct: 100, transitive: 0 },
      fix_available: { available: 100, not_available: 0 },
      finding_age_days: [
        { minDays: 0, percent: 0 },
        { minDays: 30, percent: 50 },
        { minDays: 90, percent: 100 },
      ],
    },
    bands: [
      { band: 'P1', minPriority: 80, dueDateRecommendationDays: 7 },
      { band: 'P2', minPriority: 60, dueDateRecommendationDays: 30 },
      { band: 'P3', minPriority: 40, dueDateRecommendationDays: 90 },
      { band: 'P4', minPriority: 0, dueDateRecommendationDays: 180 },
    ],
    rules: {
      kevMinimumBand: 'P2',
      kevEscalation: 'listed_and_production_or_internet_facing',
    },
  });
  if (!result.ok) {
    throw new Error('built-in priority policy definition failed validation');
  }
  return result.value;
}

export const BUILTIN_PRIORITY_POLICY_DEFINITION: ValidatedPriorityPolicyDefinition =
  loadBuiltinPriorityPolicyDefinition();
