/**
 * Version 2 priority documents stay distinct from the version 1 placeholders.
 * The evaluation document has no sources. Catalog provenance omits KEV prose.
 */

import { describe, expect, it } from 'vitest';

import {
  JSON_SCHEMA_VERSION_V1,
  type RiskCalculationResultJson,
  type RiskPolicyDefinitionJson,
} from '../json-documents.js';
import {
  assetDataClassifications,
  businessCriticalities,
  environmentSensitivityClasses,
  internetExposures,
} from '../lifecycle.js';
import { activeKevCatalogFreshnessValues } from '../vulnerability/kev-membership.js';
import {
  PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS,
  PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS,
  PRIORITY_BUSINESS_CRITICALITY_TOKENS,
  PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_ENGINE_CONTRACT,
  PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS,
  PRIORITY_FACTOR_IDS,
  PRIORITY_FINDING_AGE_DAYS_MAX,
  PRIORITY_INTERNET_EXPOSURE_TOKENS,
  PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS,
  PRIORITY_KEV_CATALOG_FRESHNESS,
  PRIORITY_KEV_LISTED_TOKENS,
  PRIORITY_KEV_OBSERVED_TOKENS,
  PRIORITY_SEVERITY_MAX_VALUES,
  type PriorityFactorId,
} from './catalog.js';
import {
  RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
  RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
  type PriorityEvaluationDocument,
  type PriorityFactorRow,
  type RiskCalculationFactorsV2Json,
  type RiskCalculationKevSourceV2,
  type RiskCalculationResultV1Json,
  type RiskPolicyDefinitionV2Json,
} from '../json-documents.js';
import type { PriorityFactInput } from './facts.js';

type V1PolicySchema = RiskPolicyDefinitionJson['schemaVersion'];
const v1PolicySchemaIsExactlyOne: [V1PolicySchema] extends [1]
  ? [1] extends [V1PolicySchema]
    ? true
    : never
  : never = true;

const policySchemaIsV2: RiskPolicyDefinitionV2Json['schemaVersion'] extends 2 ? true : never = true;
const factorsSchemaIsV2: RiskCalculationFactorsV2Json['schemaVersion'] extends 2 ? true : never =
  true;
const escalationReasonsOnFactors: 'escalationReasons' extends keyof RiskCalculationFactorsV2Json
  ? true
  : never = true;
const escalationReasonsOffResult: 'escalationReasons' extends keyof RiskCalculationResultV1Json
  ? never
  : true = true;
const resultSchemaIsV1: RiskCalculationResultV1Json['schemaVersion'] extends 1 ? true : never =
  true;
const evaluationOmitsSources: 'sources' extends keyof PriorityEvaluationDocument ? never : true =
  true;
const factorRowOmitsNotes: 'notes' extends keyof PriorityFactorRow ? never : true = true;

type CatalogKevKeys = keyof Extract<RiskCalculationKevSourceV2, { readonly state: 'catalog' }>;
const kevSourceOmitsProse: Extract<
  CatalogKevKeys,
  | 'dueDate'
  | 'requiredAction'
  | 'knownRansomwareCampaignUse'
  | 'notes'
  | 'shortDescription'
  | 'vulnerabilityName'
> extends never
  ? true
  : never = true;

type MissingFactKeys = Exclude<PriorityFactorId, keyof PriorityFactInput>;
type ExtraFactKeys = Exclude<keyof PriorityFactInput, PriorityFactorId>;
const factKeysMatchFactors: [MissingFactKeys, ExtraFactKeys] extends [never, never] ? true : never =
  true;

function asHistoricalResult(result: RiskCalculationResultV1Json): RiskCalculationResultJson {
  return result;
}

describe('priority document contracts', () => {
  it('keeps policy and factors at schema version 2 and the result at version 1', () => {
    expect(RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2).toBe(2);
    expect(RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2).toBe(2);
    expect(JSON_SCHEMA_VERSION_V1).toBe(1);
    expect(PRIORITY_CALCULATION_ENGINE_VERSION).toBe('@patchpilot/policy-engine@1');
    expect(PRIORITY_ENGINE_CONTRACT).toBe('patchpilot.priority.p1p4/1');
    expect(PRIORITY_FINDING_AGE_DAYS_MAX).toBe(36500);
    expect(PRIORITY_SEVERITY_MAX_VALUES).toBe(16);
    expect(v1PolicySchemaIsExactlyOne).toBe(true);
    expect(policySchemaIsV2).toBe(true);
    expect(factorsSchemaIsV2).toBe(true);
    expect(escalationReasonsOnFactors).toBe(true);
    expect(escalationReasonsOffResult).toBe(true);
    expect(resultSchemaIsV1).toBe(true);
    expect(evaluationOmitsSources).toBe(true);
    expect(factorRowOmitsNotes).toBe(true);
    expect(kevSourceOmitsProse).toBe(true);
    expect(factKeysMatchFactors).toBe(true);

    const placeholder = {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      policyKey: 'patchpilot.builtin.v0',
      factorCatalog: [],
      weights: {},
    } satisfies RiskPolicyDefinitionJson;
    expect(placeholder.schemaVersion).toBe(1);

    const result = {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      priority: 0,
      priorityBand: 'P4',
      dueDateRecommendationDays: 180,
      escalationRecommendation: false,
    } as const satisfies RiskCalculationResultV1Json;
    expect(asHistoricalResult(result)).toMatchObject({
      schemaVersion: 1,
      priorityBand: 'P4',
      escalationRecommendation: false,
    });
  });

  it('keeps not-listed KEV beside the listed tokens', () => {
    expect([...PRIORITY_KEV_OBSERVED_TOKENS]).toEqual([
      ...PRIORITY_KEV_LISTED_TOKENS,
      'not_listed_catalog_current',
    ]);
  });

  it('sends the ten ADR 0045 factor keys in catalog order', () => {
    expect([...PRIORITY_FACTOR_IDS]).toEqual([
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
    ]);
  });

  it('maps stored asset enums onto observed tokens and keeps unknown defaults unknown', () => {
    expect([...PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS]).toEqual([
      ...environmentSensitivityClasses,
    ]);
    expect([...PRIORITY_INTERNET_EXPOSURE_TOKENS]).toEqual(
      internetExposures.filter((value) => value !== 'unknown'),
    );
    expect([...PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS]).toEqual(['unknown']);
    expect([...PRIORITY_BUSINESS_CRITICALITY_TOKENS]).toEqual(
      businessCriticalities.filter((value) => value !== 'unspecified'),
    );
    expect([...PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS]).toEqual(['unspecified']);
    expect([...PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS]).toEqual(
      assetDataClassifications.filter((value) => value !== 'unspecified'),
    );
    expect([...PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS]).toEqual(['unspecified']);
    expect([...PRIORITY_KEV_CATALOG_FRESHNESS]).toEqual([...activeKevCatalogFreshnessValues]);
  });
});
