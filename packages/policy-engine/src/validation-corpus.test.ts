/**
 * Locks V-0001 corpus revision 1 against the built-in definition.
 * Expected values come from docs/security/priority-weight-validation.md.
 * Do not change weights, thresholds, rules, or these expectations to force a match.
 */

import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  type PriorityBand,
  type PriorityEvaluation,
  type PriorityFactInput,
} from './index.js';

const DEFINITION_SHA256 = '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7';
const ENGINE_VERSION = '@patchpilot/policy-engine@1';

const unavailable = { state: 'unavailable' } as const;

function baseline(): PriorityFactInput {
  return {
    source_severity: unavailable,
    kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
    environment_sensitivity: { state: 'observed', value: 'production' },
    internet_exposure: { state: 'observed', value: 'internal' },
    business_criticality: { state: 'unknown', value: 'unspecified' },
    asset_data_classification: { state: 'unknown', value: 'unspecified' },
    direct_dependency: { state: 'observed', value: 'direct' },
    fix_available: unavailable,
    finding_age_days: { state: 'observed', value: 10 },
    advisory_withdrawn: { state: 'observed', value: 'not_withdrawn' },
  };
}

function allUnavailable(): PriorityFactInput {
  return {
    source_severity: unavailable,
    kev_listed: { state: 'unavailable', reason: 'no_active_generation' },
    environment_sensitivity: unavailable,
    internet_exposure: unavailable,
    business_criticality: unavailable,
    asset_data_classification: unavailable,
    direct_dependency: unavailable,
    fix_available: unavailable,
    finding_age_days: unavailable,
    advisory_withdrawn: unavailable,
  };
}

function withFacts(
  base: PriorityFactInput,
  changes: Partial<PriorityFactInput>,
): PriorityFactInput {
  return { ...base, ...changes };
}

const s01 = withFacts(baseline(), {
  kev_listed: { state: 'observed', value: 'listed_catalog_current' },
  internet_exposure: { state: 'observed', value: 'internet_facing' },
});
const s08 = allUnavailable();
const r01 = withFacts(s08, {
  source_severity: { state: 'observed', values: ['critical'] },
  kev_listed: { state: 'observed', value: 'listed_catalog_current' },
  environment_sensitivity: { state: 'observed', value: 'production' },
  internet_exposure: { state: 'observed', value: 'internet_facing' },
});

type CorpusExpectation = {
  readonly id: string;
  readonly facts: PriorityFactInput;
  readonly weighted: number;
  readonly uplift: number;
  readonly priority: number;
  readonly band: PriorityBand;
  readonly due: number;
  readonly reasons: readonly string[];
  readonly rules: readonly string[];
  readonly evidence: readonly [number, number, number];
  readonly fingerprint: string;
  readonly factors: Readonly<Record<string, string>>;
  readonly withdrawnStatus: 'informational' | null;
};

function row(
  id: string,
  facts: PriorityFactInput,
  weighted: number,
  uplift: number,
  priority: number,
  band: PriorityBand,
  due: number,
  reasons: readonly string[],
  rules: readonly string[],
  evidence: readonly [number, number, number],
  fingerprint: string,
  factors: Readonly<Record<string, string>>,
  withdrawnStatus: 'informational' | null = null,
): CorpusExpectation {
  return {
    id,
    facts,
    weighted,
    uplift,
    priority,
    band,
    due,
    reasons,
    rules,
    evidence,
    fingerprint,
    factors,
    withdrawnStatus,
  };
}

const CORPUS: readonly CorpusExpectation[] = [
  row(
    'S01',
    s01,
    4300,
    1700,
    60,
    'P2',
    30,
    ['kev_production', 'kev_internet_facing'],
    ['kev_minimum_band_raised', 'kev_escalation_recommended'],
    [6, 2, 2],
    'c8bf1d74505d0d1f759304b1ce26b69b7b0f02637ef3303b6622ad167e7e5a98',
    { kev_listed: 'kev_listed_catalog_current' },
  ),
  row(
    'S02',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
    }),
    2300,
    3700,
    60,
    'P2',
    30,
    [],
    ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
    [6, 2, 2],
    'cab54597a786c8c6b7deaf95de6d0918e475a3e42c4df1214f2509be82cb600e',
    { kev_listed: 'kev_listed_catalog_current' },
  ),
  row(
    'S03',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
    }),
    3300,
    2700,
    60,
    'P2',
    30,
    ['kev_production'],
    ['kev_minimum_band_raised', 'kev_escalation_recommended'],
    [6, 2, 2],
    '469c13e8e8bad2039f99c504dd720b2a1479ee8c447ad0080327483e789a251e',
    { kev_listed: 'kev_listed_catalog_current' },
  ),
  row(
    'S04',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      internet_exposure: { state: 'observed', value: 'internet_facing' },
      business_criticality: { state: 'observed', value: 'critical' },
      asset_data_classification: { state: 'observed', value: 'restricted' },
      finding_age_days: { state: 'observed', value: 90 },
    }),
    5800,
    200,
    60,
    'P2',
    30,
    ['kev_production', 'kev_internet_facing'],
    ['kev_minimum_band_raised', 'kev_escalation_recommended'],
    [8, 0, 2],
    '9705c5075e1ca315dddff885e632788bfea14eebe1b46d91c214e5a68cd089c8',
    { kev_listed: 'kev_listed_catalog_current' },
  ),
  row(
    'S05',
    withFacts(baseline(), {
      internet_exposure: { state: 'observed', value: 'internet_facing' },
      business_criticality: { state: 'observed', value: 'critical' },
      asset_data_classification: { state: 'observed', value: 'restricted' },
      finding_age_days: { state: 'observed', value: 90 },
    }),
    3800,
    0,
    38,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [8, 0, 2],
    'bee2675034af331bcf710faffae9e53a875ed9d2e5ecf7ef93c4f182acb41e81',
    {},
  ),
  row(
    'S06',
    withFacts(baseline(), {
      kev_listed: { state: 'unavailable', reason: 'no_canonical_cve' },
      internet_exposure: { state: 'observed', value: 'internet_facing' },
      business_criticality: { state: 'observed', value: 'critical' },
      asset_data_classification: { state: 'observed', value: 'restricted' },
      finding_age_days: { state: 'observed', value: 90 },
    }),
    3800,
    0,
    38,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [7, 0, 3],
    '92bd13356004b39c52af387253d232d851e00ca7c5c8de0989e54bb480d45845',
    { kev_listed: 'kev_unavailable_no_canonical_cve' },
  ),
  row(
    'S07',
    withFacts(baseline(), {
      environment_sensitivity: { state: 'observed', value: 'non_production' },
      business_criticality: { state: 'observed', value: 'low' },
      asset_data_classification: { state: 'observed', value: 'public' },
      direct_dependency: { state: 'observed', value: 'transitive' },
      finding_age_days: { state: 'observed', value: 0 },
    }),
    0,
    0,
    0,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [8, 0, 2],
    '6bce85d00a2840b36ab23870cadb76300fb6c45d7c06f9581daa19e276c4f24d',
    {},
  ),
  row(
    'S08',
    s08,
    0,
    0,
    0,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [0, 0, 10],
    '103bff93eb31793dd87b69f6bf315be9abb2e233c6c39f591c009a5c45382546',
    {
      kev_listed: 'kev_unavailable_no_active_generation',
      finding_age_days: 'age_unavailable',
    },
  ),
  row(
    'S09',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_stale' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
    }),
    2300,
    3700,
    60,
    'P2',
    30,
    [],
    ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
    [6, 2, 2],
    '1c5f6edaeb6dfac668a4a5b44d90522ae40770298136e8d51a43106a29fa9a09',
    { kev_listed: 'kev_listed_catalog_stale' },
  ),
  row(
    'S10',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_disabled_with_history' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
    }),
    2300,
    3700,
    60,
    'P2',
    30,
    [],
    ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
    [6, 2, 2],
    '9bf49dd24e38b19726e21ed06cc247d690e5d223344c21c4675885bb85a46223',
    { kev_listed: 'kev_listed_catalog_disabled_with_history' },
  ),
  row(
    'S11',
    withFacts(baseline(), {
      kev_listed: { state: 'unknown', value: 'absent_catalog_stale' },
      internet_exposure: { state: 'observed', value: 'internet_facing' },
    }),
    2300,
    0,
    23,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [5, 3, 2],
    '1df1f46d2d16c57a3c386a829fdd1a6b986ae0acaa7752bc96e890133b9aae68',
    { kev_listed: 'kev_absent_catalog_stale' },
  ),
  row(
    'S12',
    withFacts(s01, {
      advisory_withdrawn: { state: 'observed', value: 'withdrawn' },
    }),
    4300,
    1700,
    60,
    'P2',
    30,
    ['kev_production', 'kev_internet_facing'],
    ['kev_minimum_band_raised', 'kev_escalation_recommended'],
    [6, 2, 2],
    '45732d3fbf83222a4729177ca14711c94b9a0bad9e2100e0c000c1313281316c',
    {
      kev_listed: 'kev_listed_catalog_current',
      advisory_withdrawn: 'advisory_withdrawn_review_required',
    },
    'informational',
  ),
  row(
    'S13',
    withFacts(baseline(), {
      internet_exposure: { state: 'observed', value: 'internet_facing' },
      advisory_withdrawn: { state: 'observed', value: 'withdrawn' },
    }),
    2300,
    0,
    23,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [6, 2, 2],
    '59ffa739a607d34588e3ab99f206dad951167c5ee170ffb1ecd44cd0bee99f33',
    { advisory_withdrawn: 'advisory_withdrawn_review_required' },
    'informational',
  ),
  row(
    'S14',
    withFacts(baseline(), { finding_age_days: { state: 'observed', value: 29 } }),
    1300,
    0,
    13,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [6, 2, 2],
    'eedca271059e540875cf07e79b506e8d228aabf7ea3d92c0e78e1b542dc16479',
    { finding_age_days: 'age_under_30_days' },
  ),
  row(
    'S15',
    withFacts(baseline(), { finding_age_days: { state: 'observed', value: 30 } }),
    1400,
    0,
    14,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [6, 2, 2],
    '1237fa35abae3940e2fe99840f715fb0fc68a8dd81ca94be8d01469834e49774',
    { finding_age_days: 'age_30_to_89_days' },
  ),
  row(
    'S16',
    withFacts(baseline(), { finding_age_days: { state: 'observed', value: 89 } }),
    1400,
    0,
    14,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [6, 2, 2],
    '3dc44237ee2222b893d424d533daf27e3fa981ccb452f5c76e981afde1a936b7',
    { finding_age_days: 'age_30_to_89_days' },
  ),
  row(
    'S17',
    withFacts(baseline(), { finding_age_days: { state: 'observed', value: 90 } }),
    1500,
    0,
    15,
    'P4',
    180,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [6, 2, 2],
    '2d30d256046b8d3a26f58d260cf612355facd4dfe6311df484805caf41be47f5',
    { finding_age_days: 'age_90_days_or_more' },
  ),
  row(
    'S18',
    withFacts(baseline(), {
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: unavailable,
      internet_exposure: { state: 'unknown', value: 'unknown' },
    }),
    2300,
    3700,
    60,
    'P2',
    30,
    [],
    ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
    [4, 3, 3],
    '1f5336f4187642c3d175536d3b5bdb551589199e094a1d9c37ade34da110d713',
    { kev_listed: 'kev_listed_catalog_current' },
  ),
  row(
    'R01',
    r01,
    8000,
    0,
    80,
    'P1',
    7,
    ['kev_production', 'kev_internet_facing'],
    ['kev_minimum_band_already_met', 'kev_escalation_recommended'],
    [4, 0, 6],
    'aa11695d584a525109f7adc4460f5c2b5f3c6b55b24e52c5f7d3046f012bdc6e',
    {},
  ),
  row(
    'R02',
    withFacts(r01, {
      kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
    }),
    6000,
    0,
    60,
    'P2',
    30,
    [],
    ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    [4, 0, 6],
    '0d6974f4c64727cc959f8b18d573e0eea3e3926aa84a9c370c5178733939ffc8',
    {},
  ),
];

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function evaluateCorpusRow(facts: PriorityFactInput): {
  readonly parsedFacts: PriorityFactInput;
  readonly first: PriorityEvaluation;
  readonly second: PriorityEvaluation;
} {
  const parsed = parseFactInput(facts);
  if (!parsed.ok) {
    throw new Error('corpus facts must parse');
  }
  const first = evaluatePriority(BUILTIN_PRIORITY_POLICY_DEFINITION, parsed.value);
  const second = evaluatePriority(BUILTIN_PRIORITY_POLICY_DEFINITION, parsed.value);
  if (!first.ok || !second.ok) {
    throw new Error('corpus evaluation must succeed');
  }
  return { parsedFacts: parsed.value, first: first.value, second: second.value };
}

describe('V-0001 validation corpus', () => {
  it('hashes the built-in version 2 definition to the admitted digest', () => {
    const encoded = canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) {
      return;
    }
    expect(POLICY_ENGINE_VERSION).toBe(ENGINE_VERSION);
    expect(BUILTIN_PRIORITY_POLICY_DEFINITION.policyKey).toBe('patchpilot.builtin.v0');
    expect(BUILTIN_PRIORITY_POLICY_DEFINITION.schemaVersion).toBe(2);
    expect(Buffer.byteLength(encoded.value, 'utf8')).toBe(2205);
    expect(sha256(encoded.value)).toBe(DEFINITION_SHA256);
  });

  it('matches every documented S01–S18 and R01–R02 output, then replays it', () => {
    expect(CORPUS).toHaveLength(20);
    const encoded = canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) {
      return;
    }
    const policyDefinitionSha256 = sha256(encoded.value);
    expect(policyDefinitionSha256).toBe(DEFINITION_SHA256);

    for (const expected of CORPUS) {
      const { parsedFacts, first, second } = evaluateCorpusRow(expected.facts);
      expect(second, expected.id).toEqual(first);
      expect(first.engineVersion, expected.id).toBe(ENGINE_VERSION);
      expect(first.policyKey, expected.id).toBe('patchpilot.builtin.v0');
      expect(first.weightedScoreCenti, expected.id).toBe(expected.weighted);
      expect(first.upliftCenti, expected.id).toBe(expected.uplift);
      expect(first.priority, expected.id).toBe(expected.priority);
      expect(first.priorityBand, expected.id).toBe(expected.band);
      expect(first.dueDateRecommendationDays, expected.id).toBe(expected.due);
      expect(first.escalation.reasons, expected.id).toEqual(expected.reasons);
      expect(
        first.rules.map((rule) => rule.explanationCode),
        expected.id,
      ).toEqual(expected.rules);
      expect(
        [
          first.evidenceSummary.observed,
          first.evidenceSummary.unknown,
          first.evidenceSummary.unavailable,
        ],
        expected.id,
      ).toEqual(expected.evidence);
      const fingerprintJson = canonicalJson({
        engineVersion: ENGINE_VERSION,
        policyDefinitionSha256,
        facts: parsedFacts,
      });
      expect(fingerprintJson.ok, expected.id).toBe(true);
      if (!fingerprintJson.ok) {
        return;
      }
      expect(sha256(fingerprintJson.value), expected.id).toBe(expected.fingerprint);
      for (const [factorId, explanationCode] of Object.entries(expected.factors)) {
        const factor = first.factors.find((candidate) => candidate.factorId === factorId);
        expect(factor?.explanationCode, `${expected.id}:${factorId}`).toBe(explanationCode);
      }
      if (expected.withdrawnStatus !== null) {
        const withdrawn = first.factors.find(
          (candidate) => candidate.factorId === 'advisory_withdrawn',
        );
        expect(withdrawn?.status, expected.id).toBe(expected.withdrawnStatus);
      }
    }
  });
});
