import { describe, expect, it } from 'vitest';

import {
  ADVISORY_WITHDRAWN_TOKENS,
  ASSET_DATA_CLASSIFICATION_TOKENS,
  BUSINESS_CRITICALITY_TOKENS,
  DIRECT_DEPENDENCY_TOKENS,
  ENVIRONMENT_SENSITIVITY_TOKENS,
  EXPLANATION_CODES,
  EXPLANATION_TEXT,
  FIX_AVAILABLE_TOKENS,
  INTERNET_EXPOSURE_TOKENS,
  KEV_OBSERVED_TOKENS,
  KEV_UNAVAILABLE_REASONS,
  KEV_UNKNOWN_TOKENS,
  SEVERITY_RATINGS,
} from './catalog.js';
import type { PriorityFactInput } from './facts.js';
import { evaluateWith } from './test-helper.js';

type Facts = Partial<PriorityFactInput>;

const LISTED: Facts = { kev_listed: { state: 'observed', value: 'listed_catalog_current' } };

/** Every factor state and token, plus each rule outcome. */
const COVERAGE_INPUTS: readonly Facts[] = [
  {},
  ...SEVERITY_RATINGS.map((rating): Facts => ({
    source_severity: { state: 'observed', values: [rating] },
  })),
  { source_severity: { state: 'unknown', value: 'unrated' } },
  ...KEV_OBSERVED_TOKENS.map((value): Facts => ({ kev_listed: { state: 'observed', value } })),
  ...KEV_UNKNOWN_TOKENS.map((value): Facts => ({ kev_listed: { state: 'unknown', value } })),
  ...KEV_UNAVAILABLE_REASONS.map((reason): Facts => ({
    kev_listed: { state: 'unavailable', reason },
  })),
  ...ENVIRONMENT_SENSITIVITY_TOKENS.map((value): Facts => ({
    environment_sensitivity: { state: 'observed', value },
  })),
  ...INTERNET_EXPOSURE_TOKENS.map((value): Facts => ({
    internet_exposure: { state: 'observed', value },
  })),
  { internet_exposure: { state: 'unknown', value: 'unknown' } },
  ...BUSINESS_CRITICALITY_TOKENS.map((value): Facts => ({
    business_criticality: { state: 'observed', value },
  })),
  { business_criticality: { state: 'unknown', value: 'unspecified' } },
  ...ASSET_DATA_CLASSIFICATION_TOKENS.map((value): Facts => ({
    asset_data_classification: { state: 'observed', value },
  })),
  { asset_data_classification: { state: 'unknown', value: 'unspecified' } },
  ...DIRECT_DEPENDENCY_TOKENS.map((value): Facts => ({
    direct_dependency: { state: 'observed', value },
  })),
  ...FIX_AVAILABLE_TOKENS.map((value): Facts => ({ fix_available: { state: 'observed', value } })),
  { fix_available: { state: 'unknown', value: 'undetermined' } },
  ...[0, 30, 90].map((value): Facts => ({ finding_age_days: { state: 'observed', value } })),
  ...ADVISORY_WITHDRAWN_TOKENS.map((value): Facts => ({
    advisory_withdrawn: { state: 'observed', value },
  })),
  LISTED,
  {
    ...LISTED,
    source_severity: { state: 'observed', values: ['critical'] },
    environment_sensitivity: { state: 'observed', value: 'production' },
    internet_exposure: { state: 'observed', value: 'internet_facing' },
  },
];

function emittedCodes(): Set<string> {
  const codes = new Set<string>();
  for (const facts of COVERAGE_INPUTS) {
    const result = evaluateWith(facts);
    for (const row of [...result.factors, ...result.rules]) {
      codes.add(row.explanationCode);
    }
  }
  return codes;
}

describe('EXPLANATION_TEXT', () => {
  it('EX1 has text for exactly the closed explanation codes', () => {
    expect(Object.keys(EXPLANATION_TEXT).sort()).toEqual([...EXPLANATION_CODES].sort());
    expect(new Set(EXPLANATION_CODES).size).toBe(EXPLANATION_CODES.length);
  });

  it('EX1 gives every emitted code static text, and every code is reachable', () => {
    const emitted = emittedCodes();
    for (const code of emitted) {
      expect(EXPLANATION_CODES).toContain(code);
      expect(Object.hasOwn(EXPLANATION_TEXT, code)).toBe(true);
    }
    expect([...emitted].sort()).toEqual([...EXPLANATION_CODES].sort());
  });

  it.each(EXPLANATION_CODES)('EX1 %s text is a complete sentence without placeholders', (code) => {
    const text = EXPLANATION_TEXT[code];
    expect(text.length).toBeGreaterThan(0);
    expect(text).toMatch(/^[A-Z].*\.$/);
    expect(text).not.toMatch(/[{}$%<>`\\]/);
    expect(text).not.toMatch(/\b(?:undefined|null|NaN)\b/);
    expect(text.trim()).toBe(text);
    expect(text).not.toMatch(/\s{2}/);
  });

  it('never claims exploitation, affectedness, compliance, or remediation', () => {
    for (const text of Object.values(EXPLANATION_TEXT)) {
      expect(text).not.toMatch(/\b(?:is|are|was|were) exploited\b/i);
      expect(text).not.toMatch(/\bis affected\b/i);
      expect(text).not.toMatch(/\b(?:compliant|certified|remediated)\b/i);
    }
  });

  it('is frozen', () => {
    expect(Object.isFrozen(EXPLANATION_TEXT)).toBe(true);
    expect(() => {
      (EXPLANATION_TEXT as Record<string, string>)['severity_high'] = 'changed';
    }).toThrow(TypeError);
  });
});
