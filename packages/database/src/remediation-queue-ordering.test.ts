import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_KEV_LISTED_TOKENS,
  compareStoredRemediationRank,
  storedKevListed,
  type StoredRemediationRankKey,
} from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  compareForRemediationQueue,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  type PriorityEvaluation,
  type PriorityFactInput,
} from '@patchpilot/policy-engine';
import { describe, expect, it } from 'vitest';

const BASE_FACTS: PriorityFactInput = {
  source_severity: { state: 'unavailable' },
  kev_listed: { state: 'unavailable', reason: 'no_active_generation' },
  environment_sensitivity: { state: 'unavailable' },
  internet_exposure: { state: 'unavailable' },
  business_criticality: { state: 'unavailable' },
  asset_data_classification: { state: 'unavailable' },
  direct_dependency: { state: 'unavailable' },
  fix_available: { state: 'unavailable' },
  finding_age_days: { state: 'unavailable' },
  advisory_withdrawn: { state: 'unavailable' },
};

const CRITICAL = { source_severity: { state: 'observed' as const, values: ['critical' as const] } };
const HIGH = { source_severity: { state: 'observed' as const, values: ['high' as const] } };
const LOW = { source_severity: { state: 'observed' as const, values: ['low' as const] } };
const LISTED = {
  kev_listed: { state: 'observed' as const, value: 'listed_catalog_current' as const },
};
const NOT_LISTED = {
  kev_listed: { state: 'observed' as const, value: 'not_listed_catalog_current' as const },
};
const PRODUCTION = {
  environment_sensitivity: { state: 'observed' as const, value: 'production' as const },
};
const NON_PRODUCTION = {
  environment_sensitivity: { state: 'observed' as const, value: 'non_production' as const },
};
const INTERNET = {
  internet_exposure: { state: 'observed' as const, value: 'internet_facing' as const },
};
const INTERNAL = { internet_exposure: { state: 'observed' as const, value: 'internal' as const } };

function evaluate(overrides: Partial<PriorityFactInput>): PriorityEvaluation {
  const facts = parseFactInput({ ...BASE_FACTS, ...overrides });
  const definition = validatePolicyDefinition(structuredClone(BUILTIN_PRIORITY_POLICY_DEFINITION));
  if (!facts.ok || !definition.ok) {
    throw new Error('queue fixture must evaluate');
  }
  const result = evaluatePriority(definition.value, facts.value);
  if (!result.ok) {
    throw new Error(`queue fixture evaluation failed: ${result.error.kind}`);
  }
  return result.value;
}

function storedKey(
  evaluation: PriorityEvaluation,
  firstObservedAt = '2026-11-04T18:00:00.000Z',
  findingId = '55555555-5555-4555-8555-555555555555',
): StoredRemediationRankKey {
  const severity = evaluation.factors.find((row) => row.factorId === 'source_severity');
  const kev = evaluation.factors.find((row) => row.factorId === 'kev_listed');
  return {
    policyKey: evaluation.policyKey,
    priority: evaluation.priority,
    escalationRecommended: evaluation.escalation.recommended,
    kevListed: kev !== undefined && storedKevListed(kev),
    severityPercent: severity?.normalizedPercent ?? 0,
    firstObservedAt,
    findingId,
  };
}

function expectSameOrder(left: PriorityEvaluation, right: PriorityEvaluation): void {
  const engine = compareForRemediationQueue(left, right);
  const stored = compareStoredRemediationRank(storedKey(left), storedKey(right));
  expect(stored).toBe(engine);
  expect(compareStoredRemediationRank(storedKey(right), storedKey(left))).toBe(
    compareForRemediationQueue(right, left),
  );
}

describe('remediation queue comparator equivalence', () => {
  it('matches the engine keys and then the caller keys', () => {
    expect(POLICY_ENGINE_VERSION).toBe(PRIORITY_CALCULATION_ENGINE_VERSION);
    const high = evaluate({
      ...CRITICAL,
      ...LISTED,
      ...NON_PRODUCTION,
      ...INTERNAL,
      business_criticality: { state: 'observed', value: 'critical' },
    });
    const escalated = evaluate({ ...HIGH, ...LISTED, ...NON_PRODUCTION, ...INTERNET });
    const listedOnly = evaluate(LISTED);
    const severe = evaluate({ ...CRITICAL, ...PRODUCTION, ...INTERNET, ...NOT_LISTED });
    const lowListed = evaluate({ ...LOW, ...LISTED });
    expectSameOrder(high, escalated);
    expectSameOrder(escalated, listedOnly);
    expectSameOrder(listedOnly, severe);
    expectSameOrder(lowListed, severe);
    const tied = evaluate({ ...HIGH, ...PRODUCTION });
    const tiedAgain = evaluate({ ...HIGH, ...PRODUCTION });
    expect(compareForRemediationQueue(tied, tiedAgain)).toBe(0);
    expect(
      compareStoredRemediationRank(
        storedKey(tied, '2026-11-04T18:00:00.000Z', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab'),
        storedKey(tiedAgain, '2026-11-04T18:00:01.000Z', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
      ),
    ).toBe(-1);
    expect(
      compareStoredRemediationRank(
        storedKey(tied, '2026-11-04T18:00:00.000Z', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab'),
        storedKey(tiedAgain, '2026-11-04T18:00:00.000Z', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
      ),
    ).toBe(1);
    const otherPolicy = { ...tied, policyKey: 'other.policy' };
    expect(compareForRemediationQueue(tied, otherPolicy)).toBe('incomparable');
    expect(compareStoredRemediationRank(storedKey(tied), storedKey(otherPolicy))).toBe(
      'incomparable',
    );
    const withoutSeverity = {
      ...severe,
      factors: severe.factors.filter((row) => row.factorId !== 'source_severity'),
    };
    expect(compareForRemediationQueue(withoutSeverity, withoutSeverity)).toBe(0);
    expect(storedKey(withoutSeverity).severityPercent).toBe(0);
  });

  it('keeps the stored KEV tokens and caller order in the SQL read', () => {
    const source = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'remediation-queue-persistence.ts'),
      'utf8',
    );
    for (const token of PRIORITY_KEV_LISTED_TOKENS) {
      expect(source).toContain(token);
    }
    expect(source).toContain('COLLATE "C"');
    expect(source).toContain('priority_numeric DESC');
    expect(source).toContain('first_observed_text COLLATE "C" ASC');
    expect(source).not.toContain('compareForRemediationQueue');
  });
});
