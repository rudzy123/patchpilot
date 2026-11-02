import {
  AGE_EXPLANATION_THRESHOLDS,
  FACTOR_IDS,
  POLICY_ENGINE_VERSION,
  PRIORITY_MAX,
  SEVERITY_RATINGS,
  WEIGHT_SUM,
  PERCENT_MAX,
  factorOrdinal,
  isKevListedToken,
  type EscalationReason,
  type FactorExplanationCode,
  type FactorId,
  type FactorInputState,
  type FactorStatus,
  type PriorityBand,
  type RuleExplanationCode,
  type RuleId,
  type SeverityRating,
} from './catalog.js';
import { deepFreeze } from './deep-freeze.js';
import {
  definitionNotValidatedError,
  isValidatedPriorityPolicyDefinition,
  type AgeBucket,
  type PolicyDefinitionError,
  type PriorityPolicyDefinition,
  type ValidatedPriorityPolicyDefinition,
} from './definition.js';
import {
  factsNotParsedError,
  isParsedPriorityFactInput,
  type FactInputError,
  type ParsedPriorityFactInput,
  type PriorityFactInput,
} from './facts.js';
import { err, ok, type Result } from './result.js';

export type PriorityFactorRow = {
  readonly factorId: FactorId;
  readonly ordinal: number;
  readonly inputState: FactorInputState;
  readonly observedValue: string | number | null;
  readonly normalizedPercent: number;
  readonly weight: number;
  readonly contributionCenti: number;
  readonly status: FactorStatus;
  readonly explanationCode: FactorExplanationCode;
};

export type PriorityRuleRow = {
  readonly ruleId: RuleId;
  readonly triggered: boolean;
  readonly upliftCenti: number;
  readonly explanationCode: RuleExplanationCode;
};

export type PriorityEvaluation = {
  readonly engineVersion: typeof POLICY_ENGINE_VERSION;
  readonly policyKey: string;
  readonly weightedScoreCenti: number;
  readonly upliftCenti: number;
  readonly priority: number;
  readonly priorityBand: PriorityBand;
  readonly dueDateRecommendationDays: number;
  readonly escalation: {
    readonly recommended: boolean;
    readonly reasons: readonly EscalationReason[];
  };
  readonly factors: readonly PriorityFactorRow[];
  readonly rules: readonly PriorityRuleRow[];
  readonly evidenceSummary: {
    readonly observed: number;
    readonly unknown: number;
    readonly unavailable: number;
  };
};

export const ENGINE_INVARIANT_CODES = [
  'contribution_out_of_range',
  'weighted_score_out_of_range',
  'uplift_out_of_range',
  'priority_out_of_range',
  'band_unresolved',
] as const;
export type EngineInvariantCode = (typeof ENGINE_INVARIANT_CODES)[number];

export type EngineInvariantViolation = {
  readonly kind: 'engine_invariant_violation';
  readonly code: EngineInvariantCode;
};

export type PriorityEvaluationError =
  PolicyDefinitionError | FactInputError | EngineInvariantViolation;

type FactorReading = {
  readonly inputState: FactorInputState;
  readonly observedValue: string | number | null;
  readonly normalizedPercent: number;
  readonly explanationCode: FactorExplanationCode;
};

type WeightedReading = FactorReading & {
  readonly factorId: FactorId;
  readonly weight: number;
  readonly contributionCenti: number;
};

type Outcome = {
  readonly readings: readonly WeightedReading[];
  readonly contributions: readonly number[];
  readonly weightedScoreCenti: number;
  readonly upliftCenti: number;
  readonly priority: number;
  readonly band: { readonly band: PriorityBand; readonly dueDateRecommendationDays: number } | null;
  readonly kevListed: boolean;
  readonly reasons: readonly EscalationReason[];
};

const UNAVAILABLE_FACTS: PriorityFactInput = {
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

function observed(
  observedValue: string | number,
  normalizedPercent: number,
  explanationCode: FactorExplanationCode,
): FactorReading {
  return { inputState: 'observed', observedValue, normalizedPercent, explanationCode };
}

function notObserved(
  inputState: 'unknown' | 'unavailable',
  explanationCode: FactorExplanationCode,
): FactorReading {
  return { inputState, observedValue: null, normalizedPercent: 0, explanationCode };
}

function highestSeverity(values: readonly SeverityRating[]): SeverityRating {
  let highest = SEVERITY_RATINGS.length - 1;
  for (const value of values) {
    highest = Math.min(highest, SEVERITY_RATINGS.indexOf(value));
  }
  return SEVERITY_RATINGS[highest] ?? 'none';
}

function agePercent(buckets: readonly AgeBucket[], days: number): number {
  let percent = 0;
  for (const bucket of buckets) {
    if (days >= bucket.minDays) {
      percent = bucket.percent;
    }
  }
  return percent;
}

function ageCode(days: number): FactorExplanationCode {
  if (days < AGE_EXPLANATION_THRESHOLDS.under30) {
    return 'age_under_30_days';
  }
  return days < AGE_EXPLANATION_THRESHOLDS.under90 ? 'age_30_to_89_days' : 'age_90_days_or_more';
}

function readFactor(
  definition: PriorityPolicyDefinition,
  facts: PriorityFactInput,
  factorId: FactorId,
): FactorReading {
  const normalization = definition.normalization;
  switch (factorId) {
    case 'source_severity': {
      const fact = facts.source_severity;
      if (fact.state === 'observed') {
        const rating = highestSeverity(fact.values);
        return observed(rating, normalization.source_severity[rating], `severity_${rating}`);
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', 'severity_unrated')
        : notObserved('unavailable', 'severity_unavailable');
    }
    case 'kev_listed': {
      const fact = facts.kev_listed;
      if (fact.state === 'observed') {
        return observed(fact.value, normalization.kev_listed[fact.value], `kev_${fact.value}`);
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', `kev_${fact.value}`)
        : notObserved('unavailable', `kev_unavailable_${fact.reason}`);
    }
    case 'environment_sensitivity': {
      const fact = facts.environment_sensitivity;
      return fact.state === 'observed'
        ? observed(
            fact.value,
            normalization.environment_sensitivity[fact.value],
            `environment_${fact.value}`,
          )
        : notObserved('unavailable', 'environment_unavailable');
    }
    case 'internet_exposure': {
      const fact = facts.internet_exposure;
      if (fact.state === 'observed') {
        return observed(
          fact.value,
          normalization.internet_exposure[fact.value],
          `exposure_${fact.value}`,
        );
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', 'exposure_unknown')
        : notObserved('unavailable', 'exposure_unavailable');
    }
    case 'business_criticality': {
      const fact = facts.business_criticality;
      if (fact.state === 'observed') {
        return observed(
          fact.value,
          normalization.business_criticality[fact.value],
          `criticality_${fact.value}`,
        );
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', 'criticality_unspecified')
        : notObserved('unavailable', 'criticality_unavailable');
    }
    case 'asset_data_classification': {
      const fact = facts.asset_data_classification;
      if (fact.state === 'observed') {
        return observed(
          fact.value,
          normalization.asset_data_classification[fact.value],
          `data_${fact.value}`,
        );
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', 'data_unspecified')
        : notObserved('unavailable', 'data_unavailable');
    }
    case 'direct_dependency': {
      const fact = facts.direct_dependency;
      return fact.state === 'observed'
        ? observed(
            fact.value,
            normalization.direct_dependency[fact.value],
            `dependency_${fact.value}`,
          )
        : notObserved('unavailable', 'dependency_unavailable');
    }
    case 'fix_available': {
      const fact = facts.fix_available;
      if (fact.state === 'observed') {
        return observed(fact.value, normalization.fix_available[fact.value], `fix_${fact.value}`);
      }
      return fact.state === 'unknown'
        ? notObserved('unknown', 'fix_undetermined')
        : notObserved('unavailable', 'fix_unavailable');
    }
    case 'finding_age_days': {
      const fact = facts.finding_age_days;
      return fact.state === 'observed'
        ? observed(
            fact.value,
            agePercent(normalization.finding_age_days, fact.value),
            ageCode(fact.value),
          )
        : notObserved('unavailable', 'age_unavailable');
    }
    case 'advisory_withdrawn': {
      const fact = facts.advisory_withdrawn;
      if (fact.state === 'unavailable') {
        return notObserved('unavailable', 'advisory_withdrawal_unavailable');
      }
      return observed(
        fact.value,
        0,
        fact.value === 'withdrawn'
          ? 'advisory_withdrawn_review_required'
          : 'advisory_not_withdrawn',
      );
    }
  }
}

function computeOutcome(definition: PriorityPolicyDefinition, facts: PriorityFactInput): Outcome {
  const readings = FACTOR_IDS.map((factorId): WeightedReading => {
    const reading = readFactor(definition, facts, factorId);
    const weight = definition.weights[factorId];
    return { ...reading, factorId, weight, contributionCenti: weight * reading.normalizedPercent };
  });
  const contributions = readings.map((reading) => reading.contributionCenti);
  const weightedScoreCenti = contributions.reduce((total, value) => total + value, 0);

  const kev = facts.kev_listed;
  const kevListed = kev.state === 'observed' && isKevListedToken(kev.value);
  const floorBand = definition.bands.find((band) => band.band === definition.rules.kevMinimumBand);
  const floorCenti = (floorBand?.minPriority ?? 0) * 100;
  const upliftCenti = kevListed ? Math.max(0, floorCenti - weightedScoreCenti) : 0;

  const priority = Math.floor((weightedScoreCenti + upliftCenti + 50) / 100);
  const band = definition.bands.find((candidate) => priority >= candidate.minPriority) ?? null;

  const reasons: EscalationReason[] = [];
  if (kevListed) {
    const environment = facts.environment_sensitivity;
    const exposure = facts.internet_exposure;
    if (environment.state === 'observed' && environment.value === 'production') {
      reasons.push('kev_production');
    }
    if (exposure.state === 'observed' && exposure.value === 'internet_facing') {
      reasons.push('kev_internet_facing');
    }
  }

  return {
    readings,
    contributions,
    weightedScoreCenti,
    upliftCenti,
    priority,
    band,
    kevListed,
    reasons,
  };
}

/**
 * Range assertion over the arithmetic. Unreachable with a validated
 * definition, so the engine rejects rather than clamps.
 */
export function checkPriorityInvariants(outcome: {
  readonly contributions: readonly number[];
  readonly weightedScoreCenti: number;
  readonly upliftCenti: number;
  readonly priority: number;
  readonly band: unknown;
}): EngineInvariantCode | null {
  const maxCenti = WEIGHT_SUM * PERCENT_MAX;
  const inRange = (value: number, max: number): boolean =>
    Number.isSafeInteger(value) && value >= 0 && value <= max;
  if (!outcome.contributions.every((value) => inRange(value, maxCenti))) {
    return 'contribution_out_of_range';
  }
  if (!inRange(outcome.weightedScoreCenti, maxCenti)) {
    return 'weighted_score_out_of_range';
  }
  if (!inRange(outcome.upliftCenti, maxCenti - outcome.weightedScoreCenti)) {
    return 'uplift_out_of_range';
  }
  if (!inRange(outcome.priority, PRIORITY_MAX)) {
    return 'priority_out_of_range';
  }
  return outcome.band === null || outcome.band === undefined ? 'band_unresolved' : null;
}

function withFactorUnavailable(facts: PriorityFactInput, factorId: FactorId): PriorityFactInput {
  return { ...facts, [factorId]: UNAVAILABLE_FACTS[factorId] };
}

function factorStatus(
  definition: PriorityPolicyDefinition,
  facts: PriorityFactInput,
  outcome: Outcome,
  reading: WeightedReading,
): FactorStatus {
  if (reading.inputState !== 'unavailable') {
    const counterfactual = computeOutcome(
      definition,
      withFactorUnavailable(facts, reading.factorId),
    );
    const bandChanged = counterfactual.band?.band !== outcome.band?.band;
    const escalationChanged = counterfactual.reasons.length > 0 !== outcome.reasons.length > 0;
    if (bandChanged || escalationChanged) {
      return 'decisive';
    }
  }
  if (reading.weight === 0) {
    return 'informational';
  }
  return reading.contributionCenti > 0 ? 'contributing' : 'non_contributing';
}

function minimumBandRule(outcome: Outcome): PriorityRuleRow {
  if (!outcome.kevListed) {
    return {
      ruleId: 'kev_minimum_band',
      triggered: false,
      upliftCenti: 0,
      explanationCode: 'kev_minimum_band_not_triggered',
    };
  }
  return {
    ruleId: 'kev_minimum_band',
    triggered: true,
    upliftCenti: outcome.upliftCenti,
    explanationCode:
      outcome.upliftCenti > 0 ? 'kev_minimum_band_raised' : 'kev_minimum_band_already_met',
  };
}

function escalationRule(outcome: Outcome): PriorityRuleRow {
  const recommended = outcome.reasons.length > 0;
  let explanationCode: RuleExplanationCode = 'kev_escalation_not_triggered';
  if (outcome.kevListed) {
    explanationCode = recommended
      ? 'kev_escalation_recommended'
      : 'kev_escalation_context_not_observed';
  }
  return { ruleId: 'kev_escalation', triggered: recommended, upliftCenti: 0, explanationCode };
}

/**
 * Evaluates one Finding's facts under one validated policy definition. Pure:
 * no I/O, clock, or randomness. The result is deep-frozen and carries no
 * tenant, Finding, asset, component, or user identifiers.
 */
export function evaluatePriority(
  definition: ValidatedPriorityPolicyDefinition,
  facts: ParsedPriorityFactInput,
): Result<PriorityEvaluation, PriorityEvaluationError> {
  if (!isValidatedPriorityPolicyDefinition(definition)) {
    return err(definitionNotValidatedError());
  }
  if (!isParsedPriorityFactInput(facts)) {
    return err(factsNotParsedError());
  }

  const outcome = computeOutcome(definition, facts);
  const violation = checkPriorityInvariants(outcome);
  if (violation !== null || outcome.band === null) {
    return err(
      deepFreeze({ kind: 'engine_invariant_violation', code: violation ?? 'band_unresolved' }),
    );
  }

  const factors = outcome.readings.map((reading): PriorityFactorRow => ({
    factorId: reading.factorId,
    ordinal: factorOrdinal(reading.factorId),
    inputState: reading.inputState,
    observedValue: reading.observedValue,
    normalizedPercent: reading.normalizedPercent,
    weight: reading.weight,
    contributionCenti: reading.contributionCenti,
    status: factorStatus(definition, facts, outcome, reading),
    explanationCode: reading.explanationCode,
  }));

  const countState = (state: FactorInputState): number =>
    factors.filter((row) => row.inputState === state).length;

  return ok(
    deepFreeze({
      engineVersion: POLICY_ENGINE_VERSION,
      policyKey: definition.policyKey,
      weightedScoreCenti: outcome.weightedScoreCenti,
      upliftCenti: outcome.upliftCenti,
      priority: outcome.priority,
      priorityBand: outcome.band.band,
      dueDateRecommendationDays: outcome.band.dueDateRecommendationDays,
      escalation: { recommended: outcome.reasons.length > 0, reasons: [...outcome.reasons] },
      factors,
      rules: [minimumBandRule(outcome), escalationRule(outcome)],
      evidenceSummary: {
        observed: countState('observed'),
        unknown: countState('unknown'),
        unavailable: countState('unavailable'),
      },
    }),
  );
}
