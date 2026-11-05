/**
 * Current-priority read for one Finding in the actor's organization.
 * The organization comes from the trusted actor. This module does not call
 * the priority engine, assemble facts, or write an audit row.
 * `review` is the head of the current calculation. It does not change the
 * stored priority.
 */

import type { RiskCalculationFactorsV2Json } from '../json-documents.js';
import { assertNever } from '../result.js';
import {
  isAdmittedPriorityPolicyPair,
  type AdmittedPriorityPolicyPair,
} from './admitted-priority-policy.js';
import { authorizePriorityFindingCommand } from './calculation.js';
import { PRIORITY_INSPECT_PERMISSION } from './permissions.js';
import {
  FINDING_PRIORITY_REVIEW_NONE,
  type FindingPriorityReview,
  type FindingPriorityReviewNone,
} from './priority-review.js';
import type {
  FindingPriorityCalculationRecord,
  FindingPriorityPublishedBuiltin,
  RiskCalculationPersistencePort,
} from './persistence-port.js';

export const PRIORITY_INPUT_CHANGE_SIGNALS = [
  'policy_superseded',
  'engine_version_changed',
  'kev_generation_changed',
  'observed_after_calculation',
  'asset_updated_after_calculation',
] as const;

export type PriorityInputChangeSignal = (typeof PRIORITY_INPUT_CHANGE_SIGNALS)[number];

export type PriorityInputChangeReport = {
  readonly status: 'none_detected' | 'detected';
  readonly signals: readonly PriorityInputChangeSignal[];
};

export type PriorityInputChangeComparison = {
  readonly storedPolicyDefinitionSha256: string;
  readonly publishedPolicyDefinitionSha256: string;
  readonly storedEngineVersion: string;
  readonly referenceEngineVersion: string;
  readonly storedKevGenerationId: string | null;
  readonly activeKevGenerationId: string | null;
  readonly lastObservedAt: Date;
  readonly assetUpdatedAt: Date;
  readonly calculatedAt: Date;
};

export { FINDING_PRIORITY_REVIEW_NONE };
export type { FindingPriorityReviewNone };

export type FindingPriorityCalculatedView = {
  readonly findingId: string;
  readonly calculation: FindingPriorityCalculationRecord;
  readonly comparability: 'reference' | 'incomparable';
  readonly inputsChanged: PriorityInputChangeReport;
  readonly review: FindingPriorityReview;
};

export type ReadControlledFindingPriorityDependencies = {
  readonly persistence: Pick<RiskCalculationPersistencePort, 'readFindingPriority'>;
  readonly admittedPairs: readonly AdmittedPriorityPolicyPair[];
  readonly referenceEngineVersion: string;
  readonly hashPolicyDefinition: (definition: unknown) => string | null;
};

export type ReadControlledFindingPriorityResult =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'not_calculated'; readonly findingId: string }
  | { readonly kind: 'calculated'; readonly view: FindingPriorityCalculatedView }
  | { readonly kind: 'priority_policy_unavailable' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_failure' };

export function createReadControlledFindingPriorityUseCase(
  dependencies: ReadControlledFindingPriorityDependencies,
) {
  return {
    async execute(input: unknown): Promise<ReadControlledFindingPriorityResult> {
      try {
        return await executeRead(dependencies, input);
      } catch {
        return { kind: 'internal_failure' };
      }
    },
  };
}

export function classifyPriorityInputChanges(
  input: PriorityInputChangeComparison,
): PriorityInputChangeReport | null {
  if (
    !Number.isFinite(input.lastObservedAt.getTime()) ||
    !Number.isFinite(input.assetUpdatedAt.getTime()) ||
    !Number.isFinite(input.calculatedAt.getTime())
  ) {
    return null;
  }
  const signals: PriorityInputChangeSignal[] = [];
  if (input.storedPolicyDefinitionSha256 !== input.publishedPolicyDefinitionSha256) {
    signals.push('policy_superseded');
  }
  if (input.storedEngineVersion !== input.referenceEngineVersion) {
    signals.push('engine_version_changed');
  }
  if (input.storedKevGenerationId !== input.activeKevGenerationId) {
    signals.push('kev_generation_changed');
  }
  if (input.lastObservedAt.getTime() > input.calculatedAt.getTime()) {
    signals.push('observed_after_calculation');
  }
  if (input.assetUpdatedAt.getTime() > input.calculatedAt.getTime()) {
    signals.push('asset_updated_after_calculation');
  }
  if (signals.length === 0) {
    return { status: 'none_detected', signals };
  }
  return { status: 'detected', signals };
}

async function executeRead(
  dependencies: ReadControlledFindingPriorityDependencies,
  input: unknown,
): Promise<ReadControlledFindingPriorityResult> {
  const authorized = authorizePriorityFindingCommand(input, PRIORITY_INSPECT_PERMISSION);
  if (!authorized.ok) {
    return { kind: authorized.kind };
  }
  if (typeof dependencies.persistence.readFindingPriority !== 'function') {
    return { kind: 'internal_failure' };
  }
  if (dependencies.referenceEngineVersion.length === 0) {
    return { kind: 'internal_failure' };
  }
  const current = await dependencies.persistence.readFindingPriority({
    organizationId: authorized.actor.organizationId,
    findingId: authorized.findingId,
  });
  switch (current.kind) {
    case 'finding_absent':
      return { kind: 'not_found' };
    case 'unavailable':
      return { kind: 'unavailable' };
    case 'not_calculated':
    case 'calculated':
      break;
    default:
      return assertNever(current);
  }
  if (current.findingId !== authorized.findingId) {
    return { kind: 'not_found' };
  }
  const reference = admitPublishedBuiltin(dependencies, current.publishedBuiltin);
  if (!reference.ok) {
    return { kind: 'priority_policy_unavailable' };
  }
  if (current.kind === 'not_calculated') {
    return { kind: 'not_calculated', findingId: current.findingId };
  }
  const inputsChanged = classifyPriorityInputChanges({
    storedPolicyDefinitionSha256: current.calculation.policyDefinitionSha256,
    publishedPolicyDefinitionSha256: reference.policyDefinitionSha256,
    storedEngineVersion: current.calculation.calculationEngineVersion,
    referenceEngineVersion: dependencies.referenceEngineVersion,
    storedKevGenerationId: storedKevGenerationId(current.calculation.factors),
    activeKevGenerationId: current.calculation.activeKevGenerationId,
    lastObservedAt: current.calculation.lastObservedAt,
    assetUpdatedAt: current.calculation.assetUpdatedAt,
    calculatedAt: current.calculation.calculatedAt,
  });
  if (inputsChanged === null) {
    return { kind: 'unavailable' };
  }
  const comparable =
    current.calculation.policyDefinitionSha256 === reference.policyDefinitionSha256 &&
    current.calculation.calculationEngineVersion === dependencies.referenceEngineVersion;
  return {
    kind: 'calculated',
    view: {
      findingId: current.findingId,
      calculation: current.calculation,
      comparability: comparable ? 'reference' : 'incomparable',
      inputsChanged,
      review: current.review,
    },
  };
}

function admitPublishedBuiltin(
  dependencies: ReadControlledFindingPriorityDependencies,
  published: FindingPriorityPublishedBuiltin | null,
): { readonly ok: true; readonly policyDefinitionSha256: string } | { readonly ok: false } {
  if (published === null) {
    return { ok: false };
  }
  if (typeof dependencies.hashPolicyDefinition !== 'function') {
    return { ok: false };
  }
  let hash: string | null;
  try {
    hash = dependencies.hashPolicyDefinition(published.definition);
  } catch {
    return { ok: false };
  }
  if (hash === null) {
    return { ok: false };
  }
  if (
    !isAdmittedPriorityPolicyPair(
      dependencies.admittedPairs,
      dependencies.referenceEngineVersion,
      hash,
    )
  ) {
    return { ok: false };
  }
  return { ok: true, policyDefinitionSha256: hash };
}

function storedKevGenerationId(factors: RiskCalculationFactorsV2Json): string | null {
  const kev = factors.sources.kev;
  if (kev.state === 'unavailable') {
    return null;
  }
  return kev.generationId;
}
