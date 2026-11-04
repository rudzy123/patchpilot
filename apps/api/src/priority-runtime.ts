/**
 * The only production constructor for controlled priority calculation and
 * the current-priority read. Worker, web, seed, and startup do not construct
 * these use cases. Startup does not publish a policy.
 */

import { randomUUID } from 'node:crypto';

import { createActiveKevMembershipPersistence } from '@patchpilot/database';
import { createRiskCalculationApplicationPersistence } from '@patchpilot/database/risk-calculation-application-persistence';
import type { ControlledFindingOperatorActor } from '@patchpilot/domain/controlled-finding-operator';
import {
  PRIORITY_CALCULATION_ENGINE_VERSION,
  createCalculateFindingRiskUseCase,
  createQueryActiveKevMembershipUseCase,
  createReadControlledFindingPriorityUseCase,
  type AdmittedPriorityPolicyPair,
  type CalculateFindingRiskResult,
  type ReadControlledFindingPriorityResult,
} from '@patchpilot/domain';

import { BUILTIN_PRIORITY_POLICY_DEFINITION, createPriorityEnginePort } from './priority-engine.js';
import { hashPriorityPolicyDefinition } from './priority-policy-hash.js';

const LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type ControlledPriorityCalculationInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly findingId: string;
  readonly correlationId: string;
};

export type ControlledPriorityReadInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly findingId: string;
};

export type ControlledPriorityRuntime = {
  calculate(input: ControlledPriorityCalculationInput): Promise<CalculateFindingRiskResult>;
  read(input: ControlledPriorityReadInput): Promise<ReadControlledFindingPriorityResult>;
};

export type ControlledPriorityRuntimeOptions = {
  readonly admittedPairs: readonly AdmittedPriorityPolicyPair[];
  readonly kevEnabled: boolean;
  readonly kevStaleThresholdSeconds: number;
  readonly engine?: ReturnType<typeof createPriorityEnginePort>;
};

export function composeControlledPriorityRuntime(
  client: Parameters<typeof createRiskCalculationApplicationPersistence>[0],
  options: ControlledPriorityRuntimeOptions,
): ControlledPriorityRuntime {
  const engine = options.engine ?? createPriorityEnginePort();
  const persistence = createRiskCalculationApplicationPersistence(client, {
    bindKevMembership: (bound, asOf) =>
      createQueryActiveKevMembershipUseCase({
        membership: createActiveKevMembershipPersistence(bound),
        kevEnabled: options.kevEnabled,
        staleThresholdSeconds: options.kevStaleThresholdSeconds,
        now: () => asOf,
      }),
  });
  const read = createReadControlledFindingPriorityUseCase({
    persistence,
    admittedPairs: options.admittedPairs,
    referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    hashPolicyDefinition: hashPriorityPolicyDefinition,
  });
  return {
    async calculate(input) {
      const correlationId = LOWERCASE_UUID.test(input.correlationId)
        ? input.correlationId
        : randomUUID();
      const calculate = createCalculateFindingRiskUseCase({
        engine,
        persistence,
        builtinDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION,
        admittedPairs: options.admittedPairs,
        createCorrelationId: () => correlationId,
      });
      return calculate.execute({
        actor: input.actor,
        command: { findingId: input.findingId },
      });
    },
    read(input) {
      return read.execute({
        actor: input.actor,
        command: { findingId: input.findingId },
      });
    },
  };
}

export function denyControlledPriorityRuntime(): ControlledPriorityRuntime {
  return {
    async calculate() {
      return { kind: 'internal_failure' };
    },
    async read() {
      return { kind: 'unavailable' };
    },
  };
}
