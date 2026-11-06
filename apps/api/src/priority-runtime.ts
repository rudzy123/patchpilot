/**
 * The only production constructor for controlled priority calculation,
 * the current-priority read, and an append-only priority review.
 * Worker, web, seed, and startup do not construct these use cases.
 * Startup does not publish a policy.
 */

import { randomUUID } from 'node:crypto';

import { createActiveKevMembershipPersistence } from '@patchpilot/database';
import {
  createPriorityReviewPersistence,
  createRiskCalculationApplicationPersistence,
  exportRemediationQueueSnapshot,
  readRemediationQueuePage,
} from '@patchpilot/database/risk-calculation-application-persistence';
import {
  PRIORITY_CALCULATION_ENGINE_VERSION,
  type ControlledFindingOperatorActor,
  createCalculateFindingRiskUseCase,
  createExportRemediationQueueUseCase,
  createQueryActiveKevMembershipUseCase,
  createReadControlledFindingPriorityUseCase,
  createReadRemediationQueueUseCase,
  createRecordPriorityReviewUseCase,
  type AdmittedPriorityPolicyPair,
  type CalculateFindingRiskResult,
  type ExportRemediationQueueResult,
  type PriorityReviewDecision,
  type ReadControlledFindingPriorityResult,
  type ReadRemediationQueueResult,
  type RecordPriorityReviewResult,
  type RemediationQueueExportFormat,
  type RemediationQueueSection,
} from '@patchpilot/domain';

import { BUILTIN_PRIORITY_POLICY_DEFINITION, createPriorityEnginePort } from './priority-engine.js';
import { hashPriorityPolicyDefinition } from './priority-policy-hash.js';
import { serializeRemediationQueueExport } from './remediation-queue-http.js';

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

export type ControlledRemediationQueueInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly section: RemediationQueueSection;
  readonly limit: number;
  readonly cursor: string | null;
};

export type ControlledPriorityReviewInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly findingId: string;
  readonly correlationId: string;
  readonly command: {
    readonly riskCalculationId: string;
    readonly supersedesReviewId: string | null;
    readonly decision: PriorityReviewDecision;
    readonly correctedBand: 'P1' | 'P2' | 'P3' | 'P4' | null;
    readonly expiresAt: string | null;
    readonly reason: string | null;
  };
};

export type ControlledRemediationQueueExportInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly format: RemediationQueueExportFormat;
  readonly correlationId: string;
};

export type ControlledPriorityRuntime = {
  calculate(input: ControlledPriorityCalculationInput): Promise<CalculateFindingRiskResult>;
  read(input: ControlledPriorityReadInput): Promise<ReadControlledFindingPriorityResult>;
  readQueue(input: ControlledRemediationQueueInput): Promise<ReadRemediationQueueResult>;
  exportQueue(input: ControlledRemediationQueueExportInput): Promise<ExportRemediationQueueResult>;
  recordReview(input: ControlledPriorityReviewInput): Promise<RecordPriorityReviewResult>;
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
  const queue = createReadRemediationQueueUseCase({
    persistence: {
      findPublishedBuiltinPriorityPolicy: () => persistence.findPublishedBuiltinPriorityPolicy(),
      readRemediationQueue: (query) => readRemediationQueuePage(client, query),
    },
    admittedPairs: options.admittedPairs,
    referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    hashPolicyDefinition: hashPriorityPolicyDefinition,
  });
  const queueExport = createExportRemediationQueueUseCase({
    persistence: {
      exportRemediationQueue: (query, hooks) =>
        exportRemediationQueueSnapshot(client, query, hooks),
    },
    admittedPairs: options.admittedPairs,
    referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    hashPolicyDefinition: hashPriorityPolicyDefinition,
    serializeExport: serializeRemediationQueueExport,
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
    readQueue(input) {
      return queue.execute({
        actor: input.actor,
        command: {
          section: input.section,
          limit: input.limit,
          cursor: input.cursor,
        },
      });
    },
    exportQueue(input) {
      return queueExport.execute({
        actor: input.actor,
        command: {
          format: input.format,
          correlationId: input.correlationId,
        },
      });
    },
    async recordReview(input) {
      const correlationId = LOWERCASE_UUID.test(input.correlationId)
        ? input.correlationId
        : randomUUID();
      const review = createRecordPriorityReviewUseCase({
        persistence: createPriorityReviewPersistence(client),
      });
      return review.execute({
        actor: input.actor,
        command: {
          findingId: input.findingId,
          riskCalculationId: input.command.riskCalculationId,
          supersedesReviewId: input.command.supersedesReviewId,
          decision: input.command.decision,
          correctedBand: input.command.correctedBand,
          expiresAt: input.command.expiresAt,
          reason: input.command.reason,
          correlationId,
        },
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
    async readQueue() {
      return { kind: 'unavailable' };
    },
    async exportQueue() {
      return { kind: 'unavailable' };
    },
    async recordReview() {
      return { kind: 'unavailable' };
    },
  };
}
