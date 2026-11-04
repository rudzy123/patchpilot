/**
 * Thin adapter from the domain risk-calculation port to the existing
 * PostgreSQL functions. Calculation runs inside one transaction: the adapter
 * loads rows under the Finding lock and invokes the domain callback there.
 * This module does not assemble facts, hash a policy, or import the policy
 * engine. The database barrel does not construct it.
 */

import type { Prisma, PrismaClient } from '@prisma/client';
import type {
  CurrentRiskCalculationRead,
  FindingPriorityRead,
  LockedPriorityCalculationContext,
  PersistFindingRiskCalculationResult,
  PriorityPolicyLookup,
  PublishOrganizationPriorityOverridePersistenceResult,
  RiskCalculationFactGraphRead,
  RiskCalculationPersistencePort,
  StoredPriorityPolicyView,
  StoredRiskCalculation,
} from '@patchpilot/domain';
import { assertNever } from '@patchpilot/domain';

import {
  createRiskCalculationPersistence,
  runLockedPriorityCalculation,
} from './risk-calculation-persistence.js';

export { readRemediationQueuePage } from './remediation-queue-persistence.js';
import type {
  CurrentRiskCalculationResult,
  FindingPriorityStateResult,
  PersistRiskCalculationResult,
  PersistedRiskCalculation,
  PriorityCalculationFactGraphResult,
  PriorityPolicyReadResult,
  PublishOrganizationPriorityOverrideResult,
  StoredPriorityPolicy,
} from './risk-calculation-persistence.js';

export type RiskCalculationApplicationPersistenceOptions = {
  readonly bindKevMembership: (
    client: Prisma.TransactionClient,
    asOf: Date,
  ) => {
    readonly queryActiveKevMembership: LockedPriorityCalculationContext['queryActiveKevMembership'];
  };
};

export function createRiskCalculationApplicationPersistence(
  client: PrismaClient,
  options: RiskCalculationApplicationPersistenceOptions,
): RiskCalculationPersistencePort {
  const persistence = createRiskCalculationPersistence(client);
  return {
    async loadPriorityCalculationFactGraph(input) {
      return mapFactGraph(await persistence.loadPriorityCalculationFactGraph(input));
    },
    async findPublishedBuiltinPriorityPolicy() {
      return mapPolicy(await persistence.findPublishedBuiltinPriorityPolicy());
    },
    async findSelectedOrganizationPriorityOverride(organizationId) {
      return mapPolicy(await persistence.findSelectedOrganizationPriorityOverride(organizationId));
    },
    async findCurrentRiskCalculation(input) {
      return mapCurrent(await persistence.findCurrentRiskCalculation(input));
    },
    async readFindingPriority(input) {
      return mapFindingPriority(await persistence.readFindingPriority(input));
    },
    async persistRiskCalculation(input) {
      return mapPersist(await persistence.persist(input));
    },
    async executeLockedPriorityCalculation(scope, work) {
      const outcome = await runLockedPriorityCalculation(
        client,
        scope,
        options.bindKevMembership,
        async (raw) => {
          const decision = await work({
            asOf: raw.asOf,
            graph: mapFactGraph(raw.graph),
            builtin: mapPolicy(raw.builtin),
            override: mapPolicy(raw.override),
            current: mapCurrent(raw.current),
            queryActiveKevMembership: (input) => raw.queryActiveKevMembership(input),
          });
          if (decision.kind === 'stop') {
            return { kind: 'stop', result: decision.result };
          }
          return { kind: 'persist', command: decision.command };
        },
      );
      if (outcome.kind === 'stop') {
        return { kind: 'stop', result: outcome.result };
      }
      if (outcome.kind === 'write') {
        return { kind: 'write', result: mapPersist(outcome.result) };
      }
      return { kind: 'unavailable' };
    },
    async publishOrganizationPriorityOverride(input) {
      return mapPublish(await persistence.publishOrganizationPriorityOverride(input));
    },
  };
}

function mapFactGraph(result: PriorityCalculationFactGraphResult): RiskCalculationFactGraphRead {
  switch (result.kind) {
    case 'found':
      return {
        kind: 'found',
        asOf: result.graph.asOf,
        snapshot: result.graph.snapshot,
      };
    case 'not_found':
      return { kind: 'not_found' };
    case 'malformed':
    case 'rejected':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function mapPolicy(result: PriorityPolicyReadResult): PriorityPolicyLookup {
  switch (result.kind) {
    case 'found':
      return { kind: 'found', policy: policyView(result.policy) };
    case 'not_found':
      return { kind: 'not_found' };
    case 'malformed':
    case 'rejected':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function policyView(policy: StoredPriorityPolicy): StoredPriorityPolicyView {
  return {
    id: policy.id,
    policyKey: policy.policyKey,
    version: policy.version,
    definition: policy.definition,
  };
}

function mapFindingPriority(result: FindingPriorityStateResult): FindingPriorityRead {
  switch (result.kind) {
    case 'finding_absent':
      return { kind: 'finding_absent' };
    case 'not_calculated':
      return {
        kind: 'not_calculated',
        findingId: result.findingId,
        publishedBuiltin: result.publishedBuiltin,
      };
    case 'calculated':
      return {
        kind: 'calculated',
        findingId: result.findingId,
        publishedBuiltin: result.publishedBuiltin,
        calculation: result.calculation,
      };
    case 'malformed':
    case 'rejected':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function mapCurrent(result: CurrentRiskCalculationResult): CurrentRiskCalculationRead {
  switch (result.kind) {
    case 'found':
      return { kind: 'found', calculation: storedCalculation(result.calculation) };
    case 'not_found':
      return { kind: 'not_found' };
    case 'malformed':
    case 'rejected':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function mapPersist(result: PersistRiskCalculationResult): PersistFindingRiskCalculationResult {
  switch (result.kind) {
    case 'persisted':
      return { kind: 'persisted', calculation: storedCalculation(result.calculation) };
    case 'replay':
      return { kind: 'replay', calculation: storedCalculation(result.calculation) };
    case 'immutable_conflict':
      return { kind: 'immutable_conflict' };
    case 'not_found':
      return { kind: 'not_found' };
    case 'ineligible':
      return { kind: 'ineligible' };
    case 'policy_not_found':
    case 'policy_not_eligible':
      return { kind: 'policy_unavailable' };
    case 'authority_rejected':
      return { kind: 'unauthorized' };
    case 'rejected':
    case 'transaction_aborted':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function mapPublish(
  result: PublishOrganizationPriorityOverrideResult,
): PublishOrganizationPriorityOverridePersistenceResult {
  switch (result.kind) {
    case 'published':
      return {
        kind: 'published',
        policy: { id: result.policy.id, version: result.policy.version },
      };
    case 'membership_not_found':
      return { kind: 'membership_not_found' };
    case 'version_conflict':
      return { kind: 'version_conflict' };
    case 'rejected':
      return { kind: 'rejected' };
    case 'transaction_aborted':
    case 'database_unavailable':
    case 'internal_failure':
      return { kind: 'unavailable' };
    default:
      return assertNever(result);
  }
}

function storedCalculation(calculation: PersistedRiskCalculation): StoredRiskCalculation {
  return {
    id: calculation.id,
    organizationId: calculation.organizationId,
    findingId: calculation.findingId,
    riskPolicyId: calculation.riskPolicyId,
    policyVersion: calculation.policyVersion,
    policyDefinitionSha256: calculation.policyDefinitionSha256,
    calculatedAt: calculation.calculatedAt,
    factors: calculation.factors,
    result: calculation.result,
    calculationEngineVersion: calculation.calculationEngineVersion,
    calculationReason: calculation.calculationReason,
    inputFingerprint: calculation.inputFingerprint,
  };
}
