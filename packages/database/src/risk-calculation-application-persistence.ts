/**
 * Thin adapter from the domain risk-calculation port to the existing
 * PostgreSQL functions. The fact-graph snapshot is passed through. This
 * module does not assemble facts, hash a policy, or import the policy engine.
 * The database barrel does not construct it.
 */

import type { PrismaClient } from '@prisma/client';
import type {
  CurrentRiskCalculationRead,
  PersistFindingRiskCalculationResult,
  PriorityPolicyLookup,
  PublishOrganizationPriorityOverridePersistenceResult,
  RiskCalculationFactGraphRead,
  RiskCalculationPersistencePort,
  StoredPriorityPolicyView,
  StoredRiskCalculation,
} from '@patchpilot/domain';
import { assertNever } from '@patchpilot/domain';

import { createRiskCalculationPersistence } from './risk-calculation-persistence.js';
import type {
  CurrentRiskCalculationResult,
  PersistRiskCalculationResult,
  PersistedRiskCalculation,
  PriorityCalculationFactGraphResult,
  PriorityPolicyReadResult,
  PublishOrganizationPriorityOverrideResult,
  StoredPriorityPolicy,
} from './risk-calculation-persistence.js';

export function createRiskCalculationApplicationPersistence(
  client: PrismaClient,
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
    async persistRiskCalculation(input) {
      return mapPersist(await persistence.persist(input));
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
