/**
 * Uncomposed PostgreSQL adapter for one RiskCalculation and for organization
 * priority-policy versions.
 *
 * `runLockedPriorityCalculation` is the calculation transaction. It takes the
 * organization-scoped lock, selects the Finding FOR UPDATE, loads persisted
 * rows, and invokes the caller before insert. The caller assembles facts,
 * reads KEV through the injected query, selects the policy, and calls the
 * engine. This module then inserts the RiskCalculation and the
 * `priority.calculated` audit in that same transaction. `calculatedAt` is the
 * fact-graph `CURRENT_TIMESTAMP`. The transaction does no network or object
 * storage, does not import `@patchpilot/policy-engine`, and does not update
 * the Finding, Product Match Evidence, observations, or KEV rows.
 *
 * `persistRiskCalculation` remains a direct insert for an already evaluated
 * document. It opens its own transaction. When `calculatedAt` is omitted,
 * that transaction reads `CURRENT_TIMESTAMP` once.
 *
 * The database barrel does not construct this adapter. The API priority
 * runtime constructs the application wrapper around it.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  CANONICAL_CVE_PATTERN,
  JSON_SCHEMA_VERSION_V1,
  PRIORITY_ADVISORY_WITHDRAWN_TOKENS,
  PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS,
  PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS,
  PRIORITY_BANDS,
  PRIORITY_BUSINESS_CRITICALITY_TOKENS,
  PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_DIRECT_DEPENDENCY_TOKENS,
  PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS,
  PRIORITY_ESCALATION_REASONS,
  PRIORITY_FACTOR_EXPLANATION_CODES,
  PRIORITY_FACTOR_IDS,
  PRIORITY_FACTOR_INPUT_STATES,
  PRIORITY_FACTOR_STATUSES,
  PRIORITY_FINDING_AGE_DAYS_MAX,
  PRIORITY_FIX_AVAILABLE_TOKENS,
  PRIORITY_FIX_AVAILABLE_UNKNOWN_TOKENS,
  PRIORITY_INTERNET_EXPOSURE_TOKENS,
  PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS,
  PRIORITY_KEV_CATALOG_FRESHNESS,
  PRIORITY_KEV_OBSERVED_TOKENS,
  PRIORITY_KEV_UNAVAILABLE_REASONS,
  PRIORITY_KEV_UNKNOWN_TOKENS,
  PRIORITY_RULE_EXPLANATION_CODES,
  PRIORITY_RULE_IDS,
  PRIORITY_SEVERITY_RATINGS,
  PRIORITY_SEVERITY_UNKNOWN_TOKENS,
  RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
  RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
  UTC_INSTANT_PATTERN,
  assetDataClassifications,
  businessCriticalities,
  classifyInspectionObservationShape,
  environmentSensitivityClasses,
  findingStates,
  internetExposures,
  type FindingRiskBindingClassification,
  type FindingRiskCreationEvidence,
  type FindingRiskSourceAsset,
  type FindingRiskSourceFinding,
  type FindingRiskSourceSnapshot,
  type PriorityBand,
  type PriorityEscalationReason,
  type PriorityEvidenceSummary,
  type PriorityFactorId,
  type PriorityFactorRow,
  type PriorityRuleId,
  type PriorityRuleRow,
  type RiskCalculationFactorSourcesV2,
  type RiskCalculationFactorsV2Json,
  type RiskCalculationKevSourceV2,
  type RiskCalculationReason,
  type RiskCalculationResultV1Json,
} from '@patchpilot/domain';

import { SHA256_HEX, UUID_PATTERN } from './guards.js';

export const BUILTIN_PRIORITY_POLICY_KEY = 'patchpilot.builtin.v0' as const;
export const BUILTIN_PRIORITY_POLICY_VERSION = 2 as const;
export const PRIORITY_CALCULATION_SUBJECT_TYPE = 'finding' as const;
export const PRIORITY_CALCULATED_AUDIT_ACTION = 'priority.calculated' as const;
export const RISK_POLICY_SUBJECT_TYPE = 'risk_policy' as const;
export const RISK_POLICY_PUBLISHED_AUDIT_ACTION = 'risk_policy.published' as const;
export const ORGANIZATION_PRIORITY_OVERRIDE_NAME = 'Organization priority override' as const;

const MAX_PRIORITY_SOURCE_IDS = 128;
const MAX_FACT_GRAPH_LINKS = 256;
const MAX_FACT_GRAPH_OBSERVATIONS = 64;
const MAX_POLICY_DEFINITION_JSON_LENGTH = 65_536;
const MAX_CENTI = 100_000;
const MIN_DUE_DAYS = 1;
const MAX_DUE_DAYS = 3650;
const MAX_PRIORITY = 100;
const CATALOG_VERSION_PATTERN = /^[A-Za-z0-9._:+-]{1,128}$/;

const OBSERVED_VALUE_TOKENS: ReadonlySet<string> = new Set<string>([
  ...PRIORITY_SEVERITY_RATINGS,
  ...PRIORITY_SEVERITY_UNKNOWN_TOKENS,
  ...PRIORITY_KEV_OBSERVED_TOKENS,
  ...PRIORITY_KEV_UNKNOWN_TOKENS,
  ...PRIORITY_ENVIRONMENT_SENSITIVITY_TOKENS,
  ...PRIORITY_INTERNET_EXPOSURE_TOKENS,
  ...PRIORITY_INTERNET_EXPOSURE_UNKNOWN_TOKENS,
  ...PRIORITY_BUSINESS_CRITICALITY_TOKENS,
  ...PRIORITY_BUSINESS_CRITICALITY_UNKNOWN_TOKENS,
  ...PRIORITY_ASSET_DATA_CLASSIFICATION_TOKENS,
  ...PRIORITY_ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS,
  ...PRIORITY_DIRECT_DEPENDENCY_TOKENS,
  ...PRIORITY_FIX_AVAILABLE_TOKENS,
  ...PRIORITY_FIX_AVAILABLE_UNKNOWN_TOKENS,
  ...PRIORITY_ADVISORY_WITHDRAWN_TOKENS,
]);

const BINDING_CLASSIFICATIONS = [
  'one_cve_alias_evidence',
  'provider_native_without_cve',
] as const satisfies readonly FindingRiskBindingClassification[];

const PRINTABLE_TEXT = /^[\u0020-\u007e]+$/;

export const PERSISTABLE_RISK_CALCULATION_REASONS = [
  'initial',
  'rescan',
  'intel_refresh',
  'policy_change',
  'asset_change',
] as const satisfies readonly RiskCalculationReason[];

export type PersistableRiskCalculationReason =
  (typeof PERSISTABLE_RISK_CALCULATION_REASONS)[number];

type NonPersistableRiskCalculationReason = Exclude<
  RiskCalculationReason,
  PersistableRiskCalculationReason
>;

export const REJECTED_RISK_CALCULATION_REASONS = [
  'manual_override',
  'manual_recalc',
] as const satisfies readonly NonPersistableRiskCalculationReason[];

type UnlistedRiskCalculationReason = Exclude<
  NonPersistableRiskCalculationReason,
  (typeof REJECTED_RISK_CALCULATION_REASONS)[number]
>;

const RISK_CALCULATION_REASONS_COVERED: UnlistedRiskCalculationReason extends never ? true : never =
  true;
void RISK_CALCULATION_REASONS_COVERED;

export const PRIORITY_CALCULATED_AUDIT_PAYLOAD_KEYS = [
  'schemaVersion',
  'findingId',
  'riskCalculationId',
  'riskPolicyId',
  'priorityBand',
] as const;

export type PriorityCalculatedAuditPayload = {
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  readonly findingId: string;
  readonly riskCalculationId: string;
  readonly riskPolicyId: string;
  readonly priorityBand: PriorityBand;
};

type PriorityCalculatedAuditDrift =
  | Exclude<
      keyof PriorityCalculatedAuditPayload,
      (typeof PRIORITY_CALCULATED_AUDIT_PAYLOAD_KEYS)[number]
    >
  | Exclude<
      (typeof PRIORITY_CALCULATED_AUDIT_PAYLOAD_KEYS)[number],
      keyof PriorityCalculatedAuditPayload
    >;

const PRIORITY_CALCULATED_AUDIT_KEYS_ALIGNED: PriorityCalculatedAuditDrift extends never
  ? true
  : never = true;
void PRIORITY_CALCULATED_AUDIT_KEYS_ALIGNED;

export const RISK_POLICY_PUBLISHED_AUDIT_PAYLOAD_KEYS = [
  'schemaVersion',
  'riskPolicyId',
  'policyKey',
  'policyVersion',
  'policySchemaVersion',
] as const;

export type RiskPolicyPublishedAuditPayload = {
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  readonly riskPolicyId: string;
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly policyVersion: number;
  readonly policySchemaVersion: typeof RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2;
};

type RiskPolicyPublishedAuditDrift =
  | Exclude<
      keyof RiskPolicyPublishedAuditPayload,
      (typeof RISK_POLICY_PUBLISHED_AUDIT_PAYLOAD_KEYS)[number]
    >
  | Exclude<
      (typeof RISK_POLICY_PUBLISHED_AUDIT_PAYLOAD_KEYS)[number],
      keyof RiskPolicyPublishedAuditPayload
    >;

const RISK_POLICY_PUBLISHED_AUDIT_KEYS_ALIGNED: RiskPolicyPublishedAuditDrift extends never
  ? true
  : never = true;
void RISK_POLICY_PUBLISHED_AUDIT_KEYS_ALIGNED;

export const PERSIST_RISK_CALCULATION_REJECTION_REASONS = [
  'malformed_id',
  'malformed_hash',
  'malformed_document',
  'malformed_timestamp',
  'malformed_correlation',
  'calculation_reason',
] as const;

export type PersistRiskCalculationRejection =
  (typeof PERSIST_RISK_CALCULATION_REJECTION_REASONS)[number];

export type PersistedRiskCalculation = {
  readonly id: string;
  readonly organizationId: string;
  readonly findingId: string;
  readonly riskPolicyId: string;
  readonly policyVersion: number;
  readonly policyDefinitionSha256: string;
  readonly calculatedAt: Date;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly calculationEngineVersion: typeof PRIORITY_CALCULATION_ENGINE_VERSION;
  readonly calculationReason: PersistableRiskCalculationReason;
  readonly inputFingerprint: string;
};

export type PersistRiskCalculationResult =
  | { readonly kind: 'persisted'; readonly calculation: PersistedRiskCalculation }
  | { readonly kind: 'replay'; readonly calculation: PersistedRiskCalculation }
  | { readonly kind: 'immutable_conflict' }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'ineligible' }
  | { readonly kind: 'policy_not_found' }
  | { readonly kind: 'policy_not_eligible' }
  | { readonly kind: 'authority_rejected' }
  | { readonly kind: 'rejected'; readonly reason: PersistRiskCalculationRejection }
  | { readonly kind: 'transaction_aborted' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

/**
 * `calculatedAt` is optional. When present, it is the database timestamp
 * already used for finding age and is stored unchanged. When absent, the
 * transaction reads `CURRENT_TIMESTAMP` once.
 */
export type PersistRiskCalculationInput = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly findingId: string;
  readonly riskPolicyId: string;
  readonly policyDefinitionSha256: string;
  readonly inputFingerprint: string;
  readonly calculationReason: string;
  readonly factors: unknown;
  readonly result: unknown;
  readonly correlationId: string;
  readonly calculatedAt?: Date;
};

export const PUBLISH_PRIORITY_OVERRIDE_REJECTION_REASONS = [
  'malformed_id',
  'malformed_definition',
  'policy_key',
  'policy_schema_version',
] as const;

export type PublishPriorityOverrideRejection =
  (typeof PUBLISH_PRIORITY_OVERRIDE_REJECTION_REASONS)[number];

export type StoredPriorityPolicy = {
  readonly id: string;
  readonly organizationId: string | null;
  readonly scope: 'builtin' | 'organization';
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly name: string;
  readonly version: number;
  readonly status: 'published';
  readonly policySchemaVersion: typeof RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2;
  readonly definition: Readonly<Record<string, unknown>>;
  readonly publishedAt: Date;
  readonly createdByMembershipId: string | null;
};

export type PublishOrganizationPriorityOverrideInput = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly definition: unknown;
  readonly policySchemaVersion: number;
  readonly policyKey: string;
};

export type PublishOrganizationPriorityOverrideResult =
  | { readonly kind: 'published'; readonly policy: StoredPriorityPolicy }
  | { readonly kind: 'membership_not_found' }
  | { readonly kind: 'version_conflict' }
  | { readonly kind: 'rejected'; readonly reason: PublishPriorityOverrideRejection }
  | { readonly kind: 'transaction_aborted' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

export type PriorityPolicyReadResult =
  | { readonly kind: 'found'; readonly policy: StoredPriorityPolicy }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'rejected'; readonly reason: 'malformed_id' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

export type CurrentRiskCalculationQuery = {
  readonly organizationId: string;
  readonly findingId: string;
};

export type CurrentRiskCalculationResult =
  | { readonly kind: 'found'; readonly calculation: PersistedRiskCalculation }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'rejected'; readonly reason: 'malformed_id' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

/**
 * Read-only rows for `FindingRiskSourceSnapshot`. This loader does not create
 * fact tokens. `asOf` is the transaction `CURRENT_TIMESTAMP`. Pass `snapshot`
 * to fact assembly and pass this same `asOf` to `persistRiskCalculation` as
 * `calculatedAt` when age was computed from it.
 */
export type PriorityCalculationFactGraph = {
  readonly asOf: Date;
  readonly snapshot: FindingRiskSourceSnapshot;
};

export type PriorityCalculationFactGraphResult =
  | { readonly kind: 'found'; readonly graph: PriorityCalculationFactGraph }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'rejected'; readonly reason: 'malformed_id' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

type DatabaseFailureKind = 'database_unavailable' | 'transaction_aborted' | 'internal_failure';

type NormalizedPersist = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly findingId: string;
  readonly riskPolicyId: string;
  readonly policyDefinitionSha256: string;
  readonly inputFingerprint: string;
  readonly calculationReason: PersistableRiskCalculationReason;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly factorsJson: string;
  readonly resultJson: string;
  readonly correlationId: string;
  readonly calculatedAt: Date | null;
};

type CalculationRow = {
  id: string;
  organization_id: string;
  finding_id: string;
  risk_policy_id: string;
  policy_version: number | bigint;
  policy_definition_sha256: string;
  calculated_at: Date | string;
  factors: unknown;
  result: unknown;
  calculation_engine_version: string;
  calculation_reason: string;
  input_fingerprint: string;
};

type ComparisonRow = CalculationRow & {
  hash_matches: unknown;
  factors_match: unknown;
  result_match: unknown;
  engine_matches: unknown;
};

type PolicyRow = {
  id: string;
  organization_id: string | null;
  scope: string;
  policy_key: string;
  name: string;
  version: number | bigint;
  status: string;
  policy_schema_version: number | bigint;
  definition: unknown;
  published_at: Date | string | null;
  created_by_membership_id: string | null;
};

class PersistenceAbort extends Error {
  constructor(readonly failure: 'internal_failure' | 'transaction_aborted') {
    super('risk calculation persistence aborted');
  }
}

export function createRiskCalculationPersistence(client: PrismaClient) {
  return {
    persist(input: PersistRiskCalculationInput) {
      return persistRiskCalculation(client, input);
    },
    publishOrganizationPriorityOverride(input: PublishOrganizationPriorityOverrideInput) {
      return publishOrganizationPriorityOverride(client, input);
    },
    findPublishedBuiltinPriorityPolicy() {
      return findPublishedBuiltinPriorityPolicy(client);
    },
    findSelectedOrganizationPriorityOverride(organizationId: string) {
      return findSelectedOrganizationPriorityOverride(client, organizationId);
    },
    findCurrentRiskCalculation(input: CurrentRiskCalculationQuery) {
      return findCurrentRiskCalculation(client, input);
    },
    readFindingPriority(input: CurrentRiskCalculationQuery) {
      return readFindingPriorityState(client, input);
    },
    loadPriorityCalculationFactGraph(input: CurrentRiskCalculationQuery) {
      return loadPriorityCalculationFactGraph(client, input);
    },
  };
}

export async function persistRiskCalculation(
  client: PrismaClient,
  input: PersistRiskCalculationInput,
): Promise<PersistRiskCalculationResult> {
  const normalized = normalizePersistInput(input);
  if (normalized.kind === 'rejected') {
    return normalized;
  }
  try {
    return await client.$transaction((tx) => persistInTransaction(tx, normalized.command), {
      isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
    });
  } catch (error) {
    const aborted = abortedResult(error);
    if (aborted !== null) {
      return aborted;
    }
    if (isUniqueViolation(error)) {
      return reloadReplay(client, normalized.command);
    }
    const failure = classifyDatabaseFailure(error);
    if (failure !== null) {
      return { kind: failure };
    }
    throw error;
  }
}

type PrioritySqlClient = PrismaClient | Prisma.TransactionClient;

type LockedPriorityCalculationScopeInput = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly findingId: string;
};

export type LockedPriorityCalculationWorkContext<
  TQuery extends (input: unknown) => Promise<unknown>,
> = {
  readonly asOf: Date | null;
  readonly graph: PriorityCalculationFactGraphResult;
  readonly builtin: PriorityPolicyReadResult;
  readonly override: PriorityPolicyReadResult;
  readonly current: CurrentRiskCalculationResult;
  readonly queryActiveKevMembership: TQuery;
};

type LockedPriorityCalculationWorkDecision<TStop> =
  | { readonly kind: 'persist'; readonly command: PersistRiskCalculationInput }
  | { readonly kind: 'stop'; readonly result: TStop };

type LockedTransactionResult<TStop> =
  | { readonly kind: 'write'; readonly result: PersistRiskCalculationResult }
  | { readonly kind: 'stop'; readonly result: TStop }
  | { readonly kind: 'internal_failure' };

export type RunLockedPriorityCalculationResult<TStop> =
  | LockedTransactionResult<TStop>
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'transaction_aborted' };

/**
 * One calculation transaction: organization lock, Finding `FOR UPDATE`,
 * persisted reads, caller work, then calculation insert and audit.
 * `bindKevMembership` must query through the transaction client it receives.
 * A thrown audit or constraint error rolls the calculation insert back with
 * the audit. `calculatedAt` is the fact-graph database timestamp.
 */
export async function runLockedPriorityCalculation<
  TStop,
  TQuery extends (input: unknown) => Promise<unknown>,
>(
  client: PrismaClient,
  scope: LockedPriorityCalculationScopeInput,
  bindKevMembership: (
    client: Prisma.TransactionClient,
    asOf: Date,
  ) => { readonly queryActiveKevMembership: TQuery },
  work: (
    context: LockedPriorityCalculationWorkContext<TQuery>,
  ) => Promise<LockedPriorityCalculationWorkDecision<TStop>>,
): Promise<RunLockedPriorityCalculationResult<TStop>> {
  const organizationId = normalizeUuid(scope.organizationId);
  const actorUserId = normalizeUuid(scope.actorUserId);
  const membershipId = normalizeUuid(scope.membershipId);
  const findingId = normalizeUuid(scope.findingId);
  if (
    organizationId === null ||
    actorUserId === null ||
    membershipId === null ||
    findingId === null
  ) {
    return { kind: 'write', result: { kind: 'rejected', reason: 'malformed_id' } };
  }
  let replayCommand: NormalizedPersist | null = null;
  try {
    return await client.$transaction(
      async (tx): Promise<LockedTransactionResult<TStop>> => {
        await lockTransactionScope(tx, `${organizationId}:${findingId}`);
        const actor = await loadActor(tx, organizationId, membershipId, actorUserId);
        if (actor === null || actor !== actorUserId) {
          return { kind: 'write', result: { kind: 'authority_rejected' } };
        }
        await loadFindingForUpdate(tx, organizationId, findingId);
        const graph = await loadFactGraph(tx, organizationId, findingId);
        const graphAsOf = graph.kind === 'found' ? graph.graph.asOf : null;
        const builtin = await queryPublishedBuiltinPriorityPolicy(tx);
        const override = await querySelectedOrganizationPriorityOverride(tx, organizationId);
        const current = await queryCurrentRiskCalculation(tx, organizationId, findingId);
        const kevClock = graphAsOf ?? (await readDatabaseNow(tx));
        const kev = bindKevMembership(tx, kevClock);
        if (typeof kev.queryActiveKevMembership !== 'function') {
          return { kind: 'internal_failure' };
        }
        const queryActiveKevMembership: TQuery = kev.queryActiveKevMembership;
        const decision = await work({
          asOf: graphAsOf,
          graph,
          builtin,
          override,
          current,
          queryActiveKevMembership,
        });
        if (decision.kind === 'stop') {
          return { kind: 'stop', result: decision.result };
        }
        if (graphAsOf === null) {
          return { kind: 'internal_failure' };
        }
        const normalized = normalizePersistInput(decision.command);
        if (normalized.kind === 'rejected') {
          return { kind: 'write', result: normalized };
        }
        if (
          normalized.command.organizationId !== organizationId ||
          normalized.command.actorUserId !== actorUserId ||
          normalized.command.membershipId !== membershipId ||
          normalized.command.findingId !== findingId
        ) {
          return { kind: 'write', result: { kind: 'authority_rejected' } };
        }
        if (
          normalized.command.calculatedAt === null ||
          normalized.command.calculatedAt.getTime() !== graphAsOf.getTime()
        ) {
          return {
            kind: 'write',
            result: { kind: 'rejected', reason: 'malformed_timestamp' },
          };
        }
        const command = { ...normalized.command, calculatedAt: graphAsOf };
        replayCommand = command;
        return {
          kind: 'write',
          result: await persistInTransaction(tx, command),
        };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
    );
  } catch (error) {
    const aborted = abortedResult(error);
    if (aborted !== null) {
      return aborted;
    }
    if (isUniqueViolation(error) && replayCommand !== null) {
      return { kind: 'write', result: await reloadReplay(client, replayCommand) };
    }
    const failure = classifyDatabaseFailure(error);
    if (failure !== null) {
      return { kind: failure };
    }
    throw error;
  }
}

/**
 * Inserts a new published organization policy version. It does not update a
 * published row and does not validate weights. The next version is
 * max(existing versions for this organization and `patchpilot.builtin.v0`) + 1,
 * or 1 when none exist. A later call inserts another version.
 */
export async function publishOrganizationPriorityOverride(
  client: PrismaClient,
  input: PublishOrganizationPriorityOverrideInput,
): Promise<PublishOrganizationPriorityOverrideResult> {
  const normalized = normalizeOverrideInput(input);
  if (normalized.kind === 'rejected') {
    return normalized;
  }
  try {
    return await client.$transaction((tx) => publishInTransaction(tx, normalized.command), {
      isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
    });
  } catch (error) {
    const aborted = abortedResult(error);
    if (aborted !== null) {
      return aborted;
    }
    if (isUniqueViolation(error)) {
      return { kind: 'version_conflict' };
    }
    const failure = classifyDatabaseFailure(error);
    if (failure !== null) {
      return { kind: failure };
    }
    throw error;
  }
}

/** Builtin `patchpilot.builtin.v0` version 2 only. Version 1 is never selected. */
export async function findPublishedBuiltinPriorityPolicy(
  client: PrismaClient,
): Promise<PriorityPolicyReadResult> {
  try {
    return await queryPublishedBuiltinPriorityPolicy(client);
  } catch (error) {
    return mapReadFailure(error);
  }
}

/**
 * Greatest published version for the trusted organization and
 * `patchpilot.builtin.v0`. Other keys and retired rows are ignored.
 * A published row whose document is not schema version 2 is `malformed`
 * and is not replaced by an older version.
 */
export async function findSelectedOrganizationPriorityOverride(
  client: PrismaClient,
  organizationId: string,
): Promise<PriorityPolicyReadResult> {
  const organization = normalizeUuid(organizationId);
  if (organization === null) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  try {
    return await querySelectedOrganizationPriorityOverride(client, organization);
  } catch (error) {
    return mapReadFailure(error);
  }
}

/**
 * Latest calculation for the trusted organization and Finding, ordered by
 * `calculated_at` then `id`. Read only: no audit row and no Finding update.
 */
export async function findCurrentRiskCalculation(
  client: PrismaClient,
  input: CurrentRiskCalculationQuery,
): Promise<CurrentRiskCalculationResult> {
  const organizationId = normalizeUuid(input.organizationId);
  const findingId = normalizeUuid(input.findingId);
  if (organizationId === null || findingId === null) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  try {
    return await queryCurrentRiskCalculation(client, organizationId, findingId);
  } catch (error) {
    return mapReadFailure(error);
  }
}

export async function loadPriorityCalculationFactGraph(
  client: PrismaClient,
  input: CurrentRiskCalculationQuery,
): Promise<PriorityCalculationFactGraphResult> {
  const organizationId = normalizeUuid(input.organizationId);
  const findingId = normalizeUuid(input.findingId);
  if (organizationId === null || findingId === null) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  try {
    return await client.$transaction((tx) => loadFactGraph(tx, organizationId, findingId), {
      isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
    });
  } catch (error) {
    if (abortedResult(error) !== null) {
      return { kind: 'internal_failure' };
    }
    return mapReadFailure(error);
  }
}

async function persistInTransaction(
  tx: Prisma.TransactionClient,
  command: NormalizedPersist,
): Promise<PersistRiskCalculationResult> {
  await lockTransactionScope(tx, `${command.organizationId}:${command.findingId}`);
  const actor = await loadActor(
    tx,
    command.organizationId,
    command.membershipId,
    command.actorUserId,
  );
  if (actor === null || actor !== command.actorUserId) {
    return { kind: 'authority_rejected' };
  }
  const finding = await loadFindingForUpdate(tx, command.organizationId, command.findingId);
  if (finding.kind === 'not_found') {
    return { kind: 'not_found' };
  }
  if (finding.kind === 'ineligible') {
    return { kind: 'ineligible' };
  }
  const policy = await loadVisiblePolicy(tx, command.organizationId, command.riskPolicyId);
  if (policy.kind === 'policy_not_found' || policy.kind === 'policy_not_eligible') {
    return policy;
  }
  const calculatedAt =
    command.calculatedAt === null ? await readDatabaseNow(tx) : command.calculatedAt;
  const existing = await findByFingerprint(tx, command);
  if (existing !== null) {
    return replayFromRow(existing);
  }
  const creationEligible = await loadCreationInsertEligible(
    tx,
    command.organizationId,
    command.findingId,
  );
  if (creationEligible === null) {
    throw new PersistenceAbort('internal_failure');
  }
  if (!creationEligible) {
    return { kind: 'ineligible' };
  }
  const prior = await tx.$queryRaw<Array<{ present: boolean }>>`
    SELECT EXISTS (
      SELECT 1
      FROM "risk_calculation"
      WHERE "organization_id" = ${command.organizationId}::uuid
        AND "finding_id" = ${command.findingId}::uuid
    ) AS "present"
  `;
  const present = prior[0]?.present;
  if (typeof present !== 'boolean') {
    throw new PersistenceAbort('internal_failure');
  }
  const initialAllowed = !present && command.calculationReason === 'initial';
  const laterAllowed = present && command.calculationReason !== 'initial';
  if (!initialAllowed && !laterAllowed) {
    return { kind: 'rejected', reason: 'calculation_reason' };
  }
  const inserted = await tx.$queryRaw<CalculationRow[]>`
    INSERT INTO "risk_calculation" (
      "organization_id",
      "finding_id",
      "risk_policy_id",
      "policy_version",
      "policy_definition_sha256",
      "calculated_at",
      "factors",
      "result",
      "calculation_engine_version",
      "calculation_reason",
      "input_fingerprint"
    )
    VALUES (
      ${command.organizationId}::uuid,
      ${command.findingId}::uuid,
      ${policy.policy.id}::uuid,
      ${policy.policy.version}::int,
      ${command.policyDefinitionSha256},
      ${calculatedAt},
      ${command.factorsJson}::jsonb,
      ${command.resultJson}::jsonb,
      ${PRIORITY_CALCULATION_ENGINE_VERSION},
      ${command.calculationReason}::"risk_calculation_reason",
      ${command.inputFingerprint}
    )
    RETURNING
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "finding_id"::text AS "finding_id",
      "risk_policy_id"::text AS "risk_policy_id",
      "policy_version"::int AS "policy_version",
      btrim("policy_definition_sha256") AS "policy_definition_sha256",
      "calculated_at",
      "factors",
      "result",
      "calculation_engine_version",
      "calculation_reason"::text AS "calculation_reason",
      btrim("input_fingerprint") AS "input_fingerprint"
  `;
  const row = inserted[0];
  if (row === undefined || inserted.length !== 1) {
    throw new PersistenceAbort('internal_failure');
  }
  const calculation = mapCalculationRow(row);
  if (
    calculation === null ||
    calculation.organizationId !== command.organizationId ||
    calculation.findingId !== command.findingId ||
    calculation.riskPolicyId !== policy.policy.id ||
    calculation.policyVersion !== policy.policy.version
  ) {
    throw new PersistenceAbort('internal_failure');
  }
  const payload = priorityCalculatedPayload(calculation);
  await tx.$executeRaw`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    )
    VALUES (
      ${command.organizationId}::uuid,
      ${command.actorUserId}::uuid,
      ${command.membershipId}::uuid,
      'user'::"audit_actor_type",
      ${PRIORITY_CALCULATED_AUDIT_ACTION},
      ${PRIORITY_CALCULATION_SUBJECT_TYPE},
      ${calculation.findingId}::uuid,
      ${command.correlationId},
      ${JSON.stringify(payload)}::jsonb,
      ${JSON_SCHEMA_VERSION_V1}::int,
      'security'::"audit_retention_category"
    )
  `;
  return { kind: 'persisted', calculation };
}

async function publishInTransaction(
  tx: Prisma.TransactionClient,
  command: {
    readonly organizationId: string;
    readonly actorUserId: string;
    readonly membershipId: string;
    readonly definition: Readonly<Record<string, unknown>>;
    readonly definitionJson: string;
  },
): Promise<PublishOrganizationPriorityOverrideResult> {
  await lockTransactionScope(tx, `${command.organizationId}:${BUILTIN_PRIORITY_POLICY_KEY}`);
  const actor = await loadActor(
    tx,
    command.organizationId,
    command.membershipId,
    command.actorUserId,
  );
  if (actor === null || actor !== command.actorUserId) {
    return { kind: 'membership_not_found' };
  }
  const inserted = await tx.$queryRaw<
    Array<{
      id: string;
      version: number | bigint;
      published_at: Date | string;
      definition: unknown;
    }>
  >`
    INSERT INTO "risk_policy" (
      "organization_id",
      "scope",
      "policy_key",
      "name",
      "version",
      "status",
      "policy_schema_version",
      "definition",
      "published_at",
      "created_by_membership_id"
    )
    SELECT
      ${command.organizationId}::uuid,
      'organization'::"risk_policy_scope",
      ${BUILTIN_PRIORITY_POLICY_KEY},
      ${ORGANIZATION_PRIORITY_OVERRIDE_NAME},
      COALESCE((
        SELECT MAX("version")
        FROM "risk_policy"
        WHERE "organization_id" = ${command.organizationId}::uuid
          AND "policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
      ), 0) + 1,
      'published'::"risk_policy_status",
      ${RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2}::int,
      ${command.definitionJson}::jsonb,
      CURRENT_TIMESTAMP,
      ${command.membershipId}::uuid
    RETURNING
      "id"::text AS "id",
      "version"::int AS "version",
      "published_at",
      "definition"
  `;
  const row = inserted[0];
  if (row === undefined || inserted.length !== 1) {
    throw new PersistenceAbort('internal_failure');
  }
  const version = readInt(row.version);
  const publishedAt = readTimestamp(row.published_at);
  const definition = readStoredDefinition(row.definition);
  const id = normalizeUuid(row.id);
  if (
    version === null ||
    version < 1 ||
    publishedAt === null ||
    definition === null ||
    id === null
  ) {
    throw new PersistenceAbort('internal_failure');
  }
  const policy: StoredPriorityPolicy = {
    id,
    organizationId: command.organizationId,
    scope: 'organization',
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    name: ORGANIZATION_PRIORITY_OVERRIDE_NAME,
    version,
    status: 'published',
    policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
    definition,
    publishedAt,
    createdByMembershipId: command.membershipId,
  };
  const payload: RiskPolicyPublishedAuditPayload = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    riskPolicyId: policy.id,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    policyVersion: policy.version,
    policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
  };
  await tx.$executeRaw`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    )
    VALUES (
      ${command.organizationId}::uuid,
      ${actor}::uuid,
      ${command.membershipId}::uuid,
      'user'::"audit_actor_type",
      ${RISK_POLICY_PUBLISHED_AUDIT_ACTION},
      ${RISK_POLICY_SUBJECT_TYPE},
      ${policy.id}::uuid,
      ${policy.id},
      ${JSON.stringify(payload)}::jsonb,
      ${JSON_SCHEMA_VERSION_V1}::int,
      'security'::"audit_retention_category"
    )
  `;
  return { kind: 'published', policy };
}

async function reloadReplay(
  client: PrismaClient,
  command: NormalizedPersist,
): Promise<PersistRiskCalculationResult> {
  try {
    return await client.$transaction(
      async (tx) => {
        await lockTransactionScope(tx, `${command.organizationId}:${command.findingId}`);
        const existing = await findByFingerprint(tx, command);
        if (existing === null) {
          return { kind: 'transaction_aborted' as const };
        }
        return replayFromRow(existing);
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
    );
  } catch (error) {
    const aborted = abortedResult(error);
    if (aborted !== null) {
      return aborted;
    }
    const failure = classifyDatabaseFailure(error);
    if (failure !== null) {
      return { kind: failure };
    }
    throw error;
  }
}

async function loadFactGraph(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<PriorityCalculationFactGraphResult> {
  const findings = await tx.$queryRaw<
    Array<{
      as_of: Date | string;
      id: string;
      asset_id: string;
      state: string;
      version: number | bigint;
      first_observed_at: Date | string;
      due_at: Date | string | null;
      current_risk_calculation_id: string | null;
      asset_row_id: string | null;
      environment_id: string | null;
      sensitivity_class: string | null;
      internet_exposure: string | null;
      business_criticality: string | null;
      data_classification: string | null;
    }>
  >`
    SELECT
      CURRENT_TIMESTAMP AS "as_of",
      finding."id"::text AS "id",
      finding."asset_id"::text AS "asset_id",
      finding."state"::text AS "state",
      finding."version"::int AS "version",
      finding."first_observed_at" AS "first_observed_at",
      finding."due_at" AS "due_at",
      finding."current_risk_calculation_id"::text AS "current_risk_calculation_id",
      asset."id"::text AS "asset_row_id",
      asset."environment_id"::text AS "environment_id",
      environment."sensitivity_class"::text AS "sensitivity_class",
      asset."internet_exposure"::text AS "internet_exposure",
      asset."business_criticality"::text AS "business_criticality",
      asset."data_classification"::text AS "data_classification"
    FROM "finding" AS finding
    LEFT JOIN "asset" AS asset
      ON asset."organization_id" = finding."organization_id"
     AND asset."id" = finding."asset_id"
    LEFT JOIN "environment" AS environment
      ON environment."organization_id" = asset."organization_id"
     AND environment."id" = asset."environment_id"
    WHERE finding."organization_id" = ${organizationId}::uuid
      AND finding."id" = ${findingId}::uuid
  `;
  const finding = findings[0];
  if (finding === undefined) {
    return { kind: 'not_found' };
  }
  if (findings.length !== 1) {
    throw new PersistenceAbort('internal_failure');
  }
  const graphHead = mapFactGraphHead(finding, organizationId, findingId);
  if (graphHead === null) {
    return { kind: 'malformed' };
  }
  const counts = await tx.$queryRaw<Array<{ links: number | bigint }>>`
    SELECT COUNT(*)::int AS "links"
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
  `;
  const linkCount = readInt(counts[0]?.links);
  if (linkCount === null) {
    throw new PersistenceAbort('internal_failure');
  }
  if (linkCount > MAX_FACT_GRAPH_LINKS) {
    return { kind: 'malformed' };
  }
  const hasControlledCreationObservation = await loadHasControlledCreationObservation(
    tx,
    organizationId,
    findingId,
  );
  if (hasControlledCreationObservation === null) {
    return { kind: 'malformed' };
  }
  if (linkCount === 0) {
    return {
      kind: 'found',
      graph: {
        asOf: graphHead.asOf,
        snapshot: {
          finding: graphHead.finding,
          asset: graphHead.asset,
          creationEvidence: [],
          hasControlledCreationObservation,
        },
      },
    };
  }
  const links = await tx.$queryRaw<
    Array<{
      evidence_id: string;
      component_occurrence_id: string;
      vulnerability_id: string;
      sbom_ingestion_id: string;
      is_direct: boolean | null;
      advisory_revision_id: string;
      withdrawal_classification: string;
      binding_classification: string | null;
    }>
  >`
    SELECT
      link."product_match_evaluation_evidence_id"::text AS "evidence_id",
      link."component_occurrence_id"::text AS "component_occurrence_id",
      link."vulnerability_id"::text AS "vulnerability_id",
      link."sbom_ingestion_id"::text AS "sbom_ingestion_id",
      occurrence."is_direct" AS "is_direct",
      evidence."advisory_revision_id"::text AS "advisory_revision_id",
      revision."withdrawal_classification"::text AS "withdrawal_classification",
      binding."binding_classification"::text AS "binding_classification"
    FROM "finding_creation_evidence_link" AS link
    JOIN "product_match_evaluation_evidence" AS evidence
      ON evidence."organization_id" = link."organization_id"
     AND evidence."id" = link."product_match_evaluation_evidence_id"
     AND evidence."component_occurrence_id" = link."component_occurrence_id"
    JOIN "component_occurrence" AS occurrence
      ON occurrence."organization_id" = link."organization_id"
     AND occurrence."id" = link."component_occurrence_id"
    JOIN "advisory_revision" AS revision
      ON revision."id" = evidence."advisory_revision_id"
    LEFT JOIN "advisory_vulnerability_binding" AS binding
      ON binding."advisory_revision_id" = revision."id"
    WHERE link."organization_id" = ${organizationId}::uuid
      AND link."finding_id" = ${findingId}::uuid
    ORDER BY link."product_match_evaluation_evidence_id"
  `;
  if (links.length !== linkCount) {
    return { kind: 'malformed' };
  }
  const revisionIds: string[] = [];
  for (const link of links) {
    const revisionId = normalizeUuid(link.advisory_revision_id);
    if (revisionId === null) {
      return { kind: 'malformed' };
    }
    revisionIds.push(revisionId);
  }
  const uniqueRevisionIds = distinctIds(revisionIds);
  const aliasRows = await tx.$queryRaw<
    Array<{ advisory_revision_id: string; alias_value: string }>
  >`
    SELECT
      "advisory_revision_id"::text AS "advisory_revision_id",
      "alias_value"
    FROM "advisory_revision_alias"
    WHERE "alias_type" = 'canonical_cve'::"advisory_alias_type"
      AND "advisory_revision_id" IN (${Prisma.join(
        uniqueRevisionIds.map((id) => Prisma.sql`${id}::uuid`),
      )})
    ORDER BY "advisory_revision_id", "ordinal"
  `;
  const aliases = groupAliases(aliasRows);
  if (aliases === null) {
    return { kind: 'malformed' };
  }
  const creationEvidence: FindingRiskCreationEvidence[] = [];
  for (const link of links) {
    const mapped = mapCreationEvidence(link, aliases);
    if (mapped === null) {
      return { kind: 'malformed' };
    }
    creationEvidence.push(mapped);
  }
  return {
    kind: 'found',
    graph: {
      asOf: graphHead.asOf,
      snapshot: {
        finding: graphHead.finding,
        asset: graphHead.asset,
        creationEvidence,
        hasControlledCreationObservation,
      },
    },
  };
}

function mapFactGraphHead(
  row: {
    readonly as_of: Date | string;
    readonly id: string;
    readonly asset_id: string;
    readonly state: string;
    readonly version: number | bigint;
    readonly first_observed_at: Date | string;
    readonly due_at: Date | string | null;
    readonly current_risk_calculation_id: string | null;
    readonly asset_row_id: string | null;
    readonly environment_id: string | null;
    readonly sensitivity_class: string | null;
    readonly internet_exposure: string | null;
    readonly business_criticality: string | null;
    readonly data_classification: string | null;
  },
  organizationId: string,
  findingId: string,
): {
  readonly asOf: Date;
  readonly finding: FindingRiskSourceFinding;
  readonly asset: FindingRiskSourceAsset;
} | null {
  const asOf = readTimestamp(row.as_of);
  const id = normalizeUuid(row.id);
  const assetId = normalizeUuid(row.asset_id);
  const version = readInt(row.version);
  const firstObservedAt = readTimestamp(row.first_observed_at);
  const dueAt = readNullableTimestamp(row.due_at);
  const currentRiskCalculationId = readNullableUuid(row.current_risk_calculation_id);
  if (
    asOf === null ||
    id !== findingId ||
    assetId === null ||
    version === null ||
    firstObservedAt === null ||
    dueAt === undefined ||
    currentRiskCalculationId === undefined ||
    !isOneOf(row.state, findingStates) ||
    row.asset_row_id === null
  ) {
    return null;
  }
  const assetRowId = normalizeUuid(row.asset_row_id);
  const environmentId = readNullableUuid(row.environment_id);
  if (assetRowId !== assetId || environmentId === undefined) {
    return null;
  }
  if (!isOneOf(row.internet_exposure, internetExposures)) {
    return null;
  }
  if (!isOneOf(row.business_criticality, businessCriticalities)) {
    return null;
  }
  if (!isOneOf(row.data_classification, assetDataClassifications)) {
    return null;
  }
  let sensitivityClass: FindingRiskSourceAsset['sensitivityClass'];
  if (environmentId === null) {
    sensitivityClass = null;
  } else if (isOneOf(row.sensitivity_class, environmentSensitivityClasses)) {
    sensitivityClass = row.sensitivity_class;
  } else {
    return null;
  }
  return {
    asOf,
    finding: {
      id,
      organizationId,
      state: row.state,
      version,
      firstObservedAt,
      currentRiskCalculationId,
      dueAt,
      assetId,
    },
    asset: {
      sensitivityClass,
      internetExposure: row.internet_exposure,
      businessCriticality: row.business_criticality,
      dataClassification: row.data_classification,
    },
  };
}

function mapCreationEvidence(
  row: {
    readonly evidence_id: string;
    readonly component_occurrence_id: string;
    readonly vulnerability_id: string;
    readonly sbom_ingestion_id: string;
    readonly is_direct: boolean | null;
    readonly advisory_revision_id: string;
    readonly withdrawal_classification: string;
    readonly binding_classification: string | null;
  },
  aliases: ReadonlyMap<string, readonly string[]>,
): FindingRiskCreationEvidence | null {
  const evidenceId = normalizeUuid(row.evidence_id);
  const componentOccurrenceId = normalizeUuid(row.component_occurrence_id);
  const vulnerabilityId = normalizeUuid(row.vulnerability_id);
  const sbomIngestionId = normalizeUuid(row.sbom_ingestion_id);
  const advisoryRevisionId = normalizeUuid(row.advisory_revision_id);
  if (
    evidenceId === null ||
    componentOccurrenceId === null ||
    vulnerabilityId === null ||
    sbomIngestionId === null ||
    advisoryRevisionId === null
  ) {
    return null;
  }
  if (row.is_direct !== null && typeof row.is_direct !== 'boolean') {
    return null;
  }
  if (!isOneOf(row.withdrawal_classification, PRIORITY_ADVISORY_WITHDRAWN_TOKENS)) {
    return null;
  }
  if (!isOneOf(row.binding_classification, BINDING_CLASSIFICATIONS)) {
    return null;
  }
  return {
    evidenceId,
    advisoryRevisionId,
    componentOccurrenceId,
    vulnerabilityId,
    sbomIngestionId,
    isDirect: row.is_direct,
    withdrawalClassification: row.withdrawal_classification,
    bindingClassification: row.binding_classification,
    canonicalCves: aliases.get(advisoryRevisionId) ?? [],
  };
}

function groupAliases(
  rows: readonly { readonly advisory_revision_id: string; readonly alias_value: string }[],
): Map<string, readonly string[]> | null {
  const grouped = new Map<string, string[]>();
  for (const row of rows) {
    const revisionId = normalizeUuid(row.advisory_revision_id);
    if (revisionId === null || !CANONICAL_CVE_PATTERN.test(row.alias_value)) {
      return null;
    }
    const existing = grouped.get(revisionId);
    if (existing === undefined) {
      grouped.set(revisionId, [row.alias_value]);
      continue;
    }
    if (existing.includes(row.alias_value)) {
      return null;
    }
    existing.push(row.alias_value);
  }
  return grouped;
}

/**
 * True only when exactly one observation matches the controlled creation shape.
 * Zero creation observations returns false. More than one, or an observation
 * set above the cap, returns null so the graph is malformed.
 * This does not write observations or assemble facts.
 */
async function loadHasControlledCreationObservation(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<boolean | null> {
  const rows = await tx.$queryRaw<ObservationClassificationRow[]>`
    SELECT
      "method"::text AS "method",
      "result"::text AS "result",
      "occurrence_id"::text AS "occurrence_id",
      "transition_classification"::text AS "transition_classification",
      "creation_purpose"::text AS "creation_purpose",
      "creation_policy_id"::text AS "creation_policy_id",
      "creation_policy_version" AS "creation_policy_version",
      "observation_purpose"::text AS "observation_purpose",
      "observation_policy_id"::text AS "observation_policy_id",
      "observation_policy_version" AS "observation_policy_version",
      "aggregate_classification"::text AS "aggregate_classification"
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
    ORDER BY "id"
    LIMIT ${MAX_FACT_GRAPH_OBSERVATIONS + 1}
  `;
  if (rows.length > MAX_FACT_GRAPH_OBSERVATIONS) {
    return null;
  }
  let creationCount = 0;
  for (const row of rows) {
    const input = observationClassificationInput(row);
    if (input === null) {
      return null;
    }
    if (classifyInspectionObservationShape(input).role === 'creation_observation') {
      creationCount += 1;
    }
  }
  if (creationCount > 1) {
    return null;
  }
  return creationCount === 1;
}

/**
 * A new insert requires the controlled creation observation and at least one
 * creation-evidence link with outcome `affected`, reloaded after the Finding
 * row lock. The observation match is the creation method `controlled_finding_creation`
 * and result `present` used by controlled Finding creation. Replay is decided
 * before this read. This function does not write Findings or Product Match Evidence.
 * False means one of those facts is missing. Null means the observation rows
 * could not be classified.
 */
async function loadCreationInsertEligible(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<boolean | null> {
  const observed = await loadHasControlledCreationObservation(tx, organizationId, findingId);
  if (observed !== true) {
    return observed;
  }
  const rows = await tx.$queryRaw<Array<{ links: number | bigint }>>`
    SELECT COUNT(*)::int AS "links"
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
      AND "outcome"::text = 'affected'
  `;
  const links = readInt(rows[0]?.links);
  if (links === null) {
    return null;
  }
  return links >= 1;
}

type ObservationClassificationRow = {
  readonly method: unknown;
  readonly result: unknown;
  readonly occurrence_id: unknown;
  readonly transition_classification: unknown;
  readonly creation_purpose: unknown;
  readonly creation_policy_id: unknown;
  readonly creation_policy_version: unknown;
  readonly observation_purpose: unknown;
  readonly observation_policy_id: unknown;
  readonly observation_policy_version: unknown;
  readonly aggregate_classification: unknown;
};

function observationClassificationInput(
  row: ObservationClassificationRow,
): Record<string, unknown> | null {
  const method = readRequiredString(row.method);
  const result = readRequiredString(row.result);
  const occurrenceId = readNullableString(row.occurrence_id);
  const transitionClassification = readNullableString(row.transition_classification);
  const creationPurpose = readNullableString(row.creation_purpose);
  const creationPolicyId = readNullableString(row.creation_policy_id);
  const creationPolicyVersion = readNullableInt(row.creation_policy_version);
  const observationPurpose = readNullableString(row.observation_purpose);
  const observationPolicyId = readNullableString(row.observation_policy_id);
  const observationPolicyVersion = readNullableInt(row.observation_policy_version);
  const aggregate = readNullableString(row.aggregate_classification);
  if (
    method === null ||
    result === null ||
    occurrenceId === undefined ||
    transitionClassification === undefined ||
    creationPurpose === undefined ||
    creationPolicyId === undefined ||
    creationPolicyVersion === undefined ||
    observationPurpose === undefined ||
    observationPolicyId === undefined ||
    observationPolicyVersion === undefined ||
    aggregate === undefined
  ) {
    return null;
  }
  return {
    method,
    result,
    occurrenceId,
    transitionClassification,
    creationPurpose,
    creationPolicyId,
    creationPolicyVersion,
    observationPurpose,
    observationPolicyId,
    observationPolicyVersion,
    aggregate,
  };
}

function readRequiredString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function readNullableString(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  return typeof value === 'string' ? value : undefined;
}

function readNullableInt(value: unknown): number | null | undefined {
  if (value === null) {
    return null;
  }
  const parsed = readInt(value);
  return parsed === null ? undefined : parsed;
}

/**
 * Reloads the actor inside the transaction. The membership must belong to the
 * trusted organization, be active, and name that actor. Callers pass the
 * organization from trusted context; this query does not accept a separate
 * client organization id.
 */
async function loadActor(
  tx: Prisma.TransactionClient,
  organizationId: string,
  membershipId: string,
  actorUserId: string,
): Promise<string | null> {
  const rows = await tx.$queryRaw<Array<{ user_id: string }>>`
    SELECT "user_id"::text AS "user_id"
    FROM "membership"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${membershipId}::uuid
      AND "user_id" = ${actorUserId}::uuid
      AND "status" = 'active'::"membership_status"
  `;
  const userId = rows[0]?.user_id;
  if (rows.length !== 1 || userId === undefined) {
    return null;
  }
  const normalized = normalizeUuid(userId);
  if (normalized !== actorUserId) {
    return null;
  }
  return normalized;
}

async function loadFindingForUpdate(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<
  { readonly kind: 'open' } | { readonly kind: 'not_found' } | { readonly kind: 'ineligible' }
> {
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      state: string;
      version: number | bigint;
      due_at: Date | string | null;
      current_risk_calculation_id: string | null;
    }>
  >`
    SELECT
      "id"::text AS "id",
      "state"::text AS "state",
      "version"::int AS "version",
      "due_at",
      "current_risk_calculation_id"::text AS "current_risk_calculation_id"
    FROM "finding"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${findingId}::uuid
    FOR UPDATE
  `;
  const row = rows[0];
  if (row === undefined) {
    return { kind: 'not_found' };
  }
  if (rows.length !== 1 || normalizeUuid(row.id) !== findingId) {
    throw new PersistenceAbort('internal_failure');
  }
  const version = readInt(row.version);
  const dueAt = readNullableTimestamp(row.due_at);
  const currentRiskCalculationId = readNullableUuid(row.current_risk_calculation_id);
  if (version === null || dueAt === undefined || currentRiskCalculationId === undefined) {
    throw new PersistenceAbort('internal_failure');
  }
  if (
    row.state !== 'open' ||
    version !== 1 ||
    currentRiskCalculationId !== null ||
    dueAt !== null
  ) {
    return { kind: 'ineligible' };
  }
  return { kind: 'open' };
}

async function loadVisiblePolicy(
  tx: Prisma.TransactionClient,
  organizationId: string,
  riskPolicyId: string,
): Promise<
  | { readonly kind: 'visible'; readonly policy: { readonly id: string; readonly version: number } }
  | { readonly kind: 'policy_not_found' }
  | { readonly kind: 'policy_not_eligible' }
> {
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      organization_id: string | null;
      scope: string;
      policy_key: string;
      version: number | bigint;
      status: string;
      policy_schema_version: number | bigint;
    }>
  >`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "scope"::text AS "scope",
      "policy_key",
      "version"::int AS "version",
      "status"::text AS "status",
      "policy_schema_version"::int AS "policy_schema_version"
    FROM "risk_policy"
    WHERE "id" = ${riskPolicyId}::uuid
  `;
  const row = rows[0];
  if (row === undefined || rows.length !== 1) {
    return { kind: 'policy_not_found' };
  }
  const id = normalizeUuid(row.id);
  const version = readInt(row.version);
  const schemaVersion = readInt(row.policy_schema_version);
  const organization = readNullableUuid(row.organization_id);
  if (id === null || version === null || schemaVersion === null || organization === undefined) {
    throw new PersistenceAbort('internal_failure');
  }
  const builtin = row.scope === 'builtin' && organization === null;
  const owned = row.scope === 'organization' && organization === organizationId;
  if (!builtin && !owned) {
    return { kind: 'policy_not_found' };
  }
  if (
    row.policy_key !== BUILTIN_PRIORITY_POLICY_KEY ||
    row.status !== 'published' ||
    schemaVersion !== RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2
  ) {
    return { kind: 'policy_not_eligible' };
  }
  return { kind: 'visible', policy: { id, version } };
}

async function findByFingerprint(
  tx: Prisma.TransactionClient,
  command: NormalizedPersist,
): Promise<ComparisonRow | null> {
  const rows = await tx.$queryRaw<ComparisonRow[]>`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "finding_id"::text AS "finding_id",
      "risk_policy_id"::text AS "risk_policy_id",
      "policy_version"::int AS "policy_version",
      btrim("policy_definition_sha256") AS "policy_definition_sha256",
      "calculated_at",
      "factors",
      "result",
      "calculation_engine_version",
      "calculation_reason"::text AS "calculation_reason",
      btrim("input_fingerprint") AS "input_fingerprint",
      (btrim("policy_definition_sha256") = ${command.policyDefinitionSha256}) AS "hash_matches",
      ("factors" = ${command.factorsJson}::jsonb) AS "factors_match",
      ("result" = ${command.resultJson}::jsonb) AS "result_match",
      ("calculation_engine_version" = ${PRIORITY_CALCULATION_ENGINE_VERSION}) AS "engine_matches"
    FROM "risk_calculation"
    WHERE "organization_id" = ${command.organizationId}::uuid
      AND "finding_id" = ${command.findingId}::uuid
      AND btrim("input_fingerprint") = ${command.inputFingerprint}
  `;
  if (rows.length > 1) {
    throw new PersistenceAbort('internal_failure');
  }
  return rows[0] ?? null;
}

function replayFromRow(row: ComparisonRow): PersistRiskCalculationResult {
  const hashMatches = readBoolean(row.hash_matches);
  const factorsMatch = readBoolean(row.factors_match);
  const resultMatch = readBoolean(row.result_match);
  const engineMatches = readBoolean(row.engine_matches);
  if (
    hashMatches === null ||
    factorsMatch === null ||
    resultMatch === null ||
    engineMatches === null
  ) {
    throw new PersistenceAbort('internal_failure');
  }
  if (!hashMatches || !factorsMatch || !resultMatch || !engineMatches) {
    return { kind: 'immutable_conflict' };
  }
  const calculation = mapCalculationRow(row);
  if (calculation === null) {
    return { kind: 'immutable_conflict' };
  }
  return { kind: 'replay', calculation };
}

function mapCalculationRow(row: CalculationRow): PersistedRiskCalculation | null {
  const id = normalizeUuid(row.id);
  const organizationId = normalizeUuid(row.organization_id);
  const findingId = normalizeUuid(row.finding_id);
  const riskPolicyId = normalizeUuid(row.risk_policy_id);
  const policyVersion = readInt(row.policy_version);
  const calculatedAt = readTimestamp(row.calculated_at);
  const factors = readFactors(row.factors);
  const result = readResult(row.result);
  const policyDefinitionSha256 = readSha256(row.policy_definition_sha256);
  const inputFingerprint = readSha256(row.input_fingerprint);
  if (
    id === null ||
    organizationId === null ||
    findingId === null ||
    riskPolicyId === null ||
    policyVersion === null ||
    policyVersion < 1 ||
    calculatedAt === null ||
    factors === null ||
    result === null ||
    policyDefinitionSha256 === null ||
    inputFingerprint === null ||
    row.calculation_engine_version !== PRIORITY_CALCULATION_ENGINE_VERSION ||
    !isOneOf(row.calculation_reason, PERSISTABLE_RISK_CALCULATION_REASONS)
  ) {
    return null;
  }
  return {
    id,
    organizationId,
    findingId,
    riskPolicyId,
    policyVersion,
    policyDefinitionSha256,
    calculatedAt,
    factors,
    result,
    calculationEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    calculationReason: row.calculation_reason,
    inputFingerprint,
  };
}

function classifyPolicyRead(
  rows: readonly PolicyRow[],
  scope: 'builtin' | 'organization',
): PriorityPolicyReadResult {
  const row = rows[0];
  if (row === undefined) {
    return { kind: 'not_found' };
  }
  if (rows.length !== 1) {
    return { kind: 'internal_failure' };
  }
  const policy = mapPolicyRow(row, scope);
  if (policy === null) {
    return { kind: 'malformed' };
  }
  return { kind: 'found', policy };
}

function mapPolicyRow(
  row: PolicyRow,
  scope: 'builtin' | 'organization',
): StoredPriorityPolicy | null {
  const id = normalizeUuid(row.id);
  const organizationId = readNullableUuid(row.organization_id);
  const version = readInt(row.version);
  const schemaVersion = readInt(row.policy_schema_version);
  const publishedAt = row.published_at === null ? null : readTimestamp(row.published_at);
  const createdByMembershipId = readNullableUuid(row.created_by_membership_id);
  const definition = readStoredDefinition(row.definition);
  if (
    id === null ||
    organizationId === undefined ||
    version === null ||
    version < 1 ||
    schemaVersion !== RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2 ||
    publishedAt === null ||
    createdByMembershipId === undefined ||
    definition === null ||
    row.scope !== scope ||
    row.status !== 'published' ||
    row.policy_key !== BUILTIN_PRIORITY_POLICY_KEY ||
    typeof row.name !== 'string' ||
    row.name.length === 0 ||
    row.name.length > 200
  ) {
    return null;
  }
  if (scope === 'builtin' && (organizationId !== null || createdByMembershipId !== null)) {
    return null;
  }
  if (scope === 'organization' && organizationId === null) {
    return null;
  }
  if (scope === 'builtin' && version !== BUILTIN_PRIORITY_POLICY_VERSION) {
    return null;
  }
  return {
    id,
    organizationId,
    scope,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    name: row.name,
    version,
    status: 'published',
    policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
    definition,
    publishedAt,
    createdByMembershipId,
  };
}

function priorityCalculatedPayload(
  calculation: PersistedRiskCalculation,
): PriorityCalculatedAuditPayload {
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    findingId: calculation.findingId,
    riskCalculationId: calculation.id,
    riskPolicyId: calculation.riskPolicyId,
    priorityBand: calculation.result.priorityBand,
  };
}

function normalizePersistInput(
  input: PersistRiskCalculationInput,
):
  | { readonly kind: 'ready'; readonly command: NormalizedPersist }
  | { readonly kind: 'rejected'; readonly reason: PersistRiskCalculationRejection } {
  const organizationId = normalizeUuid(input.organizationId);
  const actorUserId = normalizeUuid(input.actorUserId);
  const membershipId = normalizeUuid(input.membershipId);
  const findingId = normalizeUuid(input.findingId);
  const riskPolicyId = normalizeUuid(input.riskPolicyId);
  if (
    organizationId === null ||
    actorUserId === null ||
    membershipId === null ||
    findingId === null ||
    riskPolicyId === null
  ) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  const policyDefinitionSha256 = readSha256(input.policyDefinitionSha256);
  const inputFingerprint = readSha256(input.inputFingerprint);
  if (policyDefinitionSha256 === null || inputFingerprint === null) {
    return { kind: 'rejected', reason: 'malformed_hash' };
  }
  const correlationId = normalizeUuid(input.correlationId);
  if (correlationId === null) {
    return { kind: 'rejected', reason: 'malformed_correlation' };
  }
  let calculatedAt: Date | null;
  if (input.calculatedAt === undefined) {
    calculatedAt = null;
  } else if (readTimestamp(input.calculatedAt) === null) {
    return { kind: 'rejected', reason: 'malformed_timestamp' };
  } else {
    calculatedAt = input.calculatedAt;
  }
  if (!isOneOf(input.calculationReason, PERSISTABLE_RISK_CALCULATION_REASONS)) {
    return { kind: 'rejected', reason: 'calculation_reason' };
  }
  const factors = readFactors(input.factors);
  const result = readResult(input.result);
  if (factors === null || result === null) {
    return { kind: 'rejected', reason: 'malformed_document' };
  }
  const factorsJson = JSON.stringify(factors);
  const resultJson = JSON.stringify(result);
  return {
    kind: 'ready',
    command: {
      organizationId,
      actorUserId,
      membershipId,
      findingId,
      riskPolicyId,
      policyDefinitionSha256,
      inputFingerprint,
      calculationReason: input.calculationReason,
      factors,
      result,
      factorsJson,
      resultJson,
      correlationId,
      calculatedAt,
    },
  };
}

function normalizeOverrideInput(input: PublishOrganizationPriorityOverrideInput):
  | {
      readonly kind: 'ready';
      readonly command: {
        readonly organizationId: string;
        readonly actorUserId: string;
        readonly membershipId: string;
        readonly definition: Readonly<Record<string, unknown>>;
        readonly definitionJson: string;
      };
    }
  | { readonly kind: 'rejected'; readonly reason: PublishPriorityOverrideRejection } {
  const organizationId = normalizeUuid(input.organizationId);
  const actorUserId = normalizeUuid(input.actorUserId);
  const membershipId = normalizeUuid(input.membershipId);
  if (organizationId === null || actorUserId === null || membershipId === null) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  if (input.policyKey !== BUILTIN_PRIORITY_POLICY_KEY) {
    return { kind: 'rejected', reason: 'policy_key' };
  }
  if (input.policySchemaVersion !== RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2) {
    return { kind: 'rejected', reason: 'policy_schema_version' };
  }
  const definition = readPublishableDefinition(input.definition);
  if (definition === null) {
    return { kind: 'rejected', reason: 'malformed_definition' };
  }
  const definitionJson = JSON.stringify(definition);
  if (definitionJson.length > MAX_POLICY_DEFINITION_JSON_LENGTH) {
    return { kind: 'rejected', reason: 'malformed_definition' };
  }
  return {
    kind: 'ready',
    command: { organizationId, actorUserId, membershipId, definition, definitionJson },
  };
}

function readFactors(value: unknown): RiskCalculationFactorsV2Json | null {
  const record = asRecord(value);
  if (
    record === null ||
    !hasExactKeys(record, [
      'schemaVersion',
      'factors',
      'rules',
      'escalationReasons',
      'evidenceSummary',
      'weightedScoreCenti',
      'upliftCenti',
      'sources',
    ]) ||
    record['schemaVersion'] !== RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2
  ) {
    return null;
  }
  const factors = readFactorRows(record['factors']);
  const rules = readRuleRows(record['rules']);
  const escalationReasons = readEscalationReasons(record['escalationReasons']);
  const evidenceSummary = readEvidenceSummary(record['evidenceSummary'], factors);
  const weightedScoreCenti = readBoundedInt(record['weightedScoreCenti'], 0, MAX_CENTI);
  const upliftCenti = readBoundedInt(record['upliftCenti'], 0, MAX_CENTI);
  const sources = readSources(record['sources']);
  if (
    factors === null ||
    rules === null ||
    escalationReasons === null ||
    evidenceSummary === null ||
    weightedScoreCenti === null ||
    upliftCenti === null ||
    sources === null
  ) {
    return null;
  }
  return {
    schemaVersion: RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
    factors,
    rules,
    escalationReasons,
    evidenceSummary,
    weightedScoreCenti,
    upliftCenti,
    sources,
  };
}

function readFactorRows(value: unknown): readonly PriorityFactorRow[] | null {
  if (!Array.isArray(value) || value.length !== PRIORITY_FACTOR_IDS.length) {
    return null;
  }
  const rows: PriorityFactorRow[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const factorId = PRIORITY_FACTOR_IDS[index];
    if (factorId === undefined) {
      return null;
    }
    const row = readFactorRow(value[index], factorId, index + 1);
    if (row === null) {
      return null;
    }
    rows.push(row);
  }
  return rows;
}

function readFactorRow(
  value: unknown,
  factorId: PriorityFactorId,
  ordinal: number,
): PriorityFactorRow | null {
  const record = asRecord(value);
  if (
    record === null ||
    !hasExactKeys(record, [
      'factorId',
      'ordinal',
      'inputState',
      'observedValue',
      'normalizedPercent',
      'weight',
      'contributionCenti',
      'status',
      'explanationCode',
    ]) ||
    record['factorId'] !== factorId ||
    record['ordinal'] !== ordinal ||
    !isOneOf(record['inputState'], PRIORITY_FACTOR_INPUT_STATES) ||
    !isOneOf(record['status'], PRIORITY_FACTOR_STATUSES) ||
    !isOneOf(record['explanationCode'], PRIORITY_FACTOR_EXPLANATION_CODES)
  ) {
    return null;
  }
  const observedValue = readObservedValue(factorId, record['observedValue']);
  const normalizedPercent = readBoundedInt(record['normalizedPercent'], 0, 100);
  const weight = readBoundedInt(record['weight'], 0, 100);
  const contributionCenti = readBoundedInt(record['contributionCenti'], 0, MAX_CENTI);
  if (
    observedValue === undefined ||
    normalizedPercent === null ||
    weight === null ||
    contributionCenti === null
  ) {
    return null;
  }
  return {
    factorId,
    ordinal,
    inputState: record['inputState'],
    observedValue,
    normalizedPercent,
    weight,
    contributionCenti,
    status: record['status'],
    explanationCode: record['explanationCode'],
  };
}

function readRuleRows(value: unknown): readonly PriorityRuleRow[] | null {
  if (!Array.isArray(value) || value.length !== PRIORITY_RULE_IDS.length) {
    return null;
  }
  const rows: PriorityRuleRow[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const ruleId = PRIORITY_RULE_IDS[index];
    if (ruleId === undefined) {
      return null;
    }
    const row = readRuleRow(value[index], ruleId);
    if (row === null) {
      return null;
    }
    rows.push(row);
  }
  return rows;
}

function readRuleRow(value: unknown, ruleId: PriorityRuleId): PriorityRuleRow | null {
  const record = asRecord(value);
  if (
    record === null ||
    !hasExactKeys(record, ['ruleId', 'triggered', 'upliftCenti', 'explanationCode']) ||
    record['ruleId'] !== ruleId ||
    typeof record['triggered'] !== 'boolean' ||
    !isOneOf(record['explanationCode'], PRIORITY_RULE_EXPLANATION_CODES)
  ) {
    return null;
  }
  const upliftCenti = readBoundedInt(record['upliftCenti'], 0, MAX_CENTI);
  if (upliftCenti === null) {
    return null;
  }
  return {
    ruleId,
    triggered: record['triggered'],
    upliftCenti,
    explanationCode: record['explanationCode'],
  };
}

/**
 * Closed engine order: `kev_production`, then `kev_internet_facing`.
 * An empty array is the no-reason result. Unknown strings, duplicates,
 * and any other order are rejected.
 */
function readEscalationReasons(value: unknown): readonly PriorityEscalationReason[] | null {
  if (!Array.isArray(value) || value.length > PRIORITY_ESCALATION_REASONS.length) {
    return null;
  }
  const reasons: PriorityEscalationReason[] = [];
  let cursor = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      return null;
    }
    const reason = value[index];
    let matched: PriorityEscalationReason | null = null;
    for (
      let candidateIndex = cursor;
      candidateIndex < PRIORITY_ESCALATION_REASONS.length;
      candidateIndex += 1
    ) {
      const candidate = PRIORITY_ESCALATION_REASONS[candidateIndex];
      if (candidate !== undefined && candidate === reason) {
        matched = candidate;
        cursor = candidateIndex + 1;
        break;
      }
    }
    if (matched === null) {
      return null;
    }
    reasons.push(matched);
  }
  return reasons;
}

function readEvidenceSummary(
  value: unknown,
  factors: readonly PriorityFactorRow[] | null,
): PriorityEvidenceSummary | null {
  const record = asRecord(value);
  if (
    record === null ||
    factors === null ||
    !hasExactKeys(record, ['observed', 'unknown', 'unavailable'])
  ) {
    return null;
  }
  const observed = readBoundedInt(record['observed'], 0, factors.length);
  const unknown = readBoundedInt(record['unknown'], 0, factors.length);
  const unavailable = readBoundedInt(record['unavailable'], 0, factors.length);
  if (observed === null || unknown === null || unavailable === null) {
    return null;
  }
  if (observed + unknown + unavailable !== factors.length) {
    return null;
  }
  let countedObserved = 0;
  let countedUnknown = 0;
  let countedUnavailable = 0;
  for (const factor of factors) {
    if (factor.inputState === 'observed') {
      countedObserved += 1;
    } else if (factor.inputState === 'unknown') {
      countedUnknown += 1;
    } else {
      countedUnavailable += 1;
    }
  }
  if (
    countedObserved !== observed ||
    countedUnknown !== unknown ||
    countedUnavailable !== unavailable
  ) {
    return null;
  }
  return { observed, unknown, unavailable };
}

function readSources(value: unknown): RiskCalculationFactorSourcesV2 | null {
  const record = asRecord(value);
  if (
    record === null ||
    !hasExactKeys(record, [
      'evidenceIds',
      'advisoryRevisionIds',
      'componentOccurrenceIds',
      'intelligenceSourceRecordIds',
      'kev',
    ])
  ) {
    return null;
  }
  const evidenceIds = readUuidList(record['evidenceIds']);
  const advisoryRevisionIds = readUuidList(record['advisoryRevisionIds']);
  const componentOccurrenceIds = readUuidList(record['componentOccurrenceIds']);
  const intelligenceSourceRecordIds = readUuidList(record['intelligenceSourceRecordIds']);
  const kev = readKevSource(record['kev']);
  if (
    evidenceIds === null ||
    advisoryRevisionIds === null ||
    componentOccurrenceIds === null ||
    intelligenceSourceRecordIds === null ||
    kev === null
  ) {
    return null;
  }
  return {
    evidenceIds,
    advisoryRevisionIds,
    componentOccurrenceIds,
    intelligenceSourceRecordIds,
    kev,
  };
}

function readKevSource(value: unknown): RiskCalculationKevSourceV2 | null {
  const record = asRecord(value);
  if (record === null) {
    return null;
  }
  if (record['state'] === 'unavailable') {
    if (
      !hasExactKeys(record, ['state', 'reason']) ||
      !isOneOf(record['reason'], PRIORITY_KEV_UNAVAILABLE_REASONS)
    ) {
      return null;
    }
    return { state: 'unavailable', reason: record['reason'] };
  }
  if (record['state'] !== 'catalog') {
    return null;
  }
  if (
    !hasExactKeys(record, [
      'state',
      'catalogVersion',
      'catalogReleasedAt',
      'freshness',
      'generationId',
      'snapshotSha256',
    ]) ||
    typeof record['catalogVersion'] !== 'string' ||
    !CATALOG_VERSION_PATTERN.test(record['catalogVersion']) ||
    typeof record['catalogReleasedAt'] !== 'string' ||
    !UTC_INSTANT_PATTERN.test(record['catalogReleasedAt']) ||
    !isOneOf(record['freshness'], PRIORITY_KEV_CATALOG_FRESHNESS)
  ) {
    return null;
  }
  const generationId = readNullableUuid(record['generationId']);
  const snapshotSha256 = readNullableSha256(record['snapshotSha256']);
  if (generationId === undefined || snapshotSha256 === undefined) {
    return null;
  }
  return {
    state: 'catalog',
    catalogVersion: record['catalogVersion'],
    catalogReleasedAt: record['catalogReleasedAt'],
    freshness: record['freshness'],
    generationId,
    snapshotSha256,
  };
}

function readResult(value: unknown): RiskCalculationResultV1Json | null {
  const record = asRecord(value);
  if (
    record === null ||
    !hasExactKeys(record, [
      'schemaVersion',
      'priority',
      'priorityBand',
      'dueDateRecommendationDays',
      'escalationRecommendation',
    ]) ||
    record['schemaVersion'] !== JSON_SCHEMA_VERSION_V1 ||
    !isOneOf(record['priorityBand'], PRIORITY_BANDS) ||
    typeof record['escalationRecommendation'] !== 'boolean'
  ) {
    return null;
  }
  const priority = readBoundedInt(record['priority'], 0, MAX_PRIORITY);
  const dueDateRecommendationDays = readBoundedInt(
    record['dueDateRecommendationDays'],
    MIN_DUE_DAYS,
    MAX_DUE_DAYS,
  );
  if (priority === null || dueDateRecommendationDays === null) {
    return null;
  }
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    priority,
    priorityBand: record['priorityBand'],
    dueDateRecommendationDays,
    escalationRecommendation: record['escalationRecommendation'],
  };
}

function readPublishableDefinition(value: unknown): Readonly<Record<string, unknown>> | null {
  if (!isJsonValue(value)) {
    return null;
  }
  const record = asRecord(value);
  if (
    record === null ||
    record['schemaVersion'] !== RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2 ||
    record['policyKey'] !== BUILTIN_PRIORITY_POLICY_KEY
  ) {
    return null;
  }
  return record;
}

function readStoredDefinition(value: unknown): Readonly<Record<string, unknown>> | null {
  const record = asRecord(value);
  if (
    record === null ||
    record['schemaVersion'] !== RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2 ||
    record['policyKey'] !== BUILTIN_PRIORITY_POLICY_KEY
  ) {
    return null;
  }
  return record;
}

function readObservedValue(
  factorId: PriorityFactorId,
  value: unknown,
): string | number | null | undefined {
  if (value === null) {
    return null;
  }
  if (factorId === 'finding_age_days') {
    if (
      typeof value === 'number' &&
      Number.isInteger(value) &&
      value >= 0 &&
      value <= PRIORITY_FINDING_AGE_DAYS_MAX
    ) {
      return value;
    }
    return undefined;
  }
  if (typeof value === 'string' && OBSERVED_VALUE_TOKENS.has(value)) {
    return value;
  }
  return undefined;
}

function readUuidList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > MAX_PRIORITY_SOURCE_IDS) {
    return null;
  }
  const ids: string[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      return null;
    }
    const id = normalizeUuid(value[index]);
    if (id === null || seen.has(id)) {
      return null;
    }
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

function readNullableUuid(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  const id = normalizeUuid(value);
  return id === null ? undefined : id;
}

function readNullableSha256(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  const hash = readSha256(value);
  return hash === null ? undefined : hash;
}

function readNullableTimestamp(value: unknown): Date | null | undefined {
  if (value === null) {
    return null;
  }
  const parsed = readTimestamp(value);
  return parsed === null ? undefined : parsed;
}

function normalizeUuid(value: unknown): string | null {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    return null;
  }
  return value.toLowerCase();
}

function readSha256(value: unknown): string | null {
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) {
    return null;
  }
  return value;
}

function readInt(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }
  if (
    typeof value === 'bigint' &&
    value >= BigInt(Number.MIN_SAFE_INTEGER) &&
    value <= BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return Number(value);
  }
  return null;
}

function readBoundedInt(value: unknown, minimum: number, maximum: number): number | null {
  const parsed = readInt(value);
  if (parsed === null || parsed < minimum || parsed > maximum) {
    return null;
  }
  return parsed;
}

function readBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function readTimestamp(value: unknown): Date | null {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  if (typeof value === 'string' && UTC_INSTANT_PATTERN.test(value)) {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    return null;
  }
  return value as Record<string, unknown>;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  if (actual.length !== keys.length) {
    return false;
  }
  return keys.every((key) => Object.hasOwn(record, key));
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && allowed.some((candidate) => candidate === value);
}

function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return true;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index) || !isJsonValue(value[index])) {
        return false;
      }
    }
    return true;
  }
  const record = asRecord(value);
  if (record === null) {
    return false;
  }
  return Object.values(record).every((entry) => isJsonValue(entry));
}

function distinctIds(ids: readonly string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const id of ids) {
    if (!seen.has(id)) {
      seen.add(id);
      result.push(id);
    }
  }
  return result;
}

async function queryPublishedBuiltinPriorityPolicy(
  client: PrioritySqlClient,
): Promise<PriorityPolicyReadResult> {
  const rows = await client.$queryRaw<PolicyRow[]>`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "scope"::text AS "scope",
      "policy_key",
      "name",
      "version"::int AS "version",
      "status"::text AS "status",
      "policy_schema_version"::int AS "policy_schema_version",
      "definition",
      "published_at",
      "created_by_membership_id"::text AS "created_by_membership_id"
    FROM "risk_policy"
    WHERE "organization_id" IS NULL
      AND "scope" = 'builtin'::"risk_policy_scope"
      AND "policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
      AND "version" = ${BUILTIN_PRIORITY_POLICY_VERSION}::int
    LIMIT 1
  `;
  return classifyPolicyRead(rows, 'builtin');
}

async function querySelectedOrganizationPriorityOverride(
  client: PrioritySqlClient,
  organizationId: string,
): Promise<PriorityPolicyReadResult> {
  const rows = await client.$queryRaw<PolicyRow[]>`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "scope"::text AS "scope",
      "policy_key",
      "name",
      "version"::int AS "version",
      "status"::text AS "status",
      "policy_schema_version"::int AS "policy_schema_version",
      "definition",
      "published_at",
      "created_by_membership_id"::text AS "created_by_membership_id"
    FROM "risk_policy"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "scope" = 'organization'::"risk_policy_scope"
      AND "policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
      AND "status" = 'published'::"risk_policy_status"
    ORDER BY "version" DESC
    LIMIT 1
  `;
  return classifyPolicyRead(rows, 'organization');
}

async function queryCurrentRiskCalculation(
  client: PrioritySqlClient,
  organizationId: string,
  findingId: string,
): Promise<CurrentRiskCalculationResult> {
  const rows = await client.$queryRaw<CalculationRow[]>`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "finding_id"::text AS "finding_id",
      "risk_policy_id"::text AS "risk_policy_id",
      "policy_version"::int AS "policy_version",
      btrim("policy_definition_sha256") AS "policy_definition_sha256",
      "calculated_at",
      "factors",
      "result",
      "calculation_engine_version",
      "calculation_reason"::text AS "calculation_reason",
      btrim("input_fingerprint") AS "input_fingerprint"
    FROM "risk_calculation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
    ORDER BY "calculated_at" DESC, "id" DESC
    LIMIT 1
  `;
  const row = rows[0];
  if (row === undefined) {
    return { kind: 'not_found' };
  }
  if (rows.length !== 1) {
    return { kind: 'internal_failure' };
  }
  const calculation = mapCalculationRow(row);
  if (
    calculation === null ||
    calculation.organizationId !== organizationId ||
    calculation.findingId !== findingId
  ) {
    return { kind: 'malformed' };
  }
  return { kind: 'found', calculation };
}

export type FindingPriorityStateResult =
  | { readonly kind: 'finding_absent' }
  | {
      readonly kind: 'not_calculated';
      readonly findingId: string;
      readonly publishedBuiltin: FindingPriorityBuiltinRow | null;
    }
  | {
      readonly kind: 'calculated';
      readonly findingId: string;
      readonly publishedBuiltin: FindingPriorityBuiltinRow | null;
      readonly calculation: FindingPriorityCalculationRow;
    }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'rejected'; readonly reason: 'malformed_id' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'internal_failure' };

export type FindingPriorityBuiltinRow = {
  readonly id: string;
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly version: number;
  readonly definition: Readonly<Record<string, unknown>>;
};

export type FindingPriorityCalculationRow = {
  readonly id: string;
  readonly riskPolicyId: string;
  readonly policyKey: string;
  readonly policyVersion: number;
  readonly policyDefinitionSha256: string;
  readonly calculatedAt: Date;
  readonly calculationEngineVersion: string;
  readonly calculationReason: PersistableRiskCalculationReason;
  readonly factors: RiskCalculationFactorsV2Json;
  readonly result: RiskCalculationResultV1Json;
  readonly lastObservedAt: Date;
  readonly assetUpdatedAt: Date;
  readonly activeKevGenerationId: string | null;
};

/**
 * One organization-scoped read of Finding presence, the latest calculation,
 * the published builtin, and the active KEV generation id.
 * It does not call the priority engine and does not write.
 */
export async function readFindingPriorityState(
  client: PrismaClient,
  input: CurrentRiskCalculationQuery,
): Promise<FindingPriorityStateResult> {
  const organizationId = normalizeUuid(input.organizationId);
  const findingId = normalizeUuid(input.findingId);
  if (organizationId === null || findingId === null) {
    return { kind: 'rejected', reason: 'malformed_id' };
  }
  try {
    return await queryFindingPriorityState(client, organizationId, findingId);
  } catch (error) {
    return mapReadFailure(error);
  }
}

type FindingPriorityStateRow = {
  readonly finding_id: string;
  readonly organization_id: string;
  readonly last_observed_at: Date | string;
  readonly asset_updated_at: Date | string;
  readonly calculation_id: string | null;
  readonly risk_policy_id: string | null;
  readonly policy_key: string | null;
  readonly policy_version: number | null;
  readonly policy_row_version: number | null;
  readonly policy_definition_sha256: string | null;
  readonly calculated_at: Date | string | null;
  readonly factors: Prisma.JsonValue | null;
  readonly result: Prisma.JsonValue | null;
  readonly calculation_engine_version: string | null;
  readonly calculation_reason: string | null;
  readonly published_id: string | null;
  readonly published_policy_key: string | null;
  readonly published_version: number | null;
  readonly published_definition: Prisma.JsonValue | null;
  readonly kev_generation_id: string | null;
};

async function queryFindingPriorityState(
  client: PrioritySqlClient,
  organizationId: string,
  findingId: string,
): Promise<FindingPriorityStateResult> {
  const rows = await client.$queryRaw<FindingPriorityStateRow[]>`
    SELECT
      f."id"::text AS "finding_id",
      f."organization_id"::text AS "organization_id",
      f."last_observed_at" AS "last_observed_at",
      a."updated_at" AS "asset_updated_at",
      c."id" AS "calculation_id",
      c."risk_policy_id" AS "risk_policy_id",
      c."policy_key" AS "policy_key",
      c."policy_version" AS "policy_version",
      c."policy_row_version" AS "policy_row_version",
      c."policy_definition_sha256" AS "policy_definition_sha256",
      c."calculated_at" AS "calculated_at",
      c."factors" AS "factors",
      c."result" AS "result",
      c."calculation_engine_version" AS "calculation_engine_version",
      c."calculation_reason" AS "calculation_reason",
      bp."id" AS "published_id",
      bp."policy_key" AS "published_policy_key",
      bp."version" AS "published_version",
      bp."definition" AS "published_definition",
      (
        SELECT s."active_generation_id"::text
        FROM "intelligence_source" s
        WHERE s."provider_key" = 'cisa_kev'::"integration_provider_key"
      ) AS "kev_generation_id"
    FROM "finding" f
    INNER JOIN "asset" a
      ON a."organization_id" = f."organization_id"
     AND a."id" = f."asset_id"
    LEFT JOIN LATERAL (
      SELECT
        rc."id"::text AS "id",
        rc."risk_policy_id"::text AS "risk_policy_id",
        rp."policy_key" AS "policy_key",
        rc."policy_version"::int AS "policy_version",
        rp."version"::int AS "policy_row_version",
        btrim(rc."policy_definition_sha256") AS "policy_definition_sha256",
        rc."calculated_at" AS "calculated_at",
        rc."factors" AS "factors",
        rc."result" AS "result",
        rc."calculation_engine_version" AS "calculation_engine_version",
        rc."calculation_reason"::text AS "calculation_reason"
      FROM "risk_calculation" rc
      INNER JOIN "risk_policy" rp ON rp."id" = rc."risk_policy_id"
      WHERE rc."organization_id" = f."organization_id"
        AND rc."finding_id" = f."id"
      ORDER BY rc."calculated_at" DESC, rc."id" DESC
      LIMIT 1
    ) c ON TRUE
    LEFT JOIN LATERAL (
      SELECT
        p."id"::text AS "id",
        p."policy_key" AS "policy_key",
        p."version"::int AS "version",
        p."definition" AS "definition"
      FROM "risk_policy" p
      WHERE p."organization_id" IS NULL
        AND p."scope" = 'builtin'::"risk_policy_scope"
        AND p."policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
        AND p."version" = ${BUILTIN_PRIORITY_POLICY_VERSION}::int
        AND p."status" = 'published'::"risk_policy_status"
      LIMIT 1
    ) bp ON TRUE
    WHERE f."organization_id" = ${organizationId}::uuid
      AND f."id" = ${findingId}::uuid
  `;
  const row = rows[0];
  if (row === undefined) {
    return { kind: 'finding_absent' };
  }
  if (rows.length !== 1 || normalizeUuid(row.organization_id) !== organizationId) {
    return { kind: 'internal_failure' };
  }
  if (normalizeUuid(row.finding_id) !== findingId) {
    return { kind: 'malformed' };
  }
  const publishedBuiltin = readPublishedBuiltin(row);
  if (publishedBuiltin === 'malformed') {
    return { kind: 'malformed' };
  }
  const activeKevGenerationId = readOptionalUuid(row.kev_generation_id);
  if (activeKevGenerationId === 'malformed') {
    return { kind: 'malformed' };
  }
  if (row.calculation_id === null) {
    return { kind: 'not_calculated', findingId, publishedBuiltin };
  }
  const calculation = readPriorityCalculation(row, activeKevGenerationId);
  if (calculation === null) {
    return { kind: 'malformed' };
  }
  return { kind: 'calculated', findingId, publishedBuiltin, calculation };
}

function readPublishedBuiltin(
  row: FindingPriorityStateRow,
): FindingPriorityBuiltinRow | null | 'malformed' {
  if (
    row.published_id === null &&
    row.published_policy_key === null &&
    row.published_version === null &&
    row.published_definition === null
  ) {
    return null;
  }
  const id = normalizeUuid(row.published_id);
  const definition = readStoredDefinition(row.published_definition);
  const version = readInt(row.published_version);
  if (
    id === null ||
    definition === null ||
    version !== BUILTIN_PRIORITY_POLICY_VERSION ||
    row.published_policy_key !== BUILTIN_PRIORITY_POLICY_KEY
  ) {
    return 'malformed';
  }
  return {
    id,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    version,
    definition,
  };
}

function readOptionalUuid(value: string | null): string | null | 'malformed' {
  if (value === null) {
    return null;
  }
  const normalized = normalizeUuid(value);
  return normalized === null ? 'malformed' : normalized;
}

function readPriorityCalculation(
  row: FindingPriorityStateRow,
  activeKevGenerationId: string | null,
): FindingPriorityCalculationRow | null {
  const id = normalizeUuid(row.calculation_id);
  const riskPolicyId = normalizeUuid(row.risk_policy_id);
  const policyVersion = readInt(row.policy_version);
  const policyRowVersion = readInt(row.policy_row_version);
  const policyDefinitionSha256 = readSha256(row.policy_definition_sha256);
  const calculatedAt = readTimestamp(row.calculated_at);
  const lastObservedAt = readTimestamp(row.last_observed_at);
  const assetUpdatedAt = readTimestamp(row.asset_updated_at);
  const factors = readFactors(row.factors);
  const result = readResult(row.result);
  const engineVersion = readStoredEngineVersion(row.calculation_engine_version);
  const reason = readPersistableReason(row.calculation_reason);
  if (
    id === null ||
    riskPolicyId === null ||
    policyVersion === null ||
    policyRowVersion === null ||
    policyVersion !== policyRowVersion ||
    policyDefinitionSha256 === null ||
    calculatedAt === null ||
    lastObservedAt === null ||
    assetUpdatedAt === null ||
    factors === null ||
    result === null ||
    engineVersion === null ||
    reason === null ||
    row.policy_key === null ||
    !PRINTABLE_TEXT.test(row.policy_key) ||
    row.policy_key.length > 128
  ) {
    return null;
  }
  return {
    id,
    riskPolicyId,
    policyKey: row.policy_key,
    policyVersion,
    policyDefinitionSha256,
    calculatedAt,
    calculationEngineVersion: engineVersion,
    calculationReason: reason,
    factors,
    result,
    lastObservedAt,
    assetUpdatedAt,
    activeKevGenerationId,
  };
}

function readStoredEngineVersion(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 64 || !PRINTABLE_TEXT.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function readPersistableReason(value: string | null): PersistableRiskCalculationReason | null {
  if (!isOneOf(value, PERSISTABLE_RISK_CALCULATION_REASONS)) {
    return null;
  }
  return value;
}

async function lockTransactionScope(tx: Prisma.TransactionClient, lockKey: string): Promise<void> {
  const locked = await tx.$queryRaw<Array<{ locked: number }>>`
    SELECT 1::int AS "locked"
    FROM (
      SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))
    ) AS taken
  `;
  if (locked.length !== 1) {
    throw new PersistenceAbort('transaction_aborted');
  }
}

async function readDatabaseNow(tx: Prisma.TransactionClient): Promise<Date> {
  const rows = await tx.$queryRaw<Array<{ calculated_at: Date | string }>>`
    SELECT CURRENT_TIMESTAMP AS "calculated_at"
  `;
  const calculatedAt = readTimestamp(rows[0]?.calculated_at);
  if (rows.length !== 1 || calculatedAt === null) {
    throw new PersistenceAbort('internal_failure');
  }
  return calculatedAt;
}

function abortedResult(
  error: unknown,
): { readonly kind: 'internal_failure' | 'transaction_aborted' } | null {
  if (error instanceof PersistenceAbort) {
    return { kind: error.failure };
  }
  return null;
}

function mapReadFailure(error: unknown): {
  readonly kind: 'database_unavailable' | 'internal_failure';
} {
  if (isDatabaseUnavailable(error)) {
    return { kind: 'database_unavailable' };
  }
  if (classifyDatabaseFailure(error) !== null || isUniqueViolation(error)) {
    return { kind: 'internal_failure' };
  }
  throw error;
}

function classifyDatabaseFailure(error: unknown): DatabaseFailureKind | null {
  if (isDatabaseUnavailable(error)) {
    return 'database_unavailable';
  }
  if (isConstraintFailure(error) || isPrismaRequestError(error)) {
    return 'transaction_aborted';
  }
  return null;
}

function isUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
    return true;
  }
  return sqlState(error) === '23505';
}

function isConstraintFailure(error: unknown): boolean {
  const state = sqlState(error);
  return (
    state === '23514' ||
    state === '23503' ||
    state === '23502' ||
    state === '42501' ||
    state === '23001' ||
    state === '22P02' ||
    state === '40001' ||
    state === '40P01' ||
    state === 'P0001'
  );
}

function isDatabaseUnavailable(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  );
}

function isPrismaRequestError(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError ||
    error instanceof Prisma.PrismaClientUnknownRequestError ||
    error instanceof Prisma.PrismaClientValidationError
  );
}

function sqlState(error: unknown): string | null {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    return typeof metaCode === 'string' ? metaCode : null;
  }
  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    const match = /code: "([0-9A-Z]{5})"/.exec(error.message);
    return match?.[1] ?? null;
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return /^[0-9A-Z]{5}$/.test(error.code) ? error.code : null;
  }
  return null;
}
