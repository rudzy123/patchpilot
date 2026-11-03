/**
 * Uncomposed priority calculation for one controlled Finding.
 * Organization comes from the trusted actor. The command must not carry
 * `organizationId`. Production registration stays absent: no route, worker,
 * or Outbox event is constructed here.
 *
 * `inputFingerprint` is the SHA-256 of `canonicalJson` of
 * `{ engineVersion, policyDefinitionSha256, facts }`. `facts` is the object
 * returned by `parseFactInput` and later passed to `evaluatePriority`. It is
 * not the factor-row document, and it does not include sources or
 * `calculationReason`. `policyDefinitionSha256` is the SHA-256 of
 * `canonicalJson` of the selected validated definition.
 *
 * Age and `calculatedAt` both use the fact-graph `asOf`. This module does not
 * call `Date.now()`. The insert transaction reloads membership. KEV reads use
 * the injected membership use case and stay outside that insert because the
 * existing adapter does not accept a caller transaction.
 */

import { createHash, randomUUID } from 'node:crypto';

import {
  JSON_SCHEMA_VERSION_V1,
  RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
} from '../json-documents.js';
import type {
  RiskCalculationFactorsV2Json,
  RiskCalculationKevSourceV2,
  RiskCalculationResultV1Json,
} from '../json-documents.js';
import type { PriorityFactorRow } from '../json-documents.js';
import type { MembershipRole } from '../lifecycle.js';
import {
  closedRecord,
  isPlainObject,
  recordHasAmbientKey,
} from '../findings/controlled-creation/plain.js';
import {
  parseControlledFindingOperatorActor,
  type ParsedControlledFindingOperatorActor,
} from '../findings/controlled-operator/actor.js';
import { UTC_INSTANT_PATTERN } from '../intelligence/constants.js';
import { assertNever, err, ok, type AppError, type Result } from '../result.js';
import {
  ACTIVE_KEV_MEMBERSHIP_INCONSISTENT,
  type ActiveKevCatalogFreshness,
  type ActiveKevMembership,
  type QueryActiveKevMembershipUseCase,
} from '../vulnerability/kev-membership.js';
import {
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_FACTOR_IDS,
  PRIORITY_RULE_IDS,
  type PriorityFactorExplanationCode,
  type PriorityFactorId,
  type PriorityKevObservedToken,
  type PriorityKevUnavailableReason,
  type PriorityKevUnknownToken,
} from './catalog.js';
import type { PriorityEnginePort } from './engine-port.js';
import {
  assemblePriorityFacts,
  assembleRiskCalculationFactorSources,
  assessFindingRiskEligibility,
  findingRiskKevMembershipError,
  mapActiveKevToListedFact,
  selectFindingRiskCanonicalCves,
  type FindingRiskFactAssemblyFailureCode,
  type FindingRiskIneligibleReason,
  type FindingRiskKevMappingFailureCode,
  type FindingRiskKevMembershipError,
  type FindingRiskKevMembershipErrorCode,
  type FindingRiskSourceSnapshot,
} from './fact-assembly.js';
import type {
  PriorityAssetDataClassificationFact,
  PriorityBusinessCriticalityFact,
  PriorityEnvironmentSensitivityFact,
  PriorityFactInput,
  PriorityInternetExposureFact,
  PriorityKevListedFact,
} from './facts.js';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  type PersistedRiskCalculationReason,
  type PriorityPolicyLookup,
  type RiskCalculationPersistencePort,
  type StoredPriorityPolicyView,
  type StoredRiskCalculation,
} from './persistence-port.js';
import {
  PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
  PRIORITY_INSPECT_PERMISSION,
  roleGrantsPriorityPermission,
  type PriorityPermission,
} from './permissions.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const ENVELOPE_KEYS = ['actor', 'command'] as const;

const FINDING_COMMAND_KEYS = ['findingId'] as const;

const PUBLISH_COMMAND_KEYS = ['definition'] as const;

const ENVELOPE_AUTHORITY_KEYS = [
  'organizationId',
  'organization',
  'membershipId',
  'membershipRole',
  'membershipStatus',
  'role',
  'roles',
  'permission',
  'permissions',
  'userId',
  'sessionId',
  'admin',
  'owner',
] as const;

const COMMAND_AUTHORITY_KEYS = [
  'organizationId',
  'organization',
  'actorUserId',
  'membershipId',
  'role',
  'permission',
  'permissions',
  'userId',
  'sessionId',
] as const;

const ASSET_CONTEXT_FACTORS = [
  'environment_sensitivity',
  'internet_exposure',
  'business_criticality',
  'asset_data_classification',
] as const satisfies readonly PriorityFactorId[];

type AssetContextFactorId = (typeof ASSET_CONTEXT_FACTORS)[number];

type AssetContextFact =
  | PriorityEnvironmentSensitivityFact
  | PriorityInternetExposureFact
  | PriorityBusinessCriticalityFact
  | PriorityAssetDataClassificationFact;

/** Existing admin and owner grant. This module does not copy the auth catalog. */
export const ORGANIZATION_PRIORITY_OVERRIDE_PERMISSION = 'policy:manage' as const;

function roleGrantsPolicyManage(role: MembershipRole): boolean {
  switch (role) {
    case 'owner':
    case 'admin':
      return true;
    case 'member':
    case 'viewer':
      return false;
    default:
      return assertNever(role);
  }
}

export type CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts> = {
  readonly engine: PriorityEnginePort<TValidatedDefinition, TParsedFacts>;
  readonly persistence: Pick<
    RiskCalculationPersistencePort,
    | 'loadPriorityCalculationFactGraph'
    | 'findPublishedBuiltinPriorityPolicy'
    | 'findSelectedOrganizationPriorityOverride'
    | 'findCurrentRiskCalculation'
    | 'persistRiskCalculation'
  >;
  readonly kevMembership: QueryActiveKevMembershipUseCase;
  readonly builtinDefinition: unknown;
  readonly createCorrelationId?: () => string;
};

export type CalculateFindingRiskResult =
  | { readonly kind: 'calculated'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'replayed'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'not_found' }
  | {
      readonly kind: 'ineligible';
      readonly reason: FindingRiskIneligibleReason | 'persistence';
    }
  | { readonly kind: 'canonical_cve_rejected'; readonly code: 'canonical_cve_cardinality' }
  | { readonly kind: 'kev_membership_error'; readonly error: FindingRiskKevMembershipError }
  | { readonly kind: 'kev_mapping_rejected'; readonly code: FindingRiskKevMappingFailureCode }
  | { readonly kind: 'kev_source_rejected'; readonly code: 'catalog_disagreement' }
  | {
      readonly kind: 'builtin_unavailable';
      readonly reason: 'absent' | 'mismatch' | 'invalid' | 'unreadable' | 'version';
    }
  | { readonly kind: 'override_rejected'; readonly reason: 'invalid' | 'unreadable' }
  | { readonly kind: 'facts_rejected'; readonly code: FindingRiskFactAssemblyFailureCode }
  | { readonly kind: 'fact_input_rejected' }
  | { readonly kind: 'canonical_json_rejected' }
  | { readonly kind: 'engine_rejected' }
  | { readonly kind: 'immutable_conflict' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_failure' };

export type ReadCurrentFindingRiskDependencies = {
  readonly persistence: Pick<RiskCalculationPersistencePort, 'findCurrentRiskCalculation'>;
};

export type ReadCurrentFindingRiskResult =
  | { readonly kind: 'found'; readonly calculation: StoredRiskCalculation }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_failure' };

export type PublishOrganizationPriorityOverrideDependencies<TValidatedDefinition, TParsedFacts> = {
  readonly engine: PriorityEnginePort<TValidatedDefinition, TParsedFacts>;
  readonly persistence: Pick<RiskCalculationPersistencePort, 'publishOrganizationPriorityOverride'>;
  readonly builtinDefinition: unknown;
};

export type PublishOrganizationPriorityOverrideResult =
  | {
      readonly kind: 'published';
      readonly policy: { readonly id: string; readonly version: number };
    }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'override_rejected'; readonly reason: 'invalid' | 'parent' }
  | { readonly kind: 'membership_not_found' }
  | { readonly kind: 'version_conflict' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_failure' };

type AuthorizedFinding = {
  readonly ok: true;
  readonly actor: ParsedControlledFindingOperatorActor;
  readonly findingId: string;
};

type CommandRead =
  | {
      readonly ok: true;
      readonly actor: unknown;
      readonly command: unknown;
    }
  | { readonly ok: false; readonly kind: 'unauthorized' | 'invalid_command' };

type SelectedPolicy<TValidatedDefinition> = {
  readonly definition: TValidatedDefinition;
  readonly riskPolicyId: string;
};

export function createCalculateFindingRiskUseCase<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
) {
  const createCorrelationId = dependencies.createCorrelationId ?? randomUUID;
  return {
    async execute(input: unknown): Promise<CalculateFindingRiskResult> {
      try {
        return await executeCalculation(dependencies, createCorrelationId, input);
      } catch {
        return { kind: 'internal_failure' };
      }
    },
  };
}

export function createReadCurrentFindingRiskUseCase(
  dependencies: ReadCurrentFindingRiskDependencies,
) {
  return {
    async execute(input: unknown): Promise<ReadCurrentFindingRiskResult> {
      try {
        return await executeRead(dependencies, input);
      } catch {
        return { kind: 'internal_failure' };
      }
    },
  };
}

export function createPublishOrganizationPriorityOverrideUseCase<
  TValidatedDefinition,
  TParsedFacts,
>(
  dependencies: PublishOrganizationPriorityOverrideDependencies<TValidatedDefinition, TParsedFacts>,
) {
  return {
    async execute(input: unknown): Promise<PublishOrganizationPriorityOverrideResult> {
      try {
        return await executePublish(dependencies, input);
      } catch {
        return { kind: 'internal_failure' };
      }
    },
  };
}

async function executeRead(
  dependencies: ReadCurrentFindingRiskDependencies,
  input: unknown,
): Promise<ReadCurrentFindingRiskResult> {
  const authorized = authorizeFinding(input, PRIORITY_INSPECT_PERMISSION);
  if (!authorized.ok) {
    return { kind: authorized.kind };
  }
  if (typeof dependencies.persistence.findCurrentRiskCalculation !== 'function') {
    return { kind: 'internal_failure' };
  }
  const current = await dependencies.persistence.findCurrentRiskCalculation({
    organizationId: authorized.actor.organizationId,
    findingId: authorized.findingId,
  });
  switch (current.kind) {
    case 'found':
      return { kind: 'found', calculation: current.calculation };
    case 'not_found':
      return { kind: 'not_found' };
    case 'unavailable':
      return { kind: 'unavailable' };
    default:
      return assertNever(current);
  }
}

async function executePublish<TValidatedDefinition, TParsedFacts>(
  dependencies: PublishOrganizationPriorityOverrideDependencies<TValidatedDefinition, TParsedFacts>,
  input: unknown,
): Promise<PublishOrganizationPriorityOverrideResult> {
  const envelope = readEnvelope(input);
  if (!envelope.ok) {
    return { kind: envelope.kind };
  }
  const actor = parseControlledFindingOperatorActor(envelope.actor);
  if (actor === null || !roleGrantsPolicyManage(actor.role)) {
    return { kind: 'unauthorized' };
  }
  if (!isPlainObject(envelope.command)) {
    return { kind: 'invalid_command' };
  }
  if (recordHasAmbientKey(envelope.command, COMMAND_AUTHORITY_KEYS)) {
    return { kind: 'unauthorized' };
  }
  const command = closedRecord(envelope.command, PUBLISH_COMMAND_KEYS);
  if (command === null) {
    return { kind: 'invalid_command' };
  }
  const parent = dependencies.engine.validatePolicyDefinition(dependencies.builtinDefinition);
  if (!parent.ok) {
    return { kind: 'override_rejected', reason: 'parent' };
  }
  const override = dependencies.engine.validatePolicyOverride(
    parent.value,
    command.get('definition'),
  );
  if (!override.ok) {
    return { kind: 'override_rejected', reason: 'invalid' };
  }
  if (typeof dependencies.persistence.publishOrganizationPriorityOverride !== 'function') {
    return { kind: 'internal_failure' };
  }
  const published = await dependencies.persistence.publishOrganizationPriorityOverride({
    organizationId: actor.organizationId,
    membershipId: actor.membershipId,
    definition: override.value,
    policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
  });
  switch (published.kind) {
    case 'published':
      return { kind: 'published', policy: published.policy };
    case 'membership_not_found':
      return { kind: 'membership_not_found' };
    case 'version_conflict':
      return { kind: 'version_conflict' };
    case 'rejected':
      return { kind: 'rejected' };
    case 'unavailable':
      return { kind: 'unavailable' };
    default:
      return assertNever(published);
  }
}

async function executeCalculation<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
  createCorrelationId: () => string,
  input: unknown,
): Promise<CalculateFindingRiskResult> {
  const authorized = authorizeFinding(input, PRIORITY_CALCULATE_CONTROLLED_PERMISSION);
  if (!authorized.ok) {
    return { kind: authorized.kind };
  }
  const loaded = await loadSnapshot(dependencies, authorized);
  if (!loaded.ok) {
    return loaded.failure;
  }
  const canonicalCves = selectFindingRiskCanonicalCves(loaded.snapshot);
  if (!canonicalCves.ok) {
    return { kind: 'canonical_cve_rejected', code: canonicalCves.error.code };
  }
  const memberships = await readMemberships(dependencies.kevMembership, canonicalCves.value);
  if (!memberships.ok) {
    return { kind: 'kev_membership_error', error: memberships.error };
  }
  const kevFact = mapActiveKevToListedFact(canonicalCves.value.length, memberships.value);
  if (!kevFact.ok) {
    return { kind: 'kev_mapping_rejected', code: kevFact.error.code };
  }
  const kevSource = kevCatalogSource(kevFact.value, memberships.value);
  if (!kevSource.ok) {
    return { kind: 'kev_source_rejected', code: kevSource.error.code };
  }
  const selected = await selectPolicy(dependencies, authorized.actor.organizationId);
  if (!selected.ok) {
    return selected.failure;
  }
  const facts = assemblePriorityFacts(loaded.snapshot, kevFact.value, loaded.asOf);
  if (!facts.ok) {
    return { kind: 'facts_rejected', code: facts.error.code };
  }
  const sources = assembleRiskCalculationFactorSources(loaded.snapshot, kevSource.value);
  const parsed = dependencies.engine.parseFactInput(facts.value);
  if (!parsed.ok) {
    return { kind: 'fact_input_rejected' };
  }
  const fingerprint = fingerprintCalculation(
    dependencies.engine,
    selected.policy.definition,
    parsed.value,
  );
  if (!fingerprint.ok) {
    return fingerprint.failure;
  }
  const reason = await resolveReason(
    dependencies,
    authorized,
    fingerprint.policyDefinitionSha256,
    facts.value,
  );
  if (!reason.ok) {
    return reason.failure;
  }
  const evaluation = dependencies.engine.evaluatePriority(selected.policy.definition, parsed.value);
  if (!evaluation.ok || !evaluationAccepted(evaluation.value)) {
    return { kind: 'engine_rejected' };
  }
  const correlationId = readCorrelationId(createCorrelationId);
  if (correlationId === null) {
    return { kind: 'internal_failure' };
  }
  if (typeof dependencies.persistence.persistRiskCalculation !== 'function') {
    return { kind: 'internal_failure' };
  }
  const persisted = await dependencies.persistence.persistRiskCalculation({
    organizationId: authorized.actor.organizationId,
    actorUserId: authorized.actor.userId,
    membershipId: authorized.actor.membershipId,
    findingId: authorized.findingId,
    riskPolicyId: selected.policy.riskPolicyId,
    policyDefinitionSha256: fingerprint.policyDefinitionSha256,
    inputFingerprint: fingerprint.inputFingerprint,
    calculationReason: reason.reason,
    factors: factorsDocument(evaluation.value, sources),
    result: resultDocument(evaluation.value),
    correlationId,
    calculatedAt: loaded.asOf,
  });
  switch (persisted.kind) {
    case 'persisted':
      return { kind: 'calculated', calculation: persisted.calculation };
    case 'replay':
      return { kind: 'replayed', calculation: persisted.calculation };
    case 'immutable_conflict':
      return { kind: 'immutable_conflict' };
    case 'not_found':
      return { kind: 'not_found' };
    case 'ineligible':
      return { kind: 'ineligible', reason: 'persistence' };
    case 'policy_unavailable':
    case 'unavailable':
      return { kind: 'unavailable' };
    case 'unauthorized':
      return { kind: 'unauthorized' };
    default:
      return assertNever(persisted);
  }
}

function authorizeFinding(
  input: unknown,
  permission: PriorityPermission,
): AuthorizedFinding | { readonly ok: false; readonly kind: 'unauthorized' | 'invalid_command' } {
  const envelope = readEnvelope(input);
  if (!envelope.ok) {
    return envelope;
  }
  const actor = parseControlledFindingOperatorActor(envelope.actor);
  if (actor === null || !roleGrantsPriorityPermission(actor.role, permission)) {
    return { ok: false, kind: 'unauthorized' };
  }
  if (!isPlainObject(envelope.command)) {
    return { ok: false, kind: 'invalid_command' };
  }
  if (recordHasAmbientKey(envelope.command, COMMAND_AUTHORITY_KEYS)) {
    return { ok: false, kind: 'unauthorized' };
  }
  const command = closedRecord(envelope.command, FINDING_COMMAND_KEYS);
  if (command === null) {
    return { ok: false, kind: 'invalid_command' };
  }
  const findingId = command.get('findingId');
  if (typeof findingId !== 'string' || !UUID_LOWER_PATTERN.test(findingId)) {
    return { ok: false, kind: 'invalid_command' };
  }
  return { ok: true, actor, findingId };
}

function readEnvelope(input: unknown): CommandRead {
  if (recordHasAmbientKey(input, ENVELOPE_AUTHORITY_KEYS)) {
    return { ok: false, kind: 'unauthorized' };
  }
  const envelope = closedRecord(input, ENVELOPE_KEYS);
  if (envelope === null) {
    return { ok: false, kind: 'invalid_command' };
  }
  return {
    ok: true,
    actor: envelope.get('actor'),
    command: envelope.get('command'),
  };
}

async function loadSnapshot<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
  authorized: AuthorizedFinding,
): Promise<
  | { readonly ok: true; readonly asOf: Date; readonly snapshot: FindingRiskSourceSnapshot }
  | { readonly ok: false; readonly failure: CalculateFindingRiskResult }
> {
  if (typeof dependencies.persistence.loadPriorityCalculationFactGraph !== 'function') {
    return { ok: false, failure: { kind: 'internal_failure' } };
  }
  const graph = await dependencies.persistence.loadPriorityCalculationFactGraph({
    organizationId: authorized.actor.organizationId,
    findingId: authorized.findingId,
  });
  switch (graph.kind) {
    case 'not_found':
      return { ok: false, failure: { kind: 'not_found' } };
    case 'unavailable':
      return { ok: false, failure: { kind: 'unavailable' } };
    case 'found':
      break;
    default:
      return assertNever(graph);
  }
  if (
    graph.snapshot.finding.id !== authorized.findingId ||
    graph.snapshot.finding.organizationId !== authorized.actor.organizationId
  ) {
    return { ok: false, failure: { kind: 'not_found' } };
  }
  const eligibility = assessFindingRiskEligibility(graph.snapshot);
  if (eligibility.outcome === 'ineligible') {
    return { ok: false, failure: { kind: 'ineligible', reason: eligibility.reason } };
  }
  return { ok: true, asOf: graph.asOf, snapshot: graph.snapshot };
}

async function readMemberships(
  kevMembership: QueryActiveKevMembershipUseCase,
  canonicalCves: readonly string[],
): Promise<Result<readonly ActiveKevMembership[], FindingRiskKevMembershipError>> {
  if (typeof kevMembership.queryActiveKevMembership !== 'function') {
    return err(findingRiskKevMembershipError('source_missing'));
  }
  const memberships: ActiveKevMembership[] = [];
  for (const cve of canonicalCves) {
    let result: Result<ActiveKevMembership>;
    try {
      result = await kevMembership.queryActiveKevMembership({ cve });
    } catch {
      return err(findingRiskKevMembershipError('source_missing'));
    }
    if (!result.ok) {
      return err(findingRiskKevMembershipError(membershipErrorCode(result.error)));
    }
    memberships.push(result.value);
  }
  return ok(memberships);
}

/**
 * The membership use case reports `source_missing` as its unavailable error.
 * `inconsistent_active_generation` and `malformed_persisted_entry` share one
 * inconsistent error, so that shared error is `inconsistent_active_generation`.
 * A CVE string the membership parser rejects is `malformed_persisted_entry`.
 * Every one of these stops the calculation. None of them is stored as absent.
 */
function membershipErrorCode(error: AppError): FindingRiskKevMembershipErrorCode {
  if (error.code === 'validation') {
    return 'malformed_persisted_entry';
  }
  if (error.code === 'internal' && error.message === ACTIVE_KEV_MEMBERSHIP_INCONSISTENT.message) {
    return 'inconsistent_active_generation';
  }
  return 'source_missing';
}

function kevCatalogSource(
  fact: PriorityKevListedFact,
  memberships: readonly ActiveKevMembership[],
): Result<RiskCalculationKevSourceV2, { readonly code: 'catalog_disagreement' }> {
  if (fact.state === 'unavailable') {
    return ok(Object.freeze({ state: 'unavailable', reason: fact.reason }));
  }
  const catalogs: Array<Extract<ActiveKevMembership, { status: 'absent' | 'listedInActiveKev' }>> =
    [];
  for (const membership of memberships) {
    switch (membership.status) {
      case 'unavailable':
        return err({ code: 'catalog_disagreement' });
      case 'absent':
      case 'listedInActiveKev':
        catalogs.push(membership);
        break;
      default:
        return assertNever(membership);
    }
  }
  const first = catalogs[0];
  if (first === undefined) {
    return err({ code: 'catalog_disagreement' });
  }
  const releasedAt = first.catalogReleasedAt.getTime();
  if (!Number.isFinite(releasedAt)) {
    return err({ code: 'catalog_disagreement' });
  }
  for (const membership of catalogs) {
    if (
      membership.catalogVersion !== first.catalogVersion ||
      membership.catalogReleasedAt.getTime() !== releasedAt
    ) {
      return err({ code: 'catalog_disagreement' });
    }
  }
  const freshness = agreedFreshness(fact, catalogs);
  if (freshness === null) {
    return err({ code: 'catalog_disagreement' });
  }
  const catalogReleasedAt = first.catalogReleasedAt.toISOString();
  if (!UTC_INSTANT_PATTERN.test(catalogReleasedAt)) {
    return err({ code: 'catalog_disagreement' });
  }
  return ok(
    Object.freeze({
      state: 'catalog',
      catalogVersion: first.catalogVersion,
      catalogReleasedAt,
      freshness,
      generationId: null,
      snapshotSha256: null,
    }),
  );
}

function agreedFreshness(
  fact: Exclude<PriorityKevListedFact, { readonly state: 'unavailable' }>,
  catalogs: readonly Extract<ActiveKevMembership, { status: 'absent' | 'listedInActiveKev' }>[],
): ActiveKevCatalogFreshness | null {
  const present = new Set<ActiveKevCatalogFreshness>();
  for (const membership of catalogs) {
    present.add(membership.freshness);
  }
  if (fact.state === 'observed') {
    const expected = observedFreshness(fact.value);
    return present.size === 1 && present.has(expected) ? expected : null;
  }
  const expected = unknownFreshness(fact.value);
  for (const freshness of present) {
    if (freshness !== 'current' && freshness !== expected) {
      return null;
    }
  }
  return present.has(expected) ? expected : null;
}

function observedFreshness(value: PriorityKevObservedToken): ActiveKevCatalogFreshness {
  switch (value) {
    case 'listed_catalog_current':
    case 'not_listed_catalog_current':
      return 'current';
    case 'listed_catalog_stale':
      return 'stale';
    case 'listed_catalog_disabled_with_history':
      return 'disabled_with_history';
    default:
      return assertNever(value);
  }
}

function unknownFreshness(
  value: PriorityKevUnknownToken,
): Exclude<ActiveKevCatalogFreshness, 'current'> {
  switch (value) {
    case 'absent_catalog_stale':
      return 'stale';
    case 'absent_catalog_disabled_with_history':
      return 'disabled_with_history';
    default:
      return assertNever(value);
  }
}

async function selectPolicy<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
  organizationId: string,
): Promise<
  | { readonly ok: true; readonly policy: SelectedPolicy<TValidatedDefinition> }
  | { readonly ok: false; readonly failure: CalculateFindingRiskResult }
> {
  if (
    typeof dependencies.persistence.findPublishedBuiltinPriorityPolicy !== 'function' ||
    typeof dependencies.persistence.findSelectedOrganizationPriorityOverride !== 'function'
  ) {
    return { ok: false, failure: { kind: 'internal_failure' } };
  }
  const builtin = await dependencies.persistence.findPublishedBuiltinPriorityPolicy();
  const validatedBuiltin = validateBuiltinPolicy(dependencies, builtin);
  if (!validatedBuiltin.ok) {
    return validatedBuiltin;
  }
  const override =
    await dependencies.persistence.findSelectedOrganizationPriorityOverride(organizationId);
  if (override.kind === 'unavailable') {
    return { ok: false, failure: { kind: 'override_rejected', reason: 'unreadable' } };
  }
  if (override.kind === 'not_found') {
    return {
      ok: true,
      policy: {
        definition: validatedBuiltin.definition,
        riskPolicyId: validatedBuiltin.policy.id,
      },
    };
  }
  if (override.kind !== 'found') {
    return assertNever(override);
  }
  if (!publishedBuiltinKey(override.policy)) {
    return { ok: false, failure: { kind: 'override_rejected', reason: 'unreadable' } };
  }
  const validated = dependencies.engine.validatePolicyOverride(
    validatedBuiltin.definition,
    override.policy.definition,
  );
  if (!validated.ok) {
    return { ok: false, failure: { kind: 'override_rejected', reason: 'invalid' } };
  }
  return {
    ok: true,
    policy: { definition: validated.value, riskPolicyId: override.policy.id },
  };
}

function validateBuiltinPolicy<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
  builtin: PriorityPolicyLookup,
):
  | {
      readonly ok: true;
      readonly definition: TValidatedDefinition;
      readonly policy: StoredPriorityPolicyView;
    }
  | { readonly ok: false; readonly failure: CalculateFindingRiskResult } {
  if (builtin.kind === 'not_found') {
    return { ok: false, failure: { kind: 'builtin_unavailable', reason: 'absent' } };
  }
  if (builtin.kind === 'unavailable') {
    return { ok: false, failure: { kind: 'builtin_unavailable', reason: 'unreadable' } };
  }
  if (builtin.kind !== 'found') {
    return assertNever(builtin);
  }
  if (
    builtin.policy.version !== BUILTIN_PRIORITY_POLICY_VERSION ||
    builtin.policy.policyKey !== BUILTIN_PRIORITY_POLICY_KEY
  ) {
    return { ok: false, failure: { kind: 'builtin_unavailable', reason: 'version' } };
  }
  const storedCanonical = dependencies.engine.canonicalJson(builtin.policy.definition);
  const injectedCanonical = dependencies.engine.canonicalJson(dependencies.builtinDefinition);
  if (!storedCanonical.ok || !injectedCanonical.ok) {
    return { ok: false, failure: { kind: 'canonical_json_rejected' } };
  }
  if (storedCanonical.value !== injectedCanonical.value) {
    return { ok: false, failure: { kind: 'builtin_unavailable', reason: 'mismatch' } };
  }
  const validated = dependencies.engine.validatePolicyDefinition(dependencies.builtinDefinition);
  if (!validated.ok) {
    return { ok: false, failure: { kind: 'builtin_unavailable', reason: 'invalid' } };
  }
  return {
    ok: true,
    definition: validated.value,
    policy: builtin.policy,
  };
}

function publishedBuiltinKey(policy: StoredPriorityPolicyView): boolean {
  return (
    policy.policyKey === BUILTIN_PRIORITY_POLICY_KEY &&
    Number.isSafeInteger(policy.version) &&
    policy.version >= 1
  );
}

/**
 * Hashes the parsed fact input. `canonicalJson` sorts keys, so the fingerprint
 * does not depend on property insertion order.
 */
function fingerprintCalculation<TValidatedDefinition, TParsedFacts>(
  engine: PriorityEnginePort<TValidatedDefinition, TParsedFacts>,
  definition: TValidatedDefinition,
  facts: TParsedFacts,
):
  | {
      readonly ok: true;
      readonly policyDefinitionSha256: string;
      readonly inputFingerprint: string;
    }
  | { readonly ok: false; readonly failure: CalculateFindingRiskResult } {
  const definitionJson = engine.canonicalJson(definition);
  if (!definitionJson.ok) {
    return { ok: false, failure: { kind: 'canonical_json_rejected' } };
  }
  const policyDefinitionSha256 = sha256Hex(definitionJson.value);
  const material = {
    engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    policyDefinitionSha256,
    facts,
  };
  const fingerprintJson = engine.canonicalJson(material);
  if (!fingerprintJson.ok) {
    return { ok: false, failure: { kind: 'canonical_json_rejected' } };
  }
  return {
    ok: true,
    policyDefinitionSha256,
    inputFingerprint: sha256Hex(fingerprintJson.value),
  };
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

async function resolveReason<TValidatedDefinition, TParsedFacts>(
  dependencies: CalculateFindingRiskDependencies<TValidatedDefinition, TParsedFacts>,
  authorized: AuthorizedFinding,
  policyDefinitionSha256: string,
  facts: PriorityFactInput,
): Promise<
  | { readonly ok: true; readonly reason: PersistedRiskCalculationReason }
  | { readonly ok: false; readonly failure: CalculateFindingRiskResult }
> {
  if (typeof dependencies.persistence.findCurrentRiskCalculation !== 'function') {
    return { ok: false, failure: { kind: 'internal_failure' } };
  }
  const current = await dependencies.persistence.findCurrentRiskCalculation({
    organizationId: authorized.actor.organizationId,
    findingId: authorized.findingId,
  });
  switch (current.kind) {
    case 'unavailable':
      return { ok: false, failure: { kind: 'unavailable' } };
    case 'not_found':
      return { ok: true, reason: 'initial' };
    case 'found':
      break;
    default:
      return assertNever(current);
  }
  const reason = reasonAgainstCurrent(current.calculation, policyDefinitionSha256, facts);
  if (reason === null) {
    return { ok: false, failure: { kind: 'unavailable' } };
  }
  return { ok: true, reason };
}

function reasonAgainstCurrent(
  current: StoredRiskCalculation,
  policyDefinitionSha256: string,
  facts: PriorityFactInput,
): PersistedRiskCalculationReason | null {
  if (current.policyDefinitionSha256.toLowerCase() !== policyDefinitionSha256.toLowerCase()) {
    return 'policy_change';
  }
  const kevRow = factorById(current.factors.factors, 'kev_listed');
  if (kevRow === null) {
    return null;
  }
  const kevChanged = kevFactDiffers(kevRow, facts.kev_listed);
  if (kevChanged === null) {
    return null;
  }
  if (kevChanged) {
    return 'intel_refresh';
  }
  for (const factorId of ASSET_CONTEXT_FACTORS) {
    const row = factorById(current.factors.factors, factorId);
    if (row === null) {
      return null;
    }
    if (contextFactDiffers(row, assetContextFact(facts, factorId))) {
      return 'asset_change';
    }
  }
  return 'rescan';
}

function factorById(
  factors: readonly PriorityFactorRow[],
  factorId: PriorityFactorId,
): PriorityFactorRow | null {
  let found: PriorityFactorRow | null = null;
  for (const row of factors) {
    if (row.factorId !== factorId) {
      continue;
    }
    if (found !== null) {
      return null;
    }
    found = row;
  }
  return found;
}

function kevFactDiffers(row: PriorityFactorRow, fact: PriorityKevListedFact): boolean | null {
  if (row.inputState !== fact.state) {
    return true;
  }
  if (fact.state === 'unavailable') {
    const reason = kevUnavailableReason(row.explanationCode);
    if (reason === null) {
      return null;
    }
    return reason !== fact.reason;
  }
  return row.observedValue !== fact.value;
}

function kevUnavailableReason(
  code: PriorityFactorExplanationCode,
): PriorityKevUnavailableReason | null {
  switch (code) {
    case 'kev_unavailable_no_canonical_cve':
      return 'no_canonical_cve';
    case 'kev_unavailable_no_active_generation':
      return 'no_active_generation';
    default:
      return null;
  }
}

function contextFactDiffers(row: PriorityFactorRow, fact: AssetContextFact): boolean {
  if (row.inputState !== fact.state) {
    return true;
  }
  if (fact.state === 'observed') {
    return row.observedValue !== fact.value;
  }
  if (fact.state === 'unknown') {
    return row.observedValue !== null && row.observedValue !== fact.value;
  }
  return row.observedValue !== null;
}

function assetContextFact(
  facts: PriorityFactInput,
  factorId: AssetContextFactorId,
): AssetContextFact {
  switch (factorId) {
    case 'environment_sensitivity':
      return facts.environment_sensitivity;
    case 'internet_exposure':
      return facts.internet_exposure;
    case 'business_criticality':
      return facts.business_criticality;
    case 'asset_data_classification':
      return facts.asset_data_classification;
    default:
      return assertNever(factorId);
  }
}

function evaluationAccepted(value: {
  readonly engineVersion: string;
  readonly factors: readonly PriorityFactorRow[];
  readonly rules: readonly { readonly ruleId: string }[];
}): boolean {
  if (value.engineVersion !== PRIORITY_CALCULATION_ENGINE_VERSION) {
    return false;
  }
  if (
    value.factors.length !== PRIORITY_FACTOR_IDS.length ||
    value.rules.length !== PRIORITY_RULE_IDS.length
  ) {
    return false;
  }
  for (let index = 0; index < PRIORITY_FACTOR_IDS.length; index += 1) {
    if (value.factors[index]?.factorId !== PRIORITY_FACTOR_IDS[index]) {
      return false;
    }
  }
  for (let index = 0; index < PRIORITY_RULE_IDS.length; index += 1) {
    if (value.rules[index]?.ruleId !== PRIORITY_RULE_IDS[index]) {
      return false;
    }
  }
  return true;
}

function factorsDocument(
  evaluation: {
    readonly factors: RiskCalculationFactorsV2Json['factors'];
    readonly rules: RiskCalculationFactorsV2Json['rules'];
    readonly evidenceSummary: RiskCalculationFactorsV2Json['evidenceSummary'];
    readonly weightedScoreCenti: number;
    readonly upliftCenti: number;
    readonly escalation: {
      readonly reasons: RiskCalculationFactorsV2Json['escalationReasons'] | undefined;
    };
  },
  sources: RiskCalculationFactorsV2Json['sources'],
): RiskCalculationFactorsV2Json {
  return {
    schemaVersion: 2,
    factors: evaluation.factors,
    rules: evaluation.rules,
    escalationReasons: copyEscalationReasons(evaluation.escalation.reasons),
    evidenceSummary: evaluation.evidenceSummary,
    weightedScoreCenti: evaluation.weightedScoreCenti,
    upliftCenti: evaluation.upliftCenti,
    sources,
  };
}

function copyEscalationReasons(
  reasons: RiskCalculationFactorsV2Json['escalationReasons'] | undefined,
): RiskCalculationFactorsV2Json['escalationReasons'] {
  if (reasons === undefined || reasons.length === 0) {
    return [];
  }
  return reasons;
}

function resultDocument(evaluation: {
  readonly priority: RiskCalculationResultV1Json['priority'];
  readonly priorityBand: RiskCalculationResultV1Json['priorityBand'];
  readonly dueDateRecommendationDays: number;
  readonly escalation: { readonly recommended: boolean };
}): RiskCalculationResultV1Json {
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    priority: evaluation.priority,
    priorityBand: evaluation.priorityBand,
    dueDateRecommendationDays: evaluation.dueDateRecommendationDays,
    escalationRecommendation: evaluation.escalation.recommended,
  };
}

function readCorrelationId(createCorrelationId: () => string): string | null {
  try {
    const correlationId = createCorrelationId();
    return UUID_LOWER_PATTERN.test(correlationId) ? correlationId : null;
  } catch {
    return null;
  }
}
