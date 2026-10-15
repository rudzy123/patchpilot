/**
 * PostgreSQL maintainer-reviewed advisory approval.
 * Constructed only by the API mutation application. Web, worker, seed,
 * the package barrel, and route handlers do not construct this adapter.
 *
 * The private sealed issuer is called only from this module. The presentation
 * handle does not leave the transaction.
 *
 * Lock order, held to the end of the transaction:
 * 1. Reviewer User FOR UPDATE.
 * 2. That user's instance advisory grants FOR UPDATE, ordered by id.
 * 3. Target advisory revision FOR UPDATE.
 * 4. Binding, aliases, range events, then the bound Vulnerability.
 * 5. Existing approval and capability issuance rows FOR UPDATE.
 * 6. Classify replay, conflict, separation, or a first approval.
 * 7. Insert capability issuance, approval, consumed observation, and audit.
 * 8. Validate stored state.
 *
 * The consumed observation references the approval row, so the approval insert
 * precedes the observation inside the same transaction. Commit publishes both
 * or neither. User disablement and grant revocation lock the User, then that
 * user's grants. This transaction uses that prefix and does not invert it.
 * It does not take a table lock on advisory_revision.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
  canonicalInstanceAdvisoryPrincipalId,
  compareInstanceAdvisoryPrincipals,
} from '@patchpilot/domain/instance-advisory-authority';
import {
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_ACCEPTED_SPDX,
  MAINTAINER_REVIEWED_APPROVAL_LICENSE_CANONICAL,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_ECOSYSTEM,
  MAINTAINER_REVIEWED_EVALUATOR_VERSION,
  MAINTAINER_REVIEWED_MATCHING_POLICY_ID,
  MAINTAINER_REVIEWED_ORIGIN,
  VULNERABILITY_MAPPING_POLICY_ID,
  approvalMatchesCapability,
  classifyStoredMaintainerReviewedApproval,
  issuanceCommandMatchesStored,
  openDurableIssuanceCommand,
  type ParsedMaintainerReviewedAdvisoryApprovalCommand,
  type SealedDurableIssuanceCommand,
} from '@patchpilot/vulnerability-intelligence';
import {
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION,
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_COMMAND_NAME,
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PERSISTENCE_FIELDS,
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PURPOSE,
  classifyMaintainerReviewedAdvisoryApprovalAuthority,
  maintainerReviewedAdvisoryApprovalAuditIntent,
  parseMaintainerReviewedAdvisoryApprovalApplicationCommand,
  prepareMaintainerReviewedAdvisoryApproval,
  toMaintainerReviewedAdvisoryApprovalPersistenceCommand,
  type MaintainerReviewedAdvisoryApprovalPersistenceCommand,
  type MaintainerReviewedAdvisoryApprovalPersistencePort,
  type MaintainerReviewedAdvisoryApprovalResult,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-approval-application';
import {
  classifyMaintainerReviewedAdvisoryApprovalCapabilityLifetime,
  deriveMaintainerReviewedAdvisoryApprovalCommand,
  sealMaintainerReviewedAdvisoryApprovalCapability,
} from '../../vulnerability-intelligence/dist/matching/maintainer-reviewed-advisory-approval-application/capability.js';
import { durableCapabilityTtlExact } from '../../vulnerability-intelligence/dist/matching/reviewer-approval-capability/durable-policy.js';
import type { StoredCapabilityComparison } from '../../vulnerability-intelligence/dist/matching/reviewer-approval-capability/durable-command.js';

import { reloadInstanceAdvisoryAuthorizationFacts } from './instance-advisory-authority-persistence.js';

const SHA256_HEX = /^[a-f0-9]{64}$/;
const RANGE_EVENT_NAMES = new Set(['introduced', 'fixed', 'last_affected', 'limit']);
const PINS = MAINTAINER_REVIEWED_APPROVAL_PINS;
const LOCAL_VULNERABILITY_PREFIX = 'local-maintainer-reviewed:';
const SUBMISSION_AUDIT_ACTION = 'intelligence.maintainer_reviewed_advisory_submitted';
const LICENSE_POLICY_VERSION = String(PINS.licensePolicyVersion);

export const MAINTAINER_REVIEWED_ADVISORY_APPROVAL_LOCK_ORDER = [
  'validate_command',
  'lock_reviewer_user',
  'lock_instance_advisory_grants',
  'lock_advisory_revision',
  'lock_binding_aliases_ranges_vulnerability',
  'lock_existing_approval_and_capability',
  'classify',
  'insert_capability_issuance',
  'insert_approval',
  'insert_consumed_observation',
  'insert_audit',
  'validate_stored_state',
  'commit',
] as const;

export const MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PERSISTENCE_FAULTS = [
  'before_user_lock',
  'before_grant_lock',
  'before_revision_lock',
  'before_separation',
  'before_capability_issuance',
  'before_capability_validation',
  'before_capability_consumption',
  'before_approval_insert',
  'before_audit_insert',
  'before_stored_state_validation',
  'fail_stored_state_validation',
  'skip_audit_insert',
  'force_capability_expired',
  'lose_acknowledgment',
] as const;

export type MaintainerReviewedAdvisoryApprovalPersistenceFault =
  (typeof MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PERSISTENCE_FAULTS)[number];

export type MaintainerReviewedAdvisoryApprovalPersistenceOptions = {
  readonly fault?: MaintainerReviewedAdvisoryApprovalPersistenceFault;
};

type PersistenceFailure =
  | 'uniqueness'
  | 'capability_expired'
  | 'transaction_aborted'
  | 'database_unavailable'
  | 'internal_failure';

class PersistenceStop extends Error {
  constructor(
    readonly outcome: Exclude<
      MaintainerReviewedAdvisoryApprovalResult['outcome'],
      'approved' | 'already_applied'
    >,
  ) {
    super('maintainer-reviewed advisory approval persistence stopped');
  }
}

type Admitted = {
  readonly trustedReviewerUserId: string;
  readonly advisoryRevisionId: string;
  readonly correlationId: string;
};

type RevisionRow = {
  id: string;
  advisory_family_id: string;
  origin: string;
  source: string;
  family_digest: string;
  revision_digest: string;
  content_fingerprint: string;
  range_fingerprint: string;
  product_range_fingerprint: string;
  author_identity: string | null;
  package_identity_key: string;
  trust_classification: string;
  revision_disposition: string;
  quarantine_classification: string;
  withdrawal_classification: string;
  supersedes_revision_digest: string;
  revision_schema_version: string;
  parser_id: string;
  parser_resource_policy: string;
  advisory_schema_version: string;
  advisory_schema_commit: string;
  source_license_registry_version: string;
  source_license_policy_version: string;
  spdx_license_id: string | null;
  provider_generation: string;
  retrieval_classification: string;
  retrieval_evidence_id: string;
  retrieval_policy_id: string;
  ecosystem: string;
  evaluator_version: string;
  matching_policy_id: string;
  replay_fingerprint: string;
  alias_count: number;
  cve_alias_count: number;
};

type BindingRow = {
  id: string;
  vulnerability_id: string;
  binding_schema_version: string;
  mapping_policy_id: string;
  mapping_method: string;
  mapping_review_state: string;
  conflict_classification: string;
  binding_classification: string;
  replay_fingerprint: string;
};

type AliasRow = {
  ordinal: number;
  alias_type: string;
  alias_value: string;
  source_classification: string;
  review_classification: string;
  replay_fingerprint: string;
};

type RangeEventRow = {
  range_ordinal: number;
  event_ordinal: number;
  event_name: string;
  event_value: string;
};

type ApprovalRow = {
  id: string;
  approval_schema_version: string;
  advisory_revision_id: string;
  family_digest: string;
  approval_policy_id: string;
  approval_policy_version: number;
  approval_purpose: string;
  source_classification: string;
  author_identity: string;
  reviewer_identity: string;
  reviewer_classification: string;
  content_fingerprint: string;
  range_fingerprint: string;
  package_identity_key: string;
  vulnerability_id: string;
  source_license_policy_id: string;
  source_license_policy_version: number;
  approved_license_classification: string;
  license_decision_canonical: string;
  replay_fingerprint: string;
};

type CapabilityRow = {
  id: string;
  issuance_schema_version: string;
  capability_policy_id: string;
  capability_policy_version: number;
  approval_policy_id: string;
  approval_policy_version: number;
  approval_purpose: string;
  issuer_authorization_id: string;
  issuer_decision_fingerprint: string;
  approval_claim_fingerprint: string;
  advisory_family_identity: string;
  advisory_revision_id: string;
  content_fingerprint: string;
  affected_range_fingerprint: string;
  npm_package_identity: string;
  vulnerability_id: string;
  source_license_policy_id: string;
  source_license_policy_version: number;
  approved_license_classification: string;
  license_decision_canonical: string;
  source_classification: string;
  author_identity: string;
  reviewer_identity: string;
  correlation_id: string;
  issued_at: Date;
  expires_at: Date;
  observation_classification: string | null;
  observation_approval_id: string | null;
};

export type MaintainerReviewedAdvisoryApprovalPersistence = {
  readonly approve: (
    command: MaintainerReviewedAdvisoryApprovalPersistenceCommand,
    options?: MaintainerReviewedAdvisoryApprovalPersistenceOptions,
  ) => Promise<MaintainerReviewedAdvisoryApprovalResult>;
};

export function createMaintainerReviewedAdvisoryApprovalApplicationPersistence(
  client: PrismaClient,
): MaintainerReviewedAdvisoryApprovalPersistence {
  return {
    async approve(command, options) {
      const admitted = admit(command);
      if (!admitted.ok) {
        return { outcome: admitted.outcome };
      }
      const fault = options?.fault;
      try {
        const result = await client.$transaction((tx) => apply(tx, admitted.value, fault, true), {
          timeout: 20_000,
          maxWait: 5_000,
        });
        if (fault === 'lose_acknowledgment' && result.outcome === 'approved') {
          return { outcome: 'transaction_aborted' };
        }
        return result;
      } catch (error) {
        if (error instanceof PersistenceStop) {
          return { outcome: error.outcome };
        }
        const failure = classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(error);
        if (failure === 'database_unavailable') {
          return { outcome: 'database_unavailable' };
        }
        if (failure === 'capability_expired') {
          return { outcome: 'capability_expired' };
        }
        if (failure === 'uniqueness' || failure === 'transaction_aborted') {
          return rereadAfterPersistenceFailure(client, admitted.value);
        }
        return { outcome: 'internal_failure' };
      }
    },
  };
}

export function classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(
  error: unknown,
): PersistenceFailure {
  const text = error instanceof Error ? error.message : '';
  if (text.includes('reviewer_capability_expired')) {
    return 'capability_expired';
  }
  const state = sqlState(error);
  if (state === '23505') {
    return 'uniqueness';
  }
  if (
    state === '40001' ||
    state === '40P01' ||
    state === '55P03' ||
    state === '23514' ||
    state === '23503' ||
    state === '23502' ||
    state === '42501' ||
    state === '23001' ||
    state === '22P02' ||
    state === '22023'
  ) {
    return 'transaction_aborted';
  }
  if (isDatabaseUnavailable(error)) {
    return 'database_unavailable';
  }
  if (
    error instanceof Prisma.PrismaClientUnknownRequestError &&
    error.message.includes('Error querying the database: ERROR:')
  ) {
    return 'transaction_aborted';
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002') {
      return 'uniqueness';
    }
    if (
      error.code === 'P2028' ||
      error.code === 'P2034' ||
      error.code === 'P2003' ||
      error.code === 'P2010'
    ) {
      return 'transaction_aborted';
    }
  }
  return 'internal_failure';
}

function admit(command: MaintainerReviewedAdvisoryApprovalPersistenceCommand):
  | { readonly ok: true; readonly value: Admitted }
  | {
      readonly ok: false;
      readonly outcome: Exclude<
        MaintainerReviewedAdvisoryApprovalResult['outcome'],
        'approved' | 'already_applied'
      >;
    } {
  if (
    command.commandName !== MAINTAINER_REVIEWED_ADVISORY_APPROVAL_COMMAND_NAME ||
    !sameFields(command)
  ) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const parsed = parseMaintainerReviewedAdvisoryApprovalApplicationCommand({
    advisoryRevisionId: command.advisoryRevisionId,
    correlationId: command.correlationId,
  });
  if (!parsed.ok) {
    return { ok: false, outcome: parsed.outcome };
  }
  const prepared = prepareMaintainerReviewedAdvisoryApproval(
    command.trustedReviewerUserId,
    parsed.command,
  );
  if (!prepared.ok) {
    return { ok: false, outcome: prepared.outcome };
  }
  const persisted = toMaintainerReviewedAdvisoryApprovalPersistenceCommand(prepared.prepared);
  if (
    persisted.trustedReviewerUserId !== command.trustedReviewerUserId ||
    persisted.advisoryRevisionId !== command.advisoryRevisionId ||
    persisted.correlationId !== command.correlationId
  ) {
    return { ok: false, outcome: 'invalid_command' };
  }
  return {
    ok: true,
    value: {
      trustedReviewerUserId: persisted.trustedReviewerUserId,
      advisoryRevisionId: persisted.advisoryRevisionId,
      correlationId: persisted.correlationId,
    },
  };
}

function sameFields(command: MaintainerReviewedAdvisoryApprovalPersistenceCommand): boolean {
  const keys = Object.keys(command);
  return (
    keys.length === MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PERSISTENCE_FIELDS.length &&
    MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PERSISTENCE_FIELDS.every((field) => keys.includes(field))
  );
}

async function apply(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  fault: MaintainerReviewedAdvisoryApprovalPersistenceFault | undefined,
  write: boolean,
): Promise<MaintainerReviewedAdvisoryApprovalResult> {
  throwFault(fault, 'before_user_lock');
  const users = await tx.$queryRaw<Array<{ id: string; status: string }>>`
    SELECT "id"::text AS id, "status"::text AS status
    FROM "user"
    WHERE "id" = ${admitted.trustedReviewerUserId}::uuid
    FOR UPDATE
  `;
  if (users.length > 1) {
    return { outcome: 'malformed_persisted_state' };
  }
  throwFault(fault, 'before_grant_lock');
  await tx.$queryRaw`
    SELECT "id"
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${admitted.trustedReviewerUserId}::uuid
    ORDER BY "id"
    FOR UPDATE
  `;
  const facts = await reloadInstanceAdvisoryAuthorizationFacts(tx, {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
    userId: admitted.trustedReviewerUserId,
    requiredAuthority: 'advisory_approve_for_product_evaluation',
  });
  const authority = classifyMaintainerReviewedAdvisoryApprovalAuthority(
    admitted.trustedReviewerUserId,
    facts,
  );
  if (authority !== 'authorized') {
    return { outcome: authority };
  }
  throwFault(fault, 'before_revision_lock');
  const revision = await lockRevision(tx, admitted.advisoryRevisionId);
  if (revision === null) {
    return { outcome: 'not_found' };
  }
  if (
    revision.origin !== MAINTAINER_REVIEWED_ORIGIN ||
    revision.source !== MAINTAINER_REVIEWED_ORIGIN
  ) {
    return { outcome: 'unsupported_origin' };
  }
  const binding = await lockBinding(tx, revision.id);
  const aliases = await lockAliases(tx, revision.id);
  const rangeEvents = await lockRangeEvents(tx, revision.id);
  const vulnerability =
    binding === null ? null : await lockVulnerability(tx, binding.vulnerability_id);
  const approvals = await lockApprovals(tx, revision.id);
  const capabilities = await lockCapabilities(tx, revision.id);
  if (
    revision.author_identity === null ||
    canonicalInstanceAdvisoryPrincipalId(revision.author_identity) !== revision.author_identity
  ) {
    return { outcome: 'malformed_persisted_state' };
  }
  if (
    !envelopeLegal(revision, binding, aliases, rangeEvents, vulnerability) ||
    (await countAudits(tx, SUBMISSION_AUDIT_ACTION, revision.id, revision.author_identity)) !== 1
  ) {
    return { outcome: 'malformed_persisted_state' };
  }
  throwFault(fault, 'before_separation');
  const authorIdentity = revision.author_identity;
  if (authorIdentity === null) {
    return { outcome: 'malformed_persisted_state' };
  }
  const separation = compareInstanceAdvisoryPrincipals(
    authorIdentity,
    admitted.trustedReviewerUserId,
  );
  if (separation.classification === 'malformed_principal') {
    return { outcome: 'malformed_persisted_state' };
  }
  if (separation.classification === 'self_approval_forbidden') {
    return { outcome: 'separation_of_duties_required' };
  }
  if (binding === null) {
    return { outcome: 'malformed_persisted_state' };
  }
  const target = {
    advisoryRevisionId: revision.id,
    familyDigest: revision.family_digest,
    contentFingerprint: revision.content_fingerprint,
    rangeFingerprint: revision.range_fingerprint,
    productRangeFingerprint: revision.product_range_fingerprint,
    revisionReplayFingerprint: revision.replay_fingerprint,
    packageIdentityKey: revision.package_identity_key,
    vulnerabilityId: binding.vulnerability_id,
    authorIdentity,
    reviewerIdentity: admitted.trustedReviewerUserId,
    correlationId: admitted.correlationId,
  };
  const derived = deriveMaintainerReviewedAdvisoryApprovalCommand(target);
  if (!derived.ok) {
    return { outcome: 'malformed_persisted_state' };
  }
  if (approvals.length > 1 || capabilities.length > 1) {
    return { outcome: 'malformed_persisted_state' };
  }
  const approval = approvals[0];
  if (approval !== undefined) {
    const classification = classifyStoredMaintainerReviewedApproval(
      semanticApproval(approval),
      derived.approval,
    );
    if (classification === 'conflict') {
      return { outcome: 'immutable_conflict' };
    }
    if (classification !== 'match') {
      return { outcome: 'malformed_persisted_state' };
    }
    if (!replayLineageAgrees(approval, capabilities[0], admitted.trustedReviewerUserId, revision)) {
      return { outcome: 'malformed_persisted_state' };
    }
    const approvalAudits = await countAudits(
      tx,
      MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION,
      revision.id,
      admitted.trustedReviewerUserId,
    );
    if (approvalAudits !== 1) {
      return { outcome: 'malformed_persisted_state' };
    }
    return { outcome: 'already_applied', revisionId: revision.id };
  }
  if (capabilities.length !== 0) {
    return { outcome: 'malformed_persisted_state' };
  }
  if (!write) {
    return { outcome: 'transaction_aborted' };
  }
  throwFault(fault, 'before_capability_issuance');
  const sealed = sealMaintainerReviewedAdvisoryApprovalCapability(target);
  if (!sealed.ok) {
    return { outcome: sealed.outcome };
  }
  const opened = openDurableIssuanceCommand(sealed.sealed.issuance);
  if (!opened.accepted) {
    return { outcome: 'capability_required' };
  }
  const issued = await insertCapability(tx, opened.command);
  throwFault(fault, 'before_capability_validation');
  const clock = await tx.$queryRaw<Array<{ now: Date }>>`SELECT clock_timestamp() AS now`;
  const databaseNow = clock[0]?.now;
  if (!(databaseNow instanceof Date)) {
    return { outcome: 'malformed_persisted_state' };
  }
  const lifetime = classifyMaintainerReviewedAdvisoryApprovalCapabilityLifetime({
    issuedAt: issued.issued_at,
    expiresAt: issued.expires_at,
    databaseNow,
  });
  if (lifetime === 'malformed_persisted_state') {
    throw new PersistenceStop('malformed_persisted_state');
  }
  if (lifetime === 'capability_expired' || fault === 'force_capability_expired') {
    throw new PersistenceStop('capability_expired');
  }
  if (
    !issuanceCommandMatchesStored(opened.command, capabilityComparison(issued)) ||
    !durableCapabilityTtlExact(issued.issued_at, issued.expires_at)
  ) {
    throw new PersistenceStop('capability_rejected');
  }
  const mismatch = approvalMatchesCapability(derived.approval, capabilityComparison(issued));
  if (mismatch !== null) {
    throw new PersistenceStop(
      mismatch === 'authority_expired' ? 'capability_expired' : 'capability_rejected',
    );
  }
  throwFault(fault, 'before_approval_insert');
  const approvalId = await insertApproval(tx, revision, binding, derived.approval);
  throwFault(fault, 'before_capability_consumption');
  await insertConsumption(tx, issued.id, approvalId);
  if (fault !== 'skip_audit_insert') {
    throwFault(fault, 'before_audit_insert');
    await insertAudit(tx, admitted, revision.id, opened.command.issuerAuthorizationId);
  }
  await assertStoredState(tx, admitted, revision, issued.id, approvalId, fault);
  return { outcome: 'approved', revisionId: revision.id };
}

function envelopeLegal(
  revision: RevisionRow,
  binding: BindingRow | null,
  aliases: readonly AliasRow[],
  rangeEvents: readonly RangeEventRow[],
  vulnerability: { id: string; osv_id: string } | null,
): boolean {
  if (
    revision.trust_classification !== 'unreviewed' ||
    revision.revision_disposition !== 'recorded' ||
    revision.withdrawal_classification !== 'not_withdrawn' ||
    revision.quarantine_classification !== 'not_quarantined' ||
    revision.supersedes_revision_digest !== 'none' ||
    revision.author_identity === null ||
    revision.revision_schema_version !== PINS.revisionSchema ||
    revision.parser_id !== PINS.documentSchema ||
    revision.parser_resource_policy !== PINS.canonicalization ||
    revision.advisory_schema_version !== PINS.documentSchema ||
    revision.advisory_schema_commit !== PINS.schemaCommit ||
    revision.source_license_registry_version !== PINS.licensePolicyId ||
    revision.source_license_policy_version !== LICENSE_POLICY_VERSION ||
    revision.spdx_license_id !== MAINTAINER_REVIEWED_ACCEPTED_SPDX ||
    revision.provider_generation !== PINS.providerGeneration ||
    revision.retrieval_classification !== PINS.retrieval ||
    revision.retrieval_evidence_id !== PINS.retrievalEvidence ||
    revision.retrieval_policy_id !== PINS.retrievalPolicy ||
    revision.ecosystem !== MAINTAINER_REVIEWED_ECOSYSTEM ||
    revision.evaluator_version !== MAINTAINER_REVIEWED_EVALUATOR_VERSION ||
    revision.matching_policy_id !== MAINTAINER_REVIEWED_MATCHING_POLICY_ID ||
    revision.range_fingerprint !== revision.product_range_fingerprint ||
    !SHA256_HEX.test(revision.content_fingerprint) ||
    !SHA256_HEX.test(revision.range_fingerprint) ||
    !SHA256_HEX.test(revision.family_digest) ||
    !SHA256_HEX.test(revision.revision_digest) ||
    !SHA256_HEX.test(revision.replay_fingerprint) ||
    !packageKeyLegal(revision.package_identity_key)
  ) {
    return false;
  }
  if (
    binding === null ||
    vulnerability === null ||
    binding.vulnerability_id !== vulnerability.id ||
    vulnerability.osv_id !== `${LOCAL_VULNERABILITY_PREFIX}${vulnerability.id}` ||
    binding.binding_schema_version !== PINS.bindingSchema ||
    binding.mapping_policy_id !== VULNERABILITY_MAPPING_POLICY_ID ||
    binding.mapping_method !== EXACT_MAPPING_METHOD ||
    binding.mapping_review_state !== 'reviewed' ||
    binding.conflict_classification !== 'none' ||
    !SHA256_HEX.test(binding.replay_fingerprint)
  ) {
    return false;
  }
  return aliasesLegal(revision, aliases) && rangeEventsLegal(rangeEvents);
}

function packageKeyLegal(value: string): boolean {
  const parts = value.split('\u001f');
  return parts.length === 3 && parts[0] === 'npm' && parts[2] !== undefined && parts[2].length > 0;
}

function aliasesLegal(revision: RevisionRow, aliases: readonly AliasRow[]): boolean {
  if (aliases.length !== Number(revision.alias_count) || Number(revision.alias_count) < 0) {
    return false;
  }
  const cveCount = aliases.filter((alias) => alias.alias_type === 'canonical_cve').length;
  if (cveCount !== Number(revision.cve_alias_count)) {
    return false;
  }
  for (let index = 0; index < aliases.length; index += 1) {
    const alias = aliases[index];
    if (
      alias === undefined ||
      Number(alias.ordinal) !== index + 1 ||
      alias.alias_value.length < 1 ||
      alias.source_classification !== MAINTAINER_REVIEWED_ORIGIN ||
      alias.review_classification !== 'unreviewed' ||
      !SHA256_HEX.test(alias.replay_fingerprint) ||
      (alias.alias_type !== 'canonical_cve' && alias.alias_type !== 'provider_native')
    ) {
      return false;
    }
  }
  return true;
}

function rangeEventsLegal(events: readonly RangeEventRow[]): boolean {
  if (events.length === 0) {
    return false;
  }
  let previousRange = -1;
  let previousEvent = -1;
  for (const event of events) {
    if (
      !RANGE_EVENT_NAMES.has(event.event_name) ||
      event.event_value.length < 1 ||
      event.event_value.length > 256 ||
      Number(event.range_ordinal) < 0 ||
      Number(event.event_ordinal) < 0
    ) {
      return false;
    }
    const rangeOrdinal = Number(event.range_ordinal);
    const eventOrdinal = Number(event.event_ordinal);
    const contiguous =
      (previousRange === -1 && rangeOrdinal === 0 && eventOrdinal === 0) ||
      (rangeOrdinal === previousRange && eventOrdinal === previousEvent + 1) ||
      (rangeOrdinal === previousRange + 1 && eventOrdinal === 0);
    if (!contiguous) {
      return false;
    }
    previousRange = rangeOrdinal;
    previousEvent = eventOrdinal;
  }
  return true;
}

function semanticApproval(row: ApprovalRow): Record<string, unknown> {
  return {
    approvalSchemaVersion: row.approval_schema_version,
    advisoryRevisionId: row.advisory_revision_id,
    familyDigest: row.family_digest,
    approvalPolicyId: row.approval_policy_id,
    approvalPolicyVersion: Number(row.approval_policy_version),
    approvalPurpose: row.approval_purpose,
    sourceClassification: row.source_classification,
    authorIdentity: row.author_identity,
    reviewerIdentity: row.reviewer_identity,
    reviewerClassification: row.reviewer_classification,
    contentFingerprint: row.content_fingerprint,
    rangeFingerprint: row.range_fingerprint,
    packageIdentityKey: row.package_identity_key,
    vulnerabilityId: row.vulnerability_id,
    sourceLicensePolicyId: row.source_license_policy_id,
    sourceLicensePolicyVersion: Number(row.source_license_policy_version),
    approvedLicenseClassification: row.approved_license_classification,
    licenseDecisionCanonical: row.license_decision_canonical,
    replayFingerprint: row.replay_fingerprint,
  };
}

function replayLineageAgrees(
  approval: ApprovalRow,
  capability: CapabilityRow | undefined,
  reviewerUserId: string,
  revision: RevisionRow,
): boolean {
  if (capability === undefined) {
    return false;
  }
  return (
    approval.reviewer_identity === reviewerUserId &&
    approval.approval_purpose === MAINTAINER_REVIEWED_ADVISORY_APPROVAL_PURPOSE &&
    approval.advisory_revision_id === revision.id &&
    capability.advisory_revision_id === revision.id &&
    capability.reviewer_identity === reviewerUserId &&
    capability.author_identity === approval.author_identity &&
    capability.approval_purpose === approval.approval_purpose &&
    capability.content_fingerprint === revision.content_fingerprint &&
    capability.affected_range_fingerprint === revision.range_fingerprint &&
    capability.advisory_family_identity === revision.family_digest &&
    capability.issuance_schema_version === 'reviewer_approval_capability_v1' &&
    Number(capability.capability_policy_version) === 1 &&
    capability.observation_classification === 'consumed' &&
    capability.observation_approval_id === approval.id &&
    capability.issued_at instanceof Date &&
    capability.expires_at instanceof Date &&
    durableCapabilityTtlExact(capability.issued_at, capability.expires_at) &&
    SHA256_HEX.test(capability.issuer_decision_fingerprint) &&
    SHA256_HEX.test(capability.approval_claim_fingerprint) &&
    approval.author_identity === revision.author_identity &&
    approval.content_fingerprint === revision.content_fingerprint &&
    approval.range_fingerprint === revision.range_fingerprint &&
    approval.package_identity_key === revision.package_identity_key &&
    capability.npm_package_identity === approval.package_identity_key &&
    capability.vulnerability_id === approval.vulnerability_id &&
    capability.source_classification === approval.source_classification &&
    capability.source_classification === MAINTAINER_REVIEWED_ORIGIN &&
    capability.source_license_policy_id === approval.source_license_policy_id &&
    Number(capability.source_license_policy_version) ===
      Number(approval.source_license_policy_version) &&
    capability.approved_license_classification === approval.approved_license_classification &&
    capability.license_decision_canonical === approval.license_decision_canonical
  );
}

function capabilityComparison(row: CapabilityRow): StoredCapabilityComparison {
  return {
    capabilityPolicyId: row.capability_policy_id,
    capabilityPolicyVersion: Number(row.capability_policy_version),
    approvalPolicyId: row.approval_policy_id,
    approvalPolicyVersion: Number(row.approval_policy_version),
    approvalPurpose: row.approval_purpose,
    issuerAuthorizationId: row.issuer_authorization_id,
    issuerDecisionFingerprint: row.issuer_decision_fingerprint,
    approvalClaimFingerprint: row.approval_claim_fingerprint,
    advisoryFamilyIdentity: row.advisory_family_identity,
    advisoryRevisionId: row.advisory_revision_id,
    contentFingerprint: row.content_fingerprint,
    affectedRangeFingerprint: row.affected_range_fingerprint,
    npmPackageIdentity: row.npm_package_identity,
    vulnerabilityId: row.vulnerability_id,
    sourceLicensePolicyId: row.source_license_policy_id,
    sourceLicensePolicyVersion: Number(row.source_license_policy_version),
    approvedLicenseClassification: row.approved_license_classification,
    licenseDecisionCanonical: row.license_decision_canonical,
    sourceClassification: row.source_classification,
    authorIdentity: row.author_identity,
    reviewerIdentity: row.reviewer_identity,
    correlationId: row.correlation_id,
  };
}

async function insertCapability(
  tx: Prisma.TransactionClient,
  command: SealedDurableIssuanceCommand,
): Promise<CapabilityRow> {
  const request = command.request;
  const created = await tx.reviewerCapabilityIssuance.create({
    data: {
      issuanceSchemaVersion: command.issuanceSchemaVersion,
      capabilityPolicyId: request.capabilityPolicyId,
      capabilityPolicyVersion: request.capabilityPolicyVersion,
      approvalPolicyId: request.approvalPolicyId,
      approvalPolicyVersion: request.approvalPolicyVersion,
      approvalPurpose: request.approvalPurpose,
      issuerAuthorizationId: command.issuerAuthorizationId,
      issuerDecisionFingerprint: command.issuerDecisionFingerprint,
      approvalClaimFingerprint: command.approvalClaimFingerprint,
      advisoryFamilyIdentity: request.advisoryFamilyIdentity,
      advisoryRevisionId: request.advisoryRevisionId,
      contentFingerprint: request.contentFingerprint,
      affectedRangeFingerprint: request.affectedRangeFingerprint,
      npmPackageIdentity: request.npmPackageIdentity,
      vulnerabilityId: request.vulnerabilityId,
      sourceLicensePolicyId: request.sourceLicensePolicyId,
      sourceLicensePolicyVersion: request.sourceLicensePolicyVersion,
      approvedLicenseClassification: request.approvedLicenseClassification,
      licenseDecisionCanonical: request.licenseDecisionCanonical,
      sourceClassification: request.sourceClassification,
      authorIdentity: request.authorIdentity,
      reviewerIdentity: request.reviewerIdentity,
      correlationId: request.correlationId,
    },
    select: { id: true },
  });
  const rows = await loadCapabilities(tx, request.advisoryRevisionId);
  const row = rows.find((candidate) => candidate.id === created.id);
  if (row === undefined) {
    throw new PersistenceStop('malformed_persisted_state');
  }
  return row;
}

async function insertApproval(
  tx: Prisma.TransactionClient,
  revision: RevisionRow,
  binding: BindingRow,
  command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
): Promise<string> {
  const created = await tx.maintainerReviewedAdvisoryApproval.create({
    data: {
      approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
      advisoryRevisionId: revision.id,
      advisoryFamilyId: revision.advisory_family_id,
      familyDigest: revision.family_digest,
      approvalPolicyId: command.approvalPolicyId,
      approvalPolicyVersion: command.approvalPolicyVersion,
      approvalPurpose: command.approvalPurpose,
      sourceClassification: command.expectedSourceClassification,
      authorIdentity: command.authorIdentity,
      reviewerIdentity: command.reviewerIdentity,
      reviewerClassification: command.reviewerAuthorityClassification,
      contentFingerprint: command.expectedContentFingerprint,
      rangeFingerprint: command.expectedRangeFingerprint,
      packageIdentityKey: command.expectedNpmPackageIdentity,
      vulnerabilityId: command.expectedVulnerabilityId,
      advisoryVulnerabilityBindingId: binding.id,
      sourceLicensePolicyId: command.sourceLicensePolicyId,
      sourceLicensePolicyVersion: command.sourceLicensePolicyVersion,
      approvedLicenseClassification: command.approvedLicenseClassification,
      licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_LICENSE_CANONICAL,
      replayFingerprint: command.approvalReplayFingerprint,
    },
    select: { id: true },
  });
  return created.id;
}

async function insertConsumption(
  tx: Prisma.TransactionClient,
  capabilityIssuanceId: string,
  approvalId: string,
): Promise<void> {
  await tx.reviewerCapabilityLifecycleObservation.create({
    data: {
      capabilityIssuanceId,
      observationClassification: 'consumed',
      approvalId,
    },
  });
}

async function insertAudit(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revisionId: string,
  issuerAuthorizationId: string,
): Promise<void> {
  const intent = maintainerReviewedAdvisoryApprovalAuditIntent({
    outcome: 'approved',
    trustedReviewerUserId: admitted.trustedReviewerUserId,
    revisionId,
    correlationId: admitted.correlationId,
    issuerAuthorizationId,
    capabilityPolicyVersion: 1,
  });
  if (intent === null) {
    throw new PersistenceStop('internal_failure');
  }
  const payload = JSON.stringify(intent.payload);
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "occurred_at",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    ) VALUES (
      NULL,
      ${intent.actorUserId}::uuid,
      NULL,
      'user'::"audit_actor_type",
      ${intent.action},
      ${intent.subjectType},
      ${intent.subjectId}::uuid,
      CURRENT_TIMESTAMP,
      ${intent.correlationId},
      ${payload}::jsonb,
      1,
      'security'::"audit_retention_category"
    )
    RETURNING "id"::text AS id
  `;
  if (inserted.length !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function assertStoredState(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revision: RevisionRow,
  capabilityId: string,
  approvalId: string,
  fault: MaintainerReviewedAdvisoryApprovalPersistenceFault | undefined,
): Promise<void> {
  if (fault === 'fail_stored_state_validation') {
    throw new PersistenceStop('transaction_aborted');
  }
  throwFault(fault, 'before_stored_state_validation');
  const rows = await tx.$queryRaw<
    Array<{
      approvals: number;
      capabilities: number;
      observations: number;
      audits: number;
      matches: number;
      trust: string;
    }>
  >`
    SELECT
      (SELECT COUNT(*)::int FROM "maintainer_reviewed_advisory_approval" WHERE "advisory_revision_id" = ${revision.id}::uuid) AS approvals,
      (SELECT COUNT(*)::int FROM "reviewer_capability_issuance" WHERE "advisory_revision_id" = ${revision.id}::uuid) AS capabilities,
      (SELECT COUNT(*)::int FROM "reviewer_capability_lifecycle_observation" WHERE "capability_issuance_id" = ${capabilityId}::uuid AND "approval_id" = ${approvalId}::uuid AND "observation_classification" = 'consumed') AS observations,
      (SELECT COUNT(*)::int FROM "audit_event" WHERE "action" = ${MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION} AND "subject_id" = ${revision.id}::uuid AND "actor_user_id" = ${admitted.trustedReviewerUserId}::uuid AND "organization_id" IS NULL AND "actor_membership_id" IS NULL) AS audits,
      (SELECT COUNT(*)::int FROM "product_match_evaluation_evidence" WHERE "advisory_revision_id" = ${revision.id}::uuid) AS matches,
      (SELECT "trust_classification"::text FROM "advisory_revision" WHERE "id" = ${revision.id}::uuid) AS trust
  `;
  const row = rows[0];
  if (
    row === undefined ||
    Number(row.approvals) !== 1 ||
    Number(row.capabilities) !== 1 ||
    Number(row.observations) !== 1 ||
    Number(row.audits) !== 1 ||
    Number(row.matches) !== 0 ||
    row.trust !== 'unreviewed'
  ) {
    throw new PersistenceStop('malformed_persisted_state');
  }
}

async function rereadAfterPersistenceFailure(
  client: PrismaClient,
  admitted: Admitted,
): Promise<MaintainerReviewedAdvisoryApprovalResult> {
  try {
    const reread = await client.$transaction((tx) => apply(tx, admitted, undefined, false), {
      timeout: 20_000,
      maxWait: 5_000,
    });
    if (reread.outcome === 'approved') {
      return { outcome: 'transaction_aborted' };
    }
    return reread;
  } catch (error) {
    const failure = classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(error);
    if (failure === 'database_unavailable') {
      return { outcome: 'database_unavailable' };
    }
    if (failure === 'capability_expired') {
      return { outcome: 'capability_expired' };
    }
    return { outcome: 'transaction_aborted' };
  }
}

async function lockRevision(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<RevisionRow | null> {
  const rows = await tx.$queryRaw<RevisionRow[]>`
    SELECT
      "id"::text AS id,
      "advisory_family_id"::text AS advisory_family_id,
      "origin"::text AS origin,
      "source"::text AS source,
      "family_digest",
      "revision_digest",
      "content_fingerprint",
      "session14_range_fingerprint" AS range_fingerprint,
      "product_range_fingerprint",
      "author_identity",
      "package_identity_key",
      "trust_classification"::text AS trust_classification,
      "revision_disposition"::text AS revision_disposition,
      "quarantine_classification"::text AS quarantine_classification,
      "withdrawal_classification"::text AS withdrawal_classification,
      "supersedes_revision_digest",
      "revision_schema_version",
      "parser_id",
      "parser_resource_policy",
      "advisory_schema_version",
      "advisory_schema_commit",
      "source_license_registry_version",
      "source_license_policy_version",
      "spdx_license_id",
      "provider_generation",
      "retrieval_classification"::text AS retrieval_classification,
      "retrieval_evidence_id",
      "retrieval_policy_id",
      "ecosystem",
      "evaluator_version",
      "matching_policy_id",
      "replay_fingerprint",
      "alias_count",
      "cve_alias_count"
    FROM "advisory_revision"
    WHERE "id" = ${revisionId}::uuid
    FOR UPDATE
  `;
  if (rows.length > 1) {
    throw new PersistenceStop('malformed_persisted_state');
  }
  return rows[0] ?? null;
}

async function lockBinding(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<BindingRow | null> {
  const rows = await tx.$queryRaw<BindingRow[]>`
    SELECT
      "id"::text AS id,
      "vulnerability_id"::text AS vulnerability_id,
      "binding_schema_version",
      "mapping_policy_id",
      "mapping_method",
      "mapping_review_state",
      "conflict_classification",
      "binding_classification"::text AS binding_classification,
      "replay_fingerprint"
    FROM "advisory_vulnerability_binding"
    WHERE "advisory_revision_id" = ${revisionId}::uuid
    FOR UPDATE
  `;
  if (rows.length > 1) {
    throw new PersistenceStop('malformed_persisted_state');
  }
  return rows[0] ?? null;
}

async function lockAliases(tx: Prisma.TransactionClient, revisionId: string): Promise<AliasRow[]> {
  return tx.$queryRaw<AliasRow[]>`
    SELECT
      "ordinal",
      "alias_type"::text AS alias_type,
      "alias_value",
      "source_classification"::text AS source_classification,
      "review_classification"::text AS review_classification,
      "replay_fingerprint"
    FROM "advisory_revision_alias"
    WHERE "advisory_revision_id" = ${revisionId}::uuid
    ORDER BY "ordinal"
    FOR UPDATE
  `;
}

async function lockRangeEvents(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<RangeEventRow[]> {
  return tx.$queryRaw<RangeEventRow[]>`
    SELECT
      "range_ordinal",
      "event_ordinal",
      "event_name",
      "event_value"
    FROM "advisory_revision_range_event"
    WHERE "advisory_revision_id" = ${revisionId}::uuid
    ORDER BY "range_ordinal", "event_ordinal"
    FOR UPDATE
  `;
}

async function lockVulnerability(
  tx: Prisma.TransactionClient,
  vulnerabilityId: string,
): Promise<{ id: string; osv_id: string } | null> {
  const rows = await tx.$queryRaw<Array<{ id: string; osv_id: string }>>`
    SELECT "id"::text AS id, "osv_id"
    FROM "vulnerability"
    WHERE "id" = ${vulnerabilityId}::uuid
    FOR UPDATE
  `;
  if (rows.length > 1) {
    throw new PersistenceStop('malformed_persisted_state');
  }
  return rows[0] ?? null;
}

async function lockApprovals(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<ApprovalRow[]> {
  return tx.$queryRaw<ApprovalRow[]>`
    SELECT
      "id"::text AS id,
      "approval_schema_version",
      "advisory_revision_id"::text AS advisory_revision_id,
      "family_digest",
      "approval_policy_id",
      "approval_policy_version",
      "approval_purpose",
      "source_classification",
      "author_identity",
      "reviewer_identity",
      "reviewer_classification",
      "content_fingerprint",
      "range_fingerprint",
      "package_identity_key",
      "vulnerability_id"::text AS vulnerability_id,
      "source_license_policy_id",
      "source_license_policy_version",
      "approved_license_classification",
      "license_decision_canonical",
      "replay_fingerprint"
    FROM "maintainer_reviewed_advisory_approval"
    WHERE "advisory_revision_id" = ${revisionId}::uuid
    FOR UPDATE
  `;
}

async function lockCapabilities(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<CapabilityRow[]> {
  await tx.$queryRaw`
    SELECT "id"
    FROM "reviewer_capability_issuance"
    WHERE "advisory_revision_id" = ${revisionId}::uuid
    ORDER BY "id"
    FOR UPDATE
  `;
  return loadCapabilities(tx, revisionId);
}

async function loadCapabilities(
  tx: Prisma.TransactionClient,
  revisionId: string,
): Promise<CapabilityRow[]> {
  return tx.$queryRaw<CapabilityRow[]>`
    SELECT
      issuance."id"::text AS id,
      issuance."issuance_schema_version",
      issuance."capability_policy_id",
      issuance."capability_policy_version",
      issuance."approval_policy_id",
      issuance."approval_policy_version",
      issuance."approval_purpose",
      issuance."issuer_authorization_id"::text AS issuer_authorization_id,
      issuance."issuer_decision_fingerprint",
      issuance."approval_claim_fingerprint",
      issuance."advisory_family_identity",
      issuance."advisory_revision_id"::text AS advisory_revision_id,
      issuance."content_fingerprint",
      issuance."affected_range_fingerprint",
      issuance."npm_package_identity",
      issuance."vulnerability_id"::text AS vulnerability_id,
      issuance."source_license_policy_id",
      issuance."source_license_policy_version",
      issuance."approved_license_classification",
      issuance."license_decision_canonical",
      issuance."source_classification",
      issuance."author_identity",
      issuance."reviewer_identity",
      issuance."correlation_id"::text AS correlation_id,
      issuance."issued_at",
      issuance."expires_at",
      observation."observation_classification",
      observation."approval_id"::text AS observation_approval_id
    FROM "reviewer_capability_issuance" issuance
    LEFT JOIN "reviewer_capability_lifecycle_observation" observation
      ON observation."capability_issuance_id" = issuance."id"
    WHERE issuance."advisory_revision_id" = ${revisionId}::uuid
    ORDER BY issuance."id"
  `;
}

async function countAudits(
  tx: Prisma.TransactionClient,
  action: string,
  revisionId: string,
  actorUserId: string | null,
): Promise<number> {
  if (actorUserId === null) {
    return 0;
  }
  const rows = await tx.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count
    FROM "audit_event"
    WHERE "action" = ${action}
      AND "subject_type" = 'advisory_revision'
      AND "subject_id" = ${revisionId}::uuid
      AND "actor_type" = 'user'::"audit_actor_type"
      AND "actor_user_id" = ${actorUserId}::uuid
      AND "organization_id" IS NULL
      AND "actor_membership_id" IS NULL
  `;
  return Number(rows[0]?.count ?? 0);
}

function throwFault(
  fault: MaintainerReviewedAdvisoryApprovalPersistenceFault | undefined,
  stage: MaintainerReviewedAdvisoryApprovalPersistenceFault,
): void {
  if (fault === stage) {
    throw new PersistenceStop('transaction_aborted');
  }
}

function sqlState(error: unknown): string | null {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    if (typeof metaCode === 'string') {
      return metaCode;
    }
  }
  if (error instanceof Error) {
    const match = /(?:Code: `|code: "|SQLSTATE )([0-9A-Z]{5})/.exec(error.message);
    if (match?.[1] !== undefined) {
      return match[1];
    }
  }
  return null;
}

function isDatabaseUnavailable(error: unknown): boolean {
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return true;
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return (
      error.code === 'P1001' ||
      error.code === 'P1002' ||
      error.code === 'P1008' ||
      error.code === 'P1017' ||
      error.code === 'P2024'
    );
  }
  const text = error instanceof Error ? error.message : '';
  return text.includes("Can't reach database server") || text.includes('ECONNREFUSED');
}

function assertApprovalPort(
  factory: (client: PrismaClient) => MaintainerReviewedAdvisoryApprovalPersistencePort,
): void {
  void factory;
}

assertApprovalPort(createMaintainerReviewedAdvisoryApprovalApplicationPersistence);
