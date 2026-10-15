/**
 * PostgreSQL maintainer-reviewed advisory submission.
 * Constructed only by the API mutation application. Web, worker, seed,
 * the package barrel, and route handlers do not construct this adapter.
 *
 * Lock order, held to the end of the transaction:
 * 1. Submitter User FOR UPDATE.
 * 2. That user's instance advisory grants FOR UPDATE, ordered by id.
 * 3. Transaction-scoped advisory lock for the local natural identity.
 * 4. Advisory family and its revisions FOR UPDATE.
 * 5. Advisory-to-Vulnerability bindings FOR UPDATE.
 * 6. Alias and range-event rows FOR UPDATE.
 * 7. Vulnerability rows for the document id and the local label, ordered by id.
 * 8. Audit insert.
 * 9. Stored-state validation.
 *
 * User disablement and grant revocation lock the User, then that user's grants.
 * This transaction uses that prefix and does not invert it. Approval persistence
 * does not lock the User. The submission setting is transaction-local. Existing
 * guards do not treat it as a write bypass, and this adapter never sets the
 * approval, capability, Finding, or observation settings.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import { INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION } from '@patchpilot/domain/instance-advisory-authority';
import {
  MAINTAINER_REVIEWED_ACCEPTED_SPDX,
  MAINTAINER_REVIEWED_APPROVAL_LICENSE_CANONICAL,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
} from '@patchpilot/vulnerability-intelligence';
import {
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_BINDING,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_COMMAND_NAME,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_PERSISTENCE_FIELDS,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_UNAPPROVED_REVISION,
  classifyMaintainerReviewedAdvisorySubmissionAuthority,
  classifyMaintainerReviewedAdvisorySubmissionUniquenessViolation,
  localMaintainerReviewedSubmissionAliasReplayFingerprint,
  localMaintainerReviewedSubmissionBindingFingerprints,
  localMaintainerReviewedSubmissionReplayFingerprint,
  localMaintainerReviewedVulnerabilityLabel,
  maintainerReviewedAdvisorySubmissionAuditIntent,
  maintainerReviewedAdvisorySubmissionNaturalIdentity,
  parseMaintainerReviewedAdvisorySubmissionCommand,
  planMaintainerReviewedAdvisorySubmission,
  prepareMaintainerReviewedAdvisorySubmission,
  submissionBindingClassification,
  type MaintainerReviewedAdvisorySubmissionPersistenceCommand,
  type MaintainerReviewedAdvisorySubmissionPersistencePort,
  type MaintainerReviewedAdvisorySubmissionPlan,
  type MaintainerReviewedAdvisorySubmissionResult,
  type MaintainerReviewedAdvisoryStoredSubmission,
  type PreparedMaintainerReviewedAdvisorySubmission,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-submission';

import { reloadInstanceAdvisoryAuthorizationFacts } from './instance-advisory-authority-persistence.js';

const SUBMISSION_SETTING = 'patchpilot.maintainer_reviewed_advisory_submission';
const SHA256_HEX = /^[a-f0-9]{64}$/;
const RANGE_EVENT_NAMES = new Set(['introduced', 'fixed', 'last_affected', 'limit']);
const PINS = MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_UNAPPROVED_REVISION;
const BINDING = MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_BINDING;
const LICENSE_POLICY_VERSION = String(MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION);

export const MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_LOCK_ORDER = [
  'validate_command',
  'enable_transaction_local_submission_setting',
  'lock_submitter_user',
  'lock_instance_advisory_grants',
  'lock_natural_identity',
  'lock_advisory_family_and_revisions',
  'lock_advisory_vulnerability_bindings',
  'lock_alias_and_range_events',
  'lock_vulnerability_identity',
  'classify',
  'insert_vulnerability_when_absent',
  'insert_family_when_absent',
  'insert_unapproved_revision',
  'insert_aliases_when_required',
  'insert_range_events',
  'insert_binding',
  'insert_audit',
  'validate_stored_state',
  'commit',
] as const;

export const MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_PERSISTENCE_FAULTS = [
  'before_user_lock',
  'before_grant_lock',
  'before_natural_identity_lock',
  'before_replay_load',
  'before_vulnerability_resolution',
  'before_vulnerability_insert',
  'before_revision_insert',
  'before_binding_insert',
  'before_audit_insert',
  'before_stored_state_validation',
  'skip_alias_insert',
  'skip_audit_insert',
  'fail_stored_state_validation',
  'lose_acknowledgment',
] as const;

export type MaintainerReviewedAdvisorySubmissionPersistenceFault =
  (typeof MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_PERSISTENCE_FAULTS)[number];

export type MaintainerReviewedAdvisorySubmissionPersistenceOptions = {
  readonly fault?: MaintainerReviewedAdvisorySubmissionPersistenceFault;
};

type PersistenceFailure =
  'uniqueness' | 'transaction_aborted' | 'database_unavailable' | 'internal_failure';

class PersistenceStop extends Error {
  constructor(readonly outcome: 'transaction_aborted' | 'internal_failure') {
    super('maintainer-reviewed advisory submission persistence stopped');
  }
}

type Admitted = {
  readonly prepared: PreparedMaintainerReviewedAdvisorySubmission;
  readonly correlationId: string;
  readonly bindingClassification: 'one_cve_alias_evidence' | 'provider_native_without_cve';
  readonly naturalKey: string;
  readonly replayFingerprint: string;
};

type FamilyRow = {
  id: string;
  family_digest: string;
  source: string;
  advisory_id: string;
};

type RevisionRow = {
  id: string;
  origin: string;
  source: string;
  advisory_id: string;
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
  advisory_revision_id: string;
  vulnerability_id: string;
  binding_classification: string;
  replay_fingerprint: string;
  mapping_evidence_fingerprint: string;
};

type RangeEventRow = {
  advisory_revision_id: string;
  range_ordinal: number;
  event_ordinal: number;
  event_name: string;
  event_value: string;
};

type ExpectedRangeEvent = {
  readonly rangeOrdinal: number;
  readonly eventOrdinal: number;
  readonly eventName: string;
  readonly eventValue: string;
};

type VulnerabilityRow = {
  id: string;
  osv_id: string;
};

type Envelope =
  | { readonly kind: 'absent'; readonly familyId: string | null }
  | { readonly kind: 'malformed' }
  | { readonly kind: 'unsupported_origin' }
  | {
      readonly kind: 'present';
      readonly familyId: string;
      readonly stored: MaintainerReviewedAdvisoryStoredSubmission;
      readonly replayFingerprint: string;
      readonly bindingReplayFingerprint: string;
      readonly bindingEvidenceFingerprint: string;
      readonly schemaAgrees: boolean;
      readonly rangeEvents: readonly RangeEventRow[];
    };

export type MaintainerReviewedAdvisorySubmissionPersistence = {
  readonly submit: (
    command: MaintainerReviewedAdvisorySubmissionPersistenceCommand,
    options?: MaintainerReviewedAdvisorySubmissionPersistenceOptions,
  ) => Promise<MaintainerReviewedAdvisorySubmissionResult>;
};

export function createMaintainerReviewedAdvisorySubmissionPersistence(
  client: PrismaClient,
): MaintainerReviewedAdvisorySubmissionPersistence {
  return {
    async submit(
      command: MaintainerReviewedAdvisorySubmissionPersistenceCommand,
      options?: MaintainerReviewedAdvisorySubmissionPersistenceOptions,
    ): Promise<MaintainerReviewedAdvisorySubmissionResult> {
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
        if (fault === 'lose_acknowledgment' && result.outcome === 'submitted') {
          return { outcome: 'transaction_aborted' };
        }
        return result;
      } catch (error) {
        if (error instanceof PersistenceStop) {
          return { outcome: error.outcome };
        }
        const failure = classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(error);
        if (failure === 'database_unavailable') {
          return { outcome: 'database_unavailable' };
        }
        if (failure === 'uniqueness' || failure === 'transaction_aborted') {
          return rereadAfterPersistenceFailure(client, admitted.value);
        }
        return { outcome: 'internal_failure' };
      }
    },
  };
}

export function classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(
  error: unknown,
): PersistenceFailure {
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

async function apply(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  fault: MaintainerReviewedAdvisorySubmissionPersistenceFault | undefined,
  write: boolean,
): Promise<MaintainerReviewedAdvisorySubmissionResult> {
  await tx.$queryRaw`SELECT set_config(${SUBMISSION_SETTING}, 'on', true)`;
  throwFault(fault, 'before_user_lock');
  const users = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS id
    FROM "user"
    WHERE "id" = ${admitted.prepared.trustedSubmitterUserId}::uuid
    FOR UPDATE
  `;
  if (users.length > 1) {
    return { outcome: 'malformed_persisted_state' };
  }
  throwFault(fault, 'before_grant_lock');
  await tx.$queryRaw`
    SELECT "id"
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${admitted.prepared.trustedSubmitterUserId}::uuid
    ORDER BY "id"
    FOR UPDATE
  `;
  const facts = await reloadInstanceAdvisoryAuthorizationFacts(tx, {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
    userId: admitted.prepared.trustedSubmitterUserId,
    requiredAuthority: 'advisory_submit_local',
  });
  const authority = classifyMaintainerReviewedAdvisorySubmissionAuthority(
    admitted.prepared.trustedSubmitterUserId,
    facts,
  );
  if (authority !== 'authorized') {
    return { outcome: authority };
  }
  throwFault(fault, 'before_natural_identity_lock');
  await tx.$executeRaw`
    SELECT pg_advisory_xact_lock(hashtext(${admitted.naturalKey}))
  `;
  throwFault(fault, 'before_replay_load');
  const family = await lockFamily(tx, admitted);
  const revisions = family === null ? [] : await lockRevisions(tx, family.id);
  const revisionIds = revisions.map((revision) => revision.id);
  const bindings = await lockBindings(tx, revisionIds);
  const aliases = await loadAliases(tx, revisionIds);
  const rangeEvents = await lockRangeEvents(tx, revisionIds);
  const approvalCount = await countApprovals(tx, revisionIds);
  const capabilityCount = await countCapabilities(tx, revisionIds);
  throwFault(fault, 'before_vulnerability_resolution');
  const vulnerabilities = await lockVulnerabilities(tx, admitted);
  const envelope = classifyEnvelope(
    admitted,
    family,
    revisions,
    bindings,
    aliases,
    rangeEvents,
    approvalCount,
    capabilityCount,
    vulnerabilities,
  );
  if (envelope.kind === 'malformed') {
    return { outcome: 'malformed_persisted_state' };
  }
  if (envelope.kind === 'unsupported_origin') {
    return { outcome: 'unsupported_origin' };
  }
  const vulnerability = vulnerabilityFacts(admitted, vulnerabilities);
  const plan = planMaintainerReviewedAdvisorySubmission({
    authority: 'authorized',
    prepared: admitted.prepared,
    stored: envelope.kind === 'absent' ? { presence: 'absent' } : envelope.stored,
    vulnerability,
  });
  if (plan.outcome !== 'submitted') {
    if (plan.outcome === 'already_applied') {
      if (!exactEnvelopeAgrees(admitted, envelope)) {
        return { outcome: 'malformed_persisted_state' };
      }
      const audits = await countSubmissionAudits(
        tx,
        plan.revisionId,
        admitted.prepared.trustedSubmitterUserId,
      );
      if (audits !== 1) {
        return { outcome: 'malformed_persisted_state' };
      }
    }
    return planResult(plan);
  }
  if (!write) {
    return { outcome: 'transaction_aborted' };
  }
  const createdVulnerability = plan.vulnerabilityDecision === 'create';
  if (createdVulnerability) {
    throwFault(fault, 'before_vulnerability_insert');
    await insertVulnerability(tx, admitted);
  }
  const familyId = envelope.kind === 'absent' ? envelope.familyId : envelope.familyId;
  const resolvedFamilyId = familyId ?? (await insertFamily(tx, admitted));
  throwFault(fault, 'before_revision_insert');
  const revisionId = await insertRevision(tx, admitted, resolvedFamilyId);
  if (fault !== 'skip_alias_insert') {
    await insertAliases(tx, admitted, revisionId);
  }
  await insertRangeEvents(tx, admitted, revisionId);
  throwFault(fault, 'before_binding_insert');
  await insertBinding(tx, admitted, revisionId);
  if (fault !== 'skip_audit_insert') {
    throwFault(fault, 'before_audit_insert');
    await insertAudit(tx, admitted, revisionId);
  }
  await assertStoredState(tx, admitted, revisionId, createdVulnerability, fault);
  return { outcome: 'submitted', revisionId };
}

function exactEnvelopeAgrees(admitted: Admitted, envelope: Envelope): boolean {
  return (
    envelope.kind === 'present' &&
    envelope.schemaAgrees &&
    envelope.replayFingerprint === admitted.replayFingerprint &&
    envelope.bindingReplayFingerprint ===
      localMaintainerReviewedSubmissionBindingFingerprints({
        revisionDigest: admitted.prepared.command.fingerprints.revisionDigest,
        vulnerabilityId: admitted.prepared.command.document.vulnerabilityId,
        bindingClassification: admitted.bindingClassification,
        aliases: admitted.prepared.command.document.aliases,
      }).replayFingerprint &&
    rangeEventsMatch(
      envelope.rangeEvents,
      expectedRangeEvents(admitted.prepared.command.document.affectedRanges),
    )
  );
}

function planResult(
  plan: MaintainerReviewedAdvisorySubmissionPlan,
): MaintainerReviewedAdvisorySubmissionResult {
  if (plan.outcome === 'already_applied') {
    return { outcome: 'already_applied', revisionId: plan.revisionId };
  }
  if (plan.outcome === 'submitted') {
    return { outcome: 'internal_failure' };
  }
  return { outcome: plan.outcome };
}

async function rereadAfterPersistenceFailure(
  client: PrismaClient,
  admitted: Admitted,
): Promise<MaintainerReviewedAdvisorySubmissionResult> {
  try {
    const reread = await client.$transaction((tx) => apply(tx, admitted, undefined, false), {
      timeout: 20_000,
      maxWait: 5_000,
    });
    if (reread.outcome === 'submitted') {
      return unclassifiedPersistenceResult();
    }
    return reread;
  } catch (error) {
    const failure = classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(error);
    if (failure === 'database_unavailable') {
      return { outcome: 'database_unavailable' };
    }
    return unclassifiedPersistenceResult();
  }
}

function unclassifiedPersistenceResult(): MaintainerReviewedAdvisorySubmissionResult {
  const plan = classifyMaintainerReviewedAdvisorySubmissionUniquenessViolation('unreadable');
  if (plan.outcome === 'already_applied') {
    return { outcome: 'already_applied', revisionId: plan.revisionId };
  }
  if (plan.outcome === 'submitted') {
    return { outcome: 'transaction_aborted' };
  }
  return { outcome: plan.outcome };
}

function vulnerabilityFacts(
  admitted: Admitted,
  rows: readonly VulnerabilityRow[],
): {
  readonly rowForDocumentId:
    | { readonly existence: 'absent' }
    | { readonly existence: 'malformed' }
    | { readonly existence: 'present'; readonly id: string; readonly osvId: string };
  readonly rowOwningDerivedLabel: { readonly id: string } | null;
} {
  const vulnerabilityId = admitted.prepared.command.document.vulnerabilityId;
  const label = localMaintainerReviewedVulnerabilityLabel(vulnerabilityId);
  const byId = rows.filter((row) => row.id === vulnerabilityId);
  const byLabel = rows.filter((row) => row.osv_id === label);
  const owner = byLabel[0];
  return {
    rowForDocumentId:
      byId.length > 1
        ? { existence: 'malformed' }
        : byId.length === 0
          ? { existence: 'absent' }
          : {
              existence: 'present',
              id: byId[0]?.id ?? vulnerabilityId,
              osvId: byId[0]?.osv_id ?? '',
            },
    rowOwningDerivedLabel:
      byLabel.length === 1 && owner !== undefined
        ? { id: owner.id }
        : byLabel.length > 1
          ? { id: '' }
          : null,
  };
}

function classifyEnvelope(
  admitted: Admitted,
  family: FamilyRow | null,
  revisions: readonly RevisionRow[],
  bindings: readonly BindingRow[],
  aliases: ReadonlyMap<string, readonly string[]>,
  rangeEvents: readonly RangeEventRow[],
  approvalCount: number,
  capabilityCount: number,
  vulnerabilities: readonly VulnerabilityRow[],
): Envelope {
  const expectedDigest = admitted.prepared.command.fingerprints.familyDigest;
  if (
    family !== null &&
    (family.family_digest !== expectedDigest || family.source !== PINS.source)
  ) {
    return { kind: 'malformed' };
  }
  if (revisions.length > 1) {
    return { kind: 'malformed' };
  }
  if (revisions.length === 0) {
    return { kind: 'absent', familyId: family?.id ?? null };
  }
  const revision = revisions[0];
  if (revision === undefined) {
    return { kind: 'malformed' };
  }
  if (revision.origin !== PINS.origin) {
    return { kind: 'unsupported_origin' };
  }
  if (!localShapeIsReadable(revision)) {
    return { kind: 'malformed' };
  }
  const revisionBindings = bindings.filter(
    (binding) => binding.advisory_revision_id === revision.id,
  );
  const revisionAliases = aliases.get(revision.id) ?? [];
  if (
    revision.trust_classification !== PINS.trustClassification ||
    revisionBindings.length !== 1 ||
    revisionAliases.length !== Number(revision.alias_count) ||
    approvalCount !== 0 ||
    capabilityCount !== 0 ||
    revision.range_fingerprint !== revision.product_range_fingerprint ||
    !schemaAgrees(revision)
  ) {
    return { kind: 'malformed' };
  }
  const revisionEvents = rangeEvents.filter((event) => event.advisory_revision_id === revision.id);
  if (!storedRangeEventsAreLegal(revisionEvents)) {
    return { kind: 'malformed' };
  }
  const binding = revisionBindings[0];
  if (
    binding === undefined ||
    !SHA256_HEX.test(binding.replay_fingerprint) ||
    (binding.binding_classification !== 'one_cve_alias_evidence' &&
      binding.binding_classification !== 'provider_native_without_cve')
  ) {
    return { kind: 'malformed' };
  }
  const contentAgrees =
    revision.content_fingerprint === admitted.prepared.command.fingerprints.contentFingerprint;
  if (
    contentAgrees &&
    (binding.vulnerability_id !== admitted.prepared.command.document.vulnerabilityId ||
      revision.spdx_license_id !== MAINTAINER_REVIEWED_ACCEPTED_SPDX)
  ) {
    return { kind: 'malformed' };
  }
  const stored: MaintainerReviewedAdvisoryStoredSubmission = {
    presence: 'present',
    revisionId: revision.id,
    origin: revision.origin,
    source: revision.source,
    advisoryFamilyId: revision.advisory_id,
    revisionNumber: 1,
    authorIdentity: revision.author_identity ?? '',
    contentFingerprint: revision.content_fingerprint,
    rangeFingerprint: revision.range_fingerprint,
    productRangeFingerprint: revision.product_range_fingerprint,
    familyDigest: revision.family_digest,
    revisionDigest: revision.revision_digest,
    vulnerabilityId: binding.vulnerability_id,
    packageIdentityKey: revision.package_identity_key,
    aliases: revisionAliases,
    licenseCanonical: MAINTAINER_REVIEWED_APPROVAL_LICENSE_CANONICAL,
    withdrawal: revision.withdrawal_classification,
    supersedesRevisionDigest: revision.supersedes_revision_digest,
    trustClassification: revision.trust_classification,
    revisionDisposition: revision.revision_disposition,
    quarantineClassification: revision.quarantine_classification,
    binding: {
      vulnerabilityId: binding.vulnerability_id,
      bindingClassification: binding.binding_classification,
    },
    vulnerabilityOsvId:
      vulnerabilities.find((row) => row.id === binding.vulnerability_id)?.osv_id ?? null,
    approvalPresent: false,
  };
  return {
    kind: 'present',
    familyId: family?.id ?? '',
    stored,
    replayFingerprint: revision.replay_fingerprint,
    bindingReplayFingerprint: binding.replay_fingerprint,
    bindingEvidenceFingerprint: binding.mapping_evidence_fingerprint,
    schemaAgrees: true,
    rangeEvents: revisionEvents,
  };
}

function localShapeIsReadable(revision: RevisionRow): boolean {
  return (
    revision.author_identity !== null &&
    SHA256_HEX.test(revision.content_fingerprint) &&
    SHA256_HEX.test(revision.range_fingerprint) &&
    SHA256_HEX.test(revision.product_range_fingerprint) &&
    SHA256_HEX.test(revision.family_digest) &&
    SHA256_HEX.test(revision.revision_digest) &&
    SHA256_HEX.test(revision.replay_fingerprint) &&
    revision.source === PINS.source
  );
}

function schemaAgrees(revision: RevisionRow): boolean {
  return (
    revision.revision_schema_version === PINS.revisionSchema &&
    revision.parser_id === PINS.parserId &&
    revision.parser_resource_policy === PINS.parserResourcePolicy &&
    revision.advisory_schema_version === PINS.documentSchema &&
    revision.advisory_schema_commit === PINS.schemaCommit &&
    revision.source_license_registry_version === PINS.sourceRegistry &&
    revision.source_license_policy_version === LICENSE_POLICY_VERSION &&
    revision.spdx_license_id === MAINTAINER_REVIEWED_ACCEPTED_SPDX &&
    revision.provider_generation === PINS.providerGeneration &&
    revision.retrieval_classification === PINS.retrieval &&
    revision.retrieval_evidence_id === PINS.retrievalEvidence &&
    revision.retrieval_policy_id === PINS.retrievalPolicy &&
    revision.ecosystem === PINS.ecosystem &&
    revision.evaluator_version === PINS.evaluatorVersion &&
    revision.matching_policy_id === PINS.matchingPolicyId &&
    revision.trust_classification === PINS.trustClassification &&
    revision.revision_disposition === PINS.revisionDisposition &&
    revision.withdrawal_classification === PINS.withdrawalClassification &&
    revision.quarantine_classification === PINS.quarantineClassification &&
    revision.supersedes_revision_digest === PINS.supersedesRevisionDigest
  );
}

async function lockFamily(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
): Promise<FamilyRow | null> {
  const rows = await tx.$queryRaw<FamilyRow[]>`
    SELECT
      "id"::text AS id,
      "family_digest",
      "source"::text AS source,
      "advisory_id"
    FROM "advisory_family"
    WHERE "source" = ${PINS.source}::"advisory_evidence_source"
      AND "advisory_id" = ${admitted.prepared.command.document.advisoryFamilyId}
    FOR UPDATE
  `;
  if (rows.length > 1) {
    throw new PersistenceStop('internal_failure');
  }
  return rows[0] ?? null;
}

async function lockRevisions(
  tx: Prisma.TransactionClient,
  familyId: string,
): Promise<RevisionRow[]> {
  const rows = await tx.$queryRaw<RevisionRow[]>`
    SELECT
      "id"::text AS id,
      "origin"::text AS origin,
      "source"::text AS source,
      "advisory_id",
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
    WHERE "advisory_family_id" = ${familyId}::uuid
    ORDER BY "id"
    FOR UPDATE
  `;
  return rows.map((row) => ({
    ...row,
    alias_count: Number(row.alias_count),
    cve_alias_count: Number(row.cve_alias_count),
  }));
}

async function lockBindings(
  tx: Prisma.TransactionClient,
  revisionIds: readonly string[],
): Promise<BindingRow[]> {
  if (revisionIds.length === 0) {
    return [];
  }
  return tx.$queryRaw<BindingRow[]>`
    SELECT
      "id"::text AS id,
      "advisory_revision_id"::text AS advisory_revision_id,
      "vulnerability_id"::text AS vulnerability_id,
      "binding_classification"::text AS binding_classification,
      "replay_fingerprint",
      "mapping_evidence_fingerprint"
    FROM "advisory_vulnerability_binding"
    WHERE "advisory_revision_id" IN (${Prisma.join(revisionIds.map((id) => Prisma.sql`${id}::uuid`))})
    ORDER BY "id"
    FOR UPDATE
  `;
}

async function lockRangeEvents(
  tx: Prisma.TransactionClient,
  revisionIds: readonly string[],
): Promise<RangeEventRow[]> {
  if (revisionIds.length === 0) {
    return [];
  }
  const rows = await tx.$queryRaw<RangeEventRow[]>`
    SELECT
      "advisory_revision_id"::text AS advisory_revision_id,
      "range_ordinal"::int AS range_ordinal,
      "event_ordinal"::int AS event_ordinal,
      "event_name",
      "event_value"
    FROM "advisory_revision_range_event"
    WHERE "advisory_revision_id" IN (${Prisma.join(revisionIds.map((id) => Prisma.sql`${id}::uuid`))})
    ORDER BY "advisory_revision_id", "range_ordinal", "event_ordinal"
    FOR UPDATE
  `;
  return rows.map((row) => ({
    ...row,
    range_ordinal: Number(row.range_ordinal),
    event_ordinal: Number(row.event_ordinal),
  }));
}

async function loadAliases(
  tx: Prisma.TransactionClient,
  revisionIds: readonly string[],
): Promise<Map<string, string[]>> {
  const grouped = new Map<string, string[]>();
  if (revisionIds.length === 0) {
    return grouped;
  }
  const rows = await tx.$queryRaw<
    Array<{ advisory_revision_id: string; alias_value: string; ordinal: number }>
  >`
    SELECT
      "advisory_revision_id"::text AS advisory_revision_id,
      "alias_value",
      "ordinal"
    FROM "advisory_revision_alias"
    WHERE "advisory_revision_id" IN (${Prisma.join(revisionIds.map((id) => Prisma.sql`${id}::uuid`))})
    ORDER BY "advisory_revision_id", "ordinal"
    FOR UPDATE
  `;
  for (const row of rows) {
    const current = grouped.get(row.advisory_revision_id) ?? [];
    current.push(row.alias_value);
    grouped.set(row.advisory_revision_id, current);
  }
  return grouped;
}

async function countSubmissionAudits(
  tx: Prisma.TransactionClient,
  revisionId: string,
  submitterUserId: string,
): Promise<number> {
  const rows = await tx.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count
    FROM "audit_event"
    WHERE "action" = ${MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION}
      AND "subject_type" = 'advisory_revision'
      AND "subject_id" = ${revisionId}::uuid
      AND "actor_type" = 'user'::"audit_actor_type"
      AND "actor_user_id" = ${submitterUserId}::uuid
      AND "organization_id" IS NULL
      AND "actor_membership_id" IS NULL
  `;
  return Number(rows[0]?.count ?? 0);
}

async function countApprovals(
  tx: Prisma.TransactionClient,
  revisionIds: readonly string[],
): Promise<number> {
  if (revisionIds.length === 0) {
    return 0;
  }
  const rows = await tx.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count
    FROM "maintainer_reviewed_advisory_approval"
    WHERE "advisory_revision_id" IN (${Prisma.join(revisionIds.map((id) => Prisma.sql`${id}::uuid`))})
  `;
  return Number(rows[0]?.count ?? 0);
}

async function countCapabilities(
  tx: Prisma.TransactionClient,
  revisionIds: readonly string[],
): Promise<number> {
  if (revisionIds.length === 0) {
    return 0;
  }
  const rows = await tx.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count
    FROM "reviewer_capability_issuance"
    WHERE "advisory_revision_id" IN (${Prisma.join(revisionIds.map((id) => Prisma.sql`${id}::uuid`))})
  `;
  return Number(rows[0]?.count ?? 0);
}

async function lockVulnerabilities(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
): Promise<VulnerabilityRow[]> {
  const vulnerabilityId = admitted.prepared.command.document.vulnerabilityId;
  const label = localMaintainerReviewedVulnerabilityLabel(vulnerabilityId);
  return tx.$queryRaw<VulnerabilityRow[]>`
    SELECT "id"::text AS id, "osv_id"
    FROM "vulnerability"
    WHERE "id" = ${vulnerabilityId}::uuid
       OR "osv_id" = ${label}
    ORDER BY "id"
    FOR UPDATE
  `;
}

async function insertVulnerability(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
): Promise<void> {
  const vulnerabilityId = admitted.prepared.command.document.vulnerabilityId;
  const label = localMaintainerReviewedVulnerabilityLabel(vulnerabilityId);
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "vulnerability" (
      "id",
      "osv_id",
      "cve_id",
      "status",
      "created_at",
      "updated_at"
    ) VALUES (
      ${vulnerabilityId}::uuid,
      ${label},
      NULL,
      'active'::"vulnerability_status",
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP
    )
    RETURNING "id"::text AS id
  `;
  if (inserted.length !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function insertFamily(tx: Prisma.TransactionClient, admitted: Admitted): Promise<string> {
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "advisory_family" (
      "family_schema_version",
      "source",
      "advisory_id",
      "family_digest",
      "source_registry_version"
    ) VALUES (
      ${PINS.familySchema},
      ${PINS.source}::"advisory_evidence_source",
      ${admitted.prepared.command.document.advisoryFamilyId},
      ${admitted.prepared.command.fingerprints.familyDigest},
      ${PINS.sourceRegistry}
    )
    RETURNING "id"::text AS id
  `;
  const familyId = inserted[0]?.id;
  if (inserted.length !== 1 || familyId === undefined) {
    throw new PersistenceStop('transaction_aborted');
  }
  return familyId;
}

async function insertRevision(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  familyId: string,
): Promise<string> {
  const document = admitted.prepared.command.document;
  const fingerprints = admitted.prepared.command.fingerprints;
  const bindingFingerprints = localMaintainerReviewedSubmissionBindingFingerprints({
    revisionDigest: fingerprints.revisionDigest,
    vulnerabilityId: document.vulnerabilityId,
    bindingClassification: admitted.bindingClassification,
    aliases: document.aliases,
  });
  const aliasCount = document.aliases.length;
  const cveAliasCount = admitted.bindingClassification === 'one_cve_alias_evidence' ? 1 : 0;
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "advisory_revision" (
      "revision_schema_version",
      "advisory_family_id",
      "source",
      "advisory_id",
      "family_digest",
      "revision_digest",
      "provider_generation",
      "content_fingerprint",
      "session14_range_fingerprint",
      "product_range_fingerprint",
      "parser_id",
      "parser_resource_policy",
      "advisory_schema_version",
      "author_identity",
      "advisory_schema_commit",
      "source_license_registry_version",
      "source_license_policy_version",
      "spdx_license_id",
      "origin",
      "trust_classification",
      "revision_disposition",
      "withdrawal_classification",
      "quarantine_classification",
      "supersedes_revision_digest",
      "retrieval_classification",
      "retrieval_evidence_id",
      "retrieval_policy_id",
      "ecosystem",
      "package_name",
      "package_identity_key",
      "evaluator_version",
      "matching_policy_id",
      "alias_count",
      "cve_alias_count",
      "alias_set_digest",
      "replay_fingerprint"
    ) VALUES (
      ${PINS.revisionSchema},
      ${familyId}::uuid,
      ${PINS.source}::"advisory_evidence_source",
      ${document.advisoryFamilyId},
      ${fingerprints.familyDigest},
      ${fingerprints.revisionDigest},
      ${PINS.providerGeneration},
      ${fingerprints.contentFingerprint},
      ${fingerprints.rangeFingerprint},
      ${fingerprints.rangeFingerprint},
      ${PINS.parserId},
      ${PINS.parserResourcePolicy},
      ${PINS.documentSchema},
      ${admitted.prepared.trustedSubmitterUserId},
      ${PINS.schemaCommit},
      ${PINS.sourceRegistry},
      ${LICENSE_POLICY_VERSION},
      ${MAINTAINER_REVIEWED_ACCEPTED_SPDX},
      ${PINS.origin}::"advisory_evidence_origin",
      ${PINS.trustClassification}::"advisory_evidence_trust",
      ${PINS.revisionDisposition}::"advisory_revision_disposition",
      ${PINS.withdrawalClassification}::"advisory_withdrawal_classification",
      ${PINS.quarantineClassification}::"advisory_quarantine_classification",
      ${PINS.supersedesRevisionDigest},
      ${PINS.retrieval}::"advisory_retrieval_classification",
      ${PINS.retrievalEvidence},
      ${PINS.retrievalPolicy},
      ${PINS.ecosystem},
      ${document.packageName},
      ${document.packageIdentityKey},
      ${PINS.evaluatorVersion},
      ${PINS.matchingPolicyId},
      ${aliasCount},
      ${cveAliasCount},
      ${bindingFingerprints.aliasSetDigest},
      ${admitted.replayFingerprint}
    )
    RETURNING "id"::text AS id
  `;
  const revisionId = inserted[0]?.id;
  if (inserted.length !== 1 || revisionId === undefined) {
    throw new PersistenceStop('transaction_aborted');
  }
  return revisionId;
}

async function insertAliases(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revisionId: string,
): Promise<void> {
  const aliases = admitted.prepared.command.document.aliases;
  for (let index = 0; index < aliases.length; index += 1) {
    const alias = aliases[index];
    if (alias === undefined) {
      throw new PersistenceStop('internal_failure');
    }
    const ordinal = index + 1;
    const replay = localMaintainerReviewedSubmissionAliasReplayFingerprint({
      revisionDigest: admitted.prepared.command.fingerprints.revisionDigest,
      ordinal,
      aliasValue: alias,
    });
    const inserted = await tx.$queryRaw<Array<{ id: string }>>`
      INSERT INTO "advisory_revision_alias" (
        "advisory_revision_id",
        "ordinal",
        "alias_type",
        "alias_value",
        "alias_policy_version",
        "source_classification",
        "review_classification",
        "replay_fingerprint"
      ) VALUES (
        ${revisionId}::uuid,
        ${ordinal},
        ${BINDING.aliasTypeWhenPresent}::"advisory_alias_type",
        ${alias},
        ${BINDING.aliasPolicyVersion},
        ${PINS.origin}::"advisory_evidence_origin",
        ${BINDING.aliasReviewClassification}::"advisory_alias_review",
        ${replay}
      )
      RETURNING "id"::text AS id
    `;
    if (inserted.length !== 1) {
      throw new PersistenceStop('transaction_aborted');
    }
  }
}

async function insertRangeEvents(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revisionId: string,
): Promise<void> {
  const events = expectedRangeEvents(admitted.prepared.command.document.affectedRanges);
  if (events === null || events.length === 0) {
    throw new PersistenceStop('internal_failure');
  }
  for (const event of events) {
    const inserted = await tx.$queryRaw<Array<{ id: string }>>`
      INSERT INTO "advisory_revision_range_event" (
        "advisory_revision_id",
        "range_ordinal",
        "event_ordinal",
        "event_name",
        "event_value"
      ) VALUES (
        ${revisionId}::uuid,
        ${event.rangeOrdinal},
        ${event.eventOrdinal},
        ${event.eventName},
        ${event.eventValue}
      )
      RETURNING "id"::text AS id
    `;
    if (inserted.length !== 1) {
      throw new PersistenceStop('transaction_aborted');
    }
  }
}

function expectedRangeEvents(
  ranges: PreparedMaintainerReviewedAdvisorySubmission['command']['document']['affectedRanges'],
): readonly ExpectedRangeEvent[] | null {
  const events: ExpectedRangeEvent[] = [];
  for (let rangeOrdinal = 0; rangeOrdinal < ranges.length; rangeOrdinal += 1) {
    const range = ranges[rangeOrdinal];
    if (range === undefined || rangeOrdinal > 31) {
      return null;
    }
    for (let eventOrdinal = 0; eventOrdinal < range.events.length; eventOrdinal += 1) {
      const event = range.events[eventOrdinal];
      if (event === undefined || eventOrdinal > 15) {
        return null;
      }
      const names = Object.keys(event);
      const name = names[0];
      if (names.length !== 1 || name === undefined || !RANGE_EVENT_NAMES.has(name)) {
        return null;
      }
      const value = event[name as keyof typeof event];
      if (typeof value !== 'string' || value.length < 1 || value.length > 256) {
        return null;
      }
      events.push({
        rangeOrdinal,
        eventOrdinal,
        eventName: name,
        eventValue: value,
      });
    }
  }
  return events;
}

function storedRangeEventsAreLegal(events: readonly RangeEventRow[]): boolean {
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
      event.range_ordinal < 0 ||
      event.range_ordinal > 31 ||
      event.event_ordinal < 0 ||
      event.event_ordinal > 15
    ) {
      return false;
    }
    const contiguous =
      (previousRange === -1 && event.range_ordinal === 0 && event.event_ordinal === 0) ||
      (event.range_ordinal === previousRange && event.event_ordinal === previousEvent + 1) ||
      (event.range_ordinal === previousRange + 1 && event.event_ordinal === 0);
    if (!contiguous) {
      return false;
    }
    previousRange = event.range_ordinal;
    previousEvent = event.event_ordinal;
  }
  return true;
}

function rangeEventsMatch(
  stored: readonly RangeEventRow[],
  expected: readonly ExpectedRangeEvent[] | null,
): boolean {
  if (expected === null || stored.length !== expected.length) {
    return false;
  }
  for (let index = 0; index < stored.length; index += 1) {
    const left = stored[index];
    const right = expected[index];
    if (
      left === undefined ||
      right === undefined ||
      left.range_ordinal !== right.rangeOrdinal ||
      left.event_ordinal !== right.eventOrdinal ||
      left.event_name !== right.eventName ||
      left.event_value !== right.eventValue
    ) {
      return false;
    }
  }
  return true;
}

async function insertBinding(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revisionId: string,
): Promise<void> {
  const document = admitted.prepared.command.document;
  const fingerprints = localMaintainerReviewedSubmissionBindingFingerprints({
    revisionDigest: admitted.prepared.command.fingerprints.revisionDigest,
    vulnerabilityId: document.vulnerabilityId,
    bindingClassification: admitted.bindingClassification,
    aliases: document.aliases,
  });
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "advisory_vulnerability_binding" (
      "binding_schema_version",
      "advisory_revision_id",
      "vulnerability_id",
      "mapping_policy_id",
      "mapping_method",
      "mapping_evidence_fingerprint",
      "mapping_review_state",
      "mapping_source_classification",
      "conflict_classification",
      "binding_classification",
      "replay_fingerprint"
    ) VALUES (
      ${BINDING.schemaVersion},
      ${revisionId}::uuid,
      ${document.vulnerabilityId}::uuid,
      ${BINDING.mappingPolicyId},
      ${BINDING.mappingMethod},
      ${fingerprints.mappingEvidenceFingerprint},
      ${BINDING.mappingReviewState},
      ${BINDING.mappingSourceClassification},
      ${BINDING.conflictClassification},
      ${admitted.bindingClassification}::"advisory_binding_classification",
      ${fingerprints.replayFingerprint}
    )
    RETURNING "id"::text AS id
  `;
  if (inserted.length !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function insertAudit(
  tx: Prisma.TransactionClient,
  admitted: Admitted,
  revisionId: string,
): Promise<void> {
  const intent = maintainerReviewedAdvisorySubmissionAuditIntent({
    outcome: 'submitted',
    trustedSubmitterUserId: admitted.prepared.trustedSubmitterUserId,
    revisionId,
    correlationId: admitted.correlationId,
    bindingClassification: admitted.bindingClassification,
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
  revisionId: string,
  createdVulnerability: boolean,
  fault: MaintainerReviewedAdvisorySubmissionPersistenceFault | undefined,
): Promise<void> {
  if (fault === 'fail_stored_state_validation') {
    throw new PersistenceStop('transaction_aborted');
  }
  throwFault(fault, 'before_stored_state_validation');
  const vulnerabilityId = admitted.prepared.command.document.vulnerabilityId;
  const rows = await tx.$queryRaw<
    Array<{
      revision_ok: boolean;
      binding_count: number;
      alias_count: number;
      audit_count: number;
      approval_count: number;
      capability_count: number;
      range_count: number;
      vulnerability_written: boolean;
      downstream: number;
    }>
  >`
    SELECT
      (
        SELECT COUNT(*)
        FROM "advisory_revision"
        WHERE "id" = ${revisionId}::uuid
          AND "origin"::text = ${PINS.origin}
          AND "trust_classification"::text = ${PINS.trustClassification}
          AND "author_identity" = ${admitted.prepared.trustedSubmitterUserId}
          AND "replay_fingerprint" = ${admitted.replayFingerprint}
          AND xmin = pg_current_xact_id()::xid
      ) = 1 AS revision_ok,
      (
        SELECT COUNT(*)
        FROM "advisory_vulnerability_binding"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
          AND "vulnerability_id" = ${vulnerabilityId}::uuid
          AND xmin = pg_current_xact_id()::xid
      )::int AS binding_count,
      (
        SELECT COUNT(*)
        FROM "advisory_revision_alias"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
          AND xmin = pg_current_xact_id()::xid
      )::int AS alias_count,
      (
        SELECT COUNT(*)
        FROM "audit_event"
        WHERE "action" = ${MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION}
          AND "subject_type" = 'advisory_revision'
          AND "subject_id" = ${revisionId}::uuid
          AND "actor_type" = 'user'::"audit_actor_type"
          AND "actor_user_id" = ${admitted.prepared.trustedSubmitterUserId}::uuid
          AND "organization_id" IS NULL
          AND "actor_membership_id" IS NULL
          AND xmin = pg_current_xact_id()::xid
      )::int AS audit_count,
      (
        SELECT COUNT(*)
        FROM "advisory_revision_range_event"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
          AND xmin = pg_current_xact_id()::xid
      )::int AS range_count,
      (
        SELECT COUNT(*)
        FROM "maintainer_reviewed_advisory_approval"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
      )::int AS approval_count,
      (
        SELECT COUNT(*)
        FROM "reviewer_capability_issuance"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
      )::int AS capability_count,
      (
        SELECT xmin = pg_current_xact_id()::xid
        FROM "vulnerability"
        WHERE "id" = ${vulnerabilityId}::uuid
      ) AS vulnerability_written,
      (
        (SELECT COUNT(*) FROM "organization" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "membership" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "maintainer_reviewed_advisory_approval" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "reviewer_capability_issuance" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "reviewer_capability_lifecycle_observation" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "product_match_evaluation_evidence" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "match_evaluation_evidence" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "finding" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "finding_observation" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "vulnerability_source_record" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "vulnerability_alias" WHERE xmin = pg_current_xact_id()::xid) +
        (SELECT COUNT(*) FROM "user" WHERE xmin = pg_current_xact_id()::xid)
      )::int AS downstream
  `;
  const row = rows[0];
  const expectedAliases =
    fault === 'skip_alias_insert' ? null : admitted.prepared.command.document.aliases.length;
  const expectedAudits = fault === 'skip_audit_insert' ? 0 : 1;
  const expectedRanges = expectedRangeEvents(admitted.prepared.command.document.affectedRanges);
  if (
    row === undefined ||
    expectedRanges === null ||
    row.revision_ok !== true ||
    Number(row.binding_count) !== 1 ||
    Number(row.approval_count) !== 0 ||
    Number(row.capability_count) !== 0 ||
    Number(row.range_count) !== expectedRanges.length ||
    Number(row.downstream) !== 0 ||
    (expectedAliases !== null && Number(row.alias_count) !== expectedAliases) ||
    Number(row.audit_count) !== expectedAudits
  ) {
    throw new PersistenceStop('transaction_aborted');
  }
  if (createdVulnerability !== (row.vulnerability_written === true)) {
    throw new PersistenceStop('transaction_aborted');
  }
  if (fault === 'skip_audit_insert') {
    throw new PersistenceStop('transaction_aborted');
  }
}

function admit(command: MaintainerReviewedAdvisorySubmissionPersistenceCommand):
  | { readonly ok: true; readonly value: Admitted }
  | {
      readonly ok: false;
      readonly outcome: Exclude<
        MaintainerReviewedAdvisorySubmissionResult['outcome'],
        'submitted' | 'already_applied'
      >;
    } {
  if (!plainCommand(command)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (command.commandName !== MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_COMMAND_NAME) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (command.origin !== PINS.origin) {
    return { ok: false, outcome: 'unsupported_origin' };
  }
  const document = command.document;
  if (!isPlainRecord(document) || !isPlainRecord(command.fingerprints)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const parsed = parseMaintainerReviewedAdvisorySubmissionCommand({
    schemaVersion: document.schemaVersion,
    advisoryFamilyId: document.advisoryFamilyId,
    revisionNumber: document.revisionNumber,
    vulnerabilityId: document.vulnerabilityId,
    aliases: document.aliases,
    packageEcosystem: document.packageEcosystem,
    packageName: document.packageName,
    packageUrl: document.packageUrl,
    affectedRanges: document.affectedRanges,
    withdrawal: document.withdrawal,
    supersedesRevisionId: document.supersedesRevisionId,
    sourceLicenseDecision: document.sourceLicenseDecision,
    authorIdentity: document.authorIdentity,
    submissionCorrelationId: document.submissionCorrelationId,
  });
  if (!parsed.ok) {
    return { ok: false, outcome: parsed.outcome };
  }
  const preparation = prepareMaintainerReviewedAdvisorySubmission(
    command.trustedSubmitterUserId,
    parsed.command,
  );
  if (!preparation.ok) {
    return { ok: false, outcome: preparation.outcome };
  }
  const derived = preparation.prepared.command.fingerprints;
  if (
    !sameFingerprint(command.fingerprints.contentFingerprint, derived.contentFingerprint) ||
    !sameFingerprint(command.fingerprints.rangeFingerprint, derived.rangeFingerprint) ||
    !sameFingerprint(command.fingerprints.familyDigest, derived.familyDigest) ||
    !sameFingerprint(command.fingerprints.revisionDigest, derived.revisionDigest)
  ) {
    return { ok: false, outcome: 'internal_failure' };
  }
  if (
    command.correlationId !== document.submissionCorrelationId ||
    command.correlationId !== preparation.prepared.command.document.submissionCorrelationId
  ) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const bindingClassification = submissionBindingClassification(
    preparation.prepared.command.document,
  );
  const identity = maintainerReviewedAdvisorySubmissionNaturalIdentity(preparation.prepared);
  if (bindingClassification === null || identity === null) {
    return { ok: false, outcome: 'internal_failure' };
  }
  return {
    ok: true,
    value: {
      prepared: preparation.prepared,
      correlationId: command.correlationId,
      bindingClassification,
      naturalKey: `${identity.source}\u001f${identity.advisoryFamilyId}\u001f${String(identity.revisionNumber)}`,
      replayFingerprint: localMaintainerReviewedSubmissionReplayFingerprint(
        preparation.prepared.command.document,
        derived,
      ),
    },
  };
}

function plainCommand(command: MaintainerReviewedAdvisorySubmissionPersistenceCommand): boolean {
  if (!isPlainRecord(command)) {
    return false;
  }
  const keys = Object.keys(command);
  if (keys.length !== MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_PERSISTENCE_FIELDS.length) {
    return false;
  }
  for (const key of keys) {
    if (
      !(MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_PERSISTENCE_FIELDS as readonly string[]).includes(
        key,
      )
    ) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(command, key);
    if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
      return false;
    }
  }
  return true;
}

function sameFingerprint(supplied: unknown, derived: string): boolean {
  return typeof supplied === 'string' && supplied === derived && SHA256_HEX.test(supplied);
}

function isPlainRecord(value: unknown): value is Record<string, never> {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function throwFault(
  fault: MaintainerReviewedAdvisorySubmissionPersistenceFault | undefined,
  stage: MaintainerReviewedAdvisorySubmissionPersistenceFault,
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

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : '';
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
  const text = errorText(error);
  return text.includes("Can't reach database server") || text.includes('ECONNREFUSED');
}

function assertSubmissionPort(
  factory: (client: PrismaClient) => MaintainerReviewedAdvisorySubmissionPersistencePort,
): void {
  void factory;
}

assertSubmissionPort(createMaintainerReviewedAdvisorySubmissionPersistence);
