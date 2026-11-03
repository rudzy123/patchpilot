/**
 * Transaction-scoped PostgreSQL adapter for one deliberate Product Match
 * Evidence evaluation. Production startup does not construct this factory.
 * One Read Committed transaction locks one asset, classifies its occurrences,
 * and commits immutable evidence with one audit row, or commits neither.
 * Finding writes stay zero. Provider calls stay zero.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import { roleGrantsProductMatchEvaluation, type MembershipRole } from '@patchpilot/domain';
import {
  PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
  PRODUCT_MATCH_EVALUATION_ORIGIN,
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATOR_ID,
  PRODUCT_MATCH_EVALUATOR_VERSION,
  PRODUCT_MATCH_FINDING_CREATION,
  PRODUCT_MATCH_MATCHING_POLICY_ID,
  PRODUCT_MATCH_MATCHING_POLICY_VERSION,
  PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
  assessProductMatchEligibility,
  classifyNpmPackageIdentityFromParts,
  classifyStoredProductMatchReplay,
  componentEvidenceFingerprint,
  evaluateReviewedNpmRange,
  parseProductMatchEvaluationCommand,
  type ProductMatchAdvisoryBundle,
  type ProductMatchComponentSnapshot,
  type ProductMatchEvaluationLookup,
  type ProductMatchReplayBody,
} from '@patchpilot/vulnerability-intelligence';
import {
  DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_LOCK_TIMEOUT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_MAX_WAIT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_NORMALIZATION_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_CAP,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_ORDER,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_ID,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_PURPOSE,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_STATEMENT_TIMEOUT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSACTION_TIMEOUT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSPORT_ID_PATTERN,
  type DeliberateAdvisoryRejectionCode,
  type DeliberateProductMatchEvaluationCommand,
  type DeliberateProductMatchEvaluationDecisions,
  type DeliberateProductMatchEvaluationFailureStatus,
  type DeliberateProductMatchEvaluationOutcome,
  type DeliberateProductMatchEvaluationPort,
  type DeliberateProductMatchEvaluationSkipReason,
} from '@patchpilot/vulnerability-intelligence/deliberate-product-match-evaluation';

import { asJsonObject, isRootPrismaClient, type PrismaClientLike } from './guards.js';
import {
  isProductMatchUniqueViolation,
  translateProductMatchFailure,
} from './product-match-evaluation-persistence-errors.js';
import {
  readProductMatchEvidenceForIdentity,
  writeProductMatchEvaluationEvidence,
} from './product-match-evaluation-persistence.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVENT_NAMES = new Set(['introduced', 'fixed', 'last_affected', 'limit']);
const SHA256_HEX = /^[a-f0-9]{64}$/;

export const DELIBERATE_PRODUCT_MATCH_EVALUATION_FAULTS = [
  'before_evidence_insert',
  'before_audit_insert',
  'after_audit_insert',
] as const;

export type DeliberateProductMatchEvaluationFault =
  (typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_FAULTS)[number];

type FailureResult = {
  readonly status: DeliberateProductMatchEvaluationFailureStatus;
  readonly auditWritten: false;
  readonly findingWrites: typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES;
  readonly insertedCount: 0;
  readonly providerCalls: typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS;
};

type SuccessStatus =
  'evaluated' | 'already_applied' | 'no_relevant_occurrence' | 'no_evaluable_occurrence';

type SuccessResult = {
  readonly status: SuccessStatus;
  readonly assetId: string;
  readonly advisoryRevisionId: string;
  readonly ingestionId: string;
  readonly selectedCount: number;
  readonly evaluatedCount: number;
  readonly insertedCount: number;
  readonly replayedCount: number;
  readonly skippedCount: number;
  readonly skippedByReason: {
    readonly version_not_known: number;
    readonly version_unrepresentable: number;
  };
  readonly outcomeCounts: {
    readonly affected: number;
    readonly unaffected: number;
    readonly unknown: number;
  };
  readonly findingCreation: typeof PRODUCT_MATCH_FINDING_CREATION;
  readonly findingWrites: typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES;
  readonly providerCalls: typeof DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS;
  readonly auditWritten: boolean;
};

type Step<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly result: FailureResult };

type OutcomeCounts = {
  affected: number;
  unaffected: number;
  unknown: number;
};

type Counts = {
  selected: number;
  versionNotKnown: number;
  versionUnrepresentable: number;
  inserted: OutcomeCounts;
  replayed: OutcomeCounts;
};

type SelectedOccurrence = {
  readonly occurrenceId: string;
  readonly organizationId: string;
  readonly assetId: string;
  readonly sbomId: string;
  readonly sbomIngestionId: string;
  readonly componentId: string;
  readonly version: string;
  readonly versionKnown: boolean;
  readonly identityKey: string;
  readonly ecosystem: string;
  readonly namespace: string | null;
  readonly name: string;
  readonly purl: string | null;
  readonly identityState: string;
  readonly sbomSha256: string;
};

type InsertPlan = {
  readonly snapshot: ProductMatchComponentSnapshot;
  readonly lookup: ProductMatchEvaluationLookup;
  readonly body: ProductMatchReplayBody;
  readonly outcome: DeliberateProductMatchEvaluationOutcome;
};

type Classification =
  | { readonly kind: 'skip'; readonly reason: DeliberateProductMatchEvaluationSkipReason }
  | { readonly kind: 'replay'; readonly outcome: DeliberateProductMatchEvaluationOutcome }
  | { readonly kind: 'insert'; readonly plan: InsertPlan }
  | { readonly kind: 'abort'; readonly result: FailureResult };

class DeliberateEvaluationAbort extends Error {
  public constructor(readonly status: DeliberateProductMatchEvaluationFailureStatus) {
    super('deliberate product match evaluation aborted');
    this.name = 'DeliberateEvaluationAbort';
  }
}

export function createDeliberateProductMatchEvaluationPersistence(
  client: PrismaClient,
  options?: { readonly fault?: DeliberateProductMatchEvaluationFault },
): DeliberateProductMatchEvaluationPort {
  if (!isRootPrismaClient(client)) {
    throw new Error(
      'Deliberate product match evaluation persistence requires the root database client.',
    );
  }
  const fault = options?.fault;
  return {
    async evaluate(command, decisions) {
      if (!commandPinsAgree(command) || !decisionPinsAgree(decisions)) {
        return failure('internal_failure');
      }
      try {
        return await runTransaction(client, command, decisions, fault);
      } catch (error) {
        const aborted = directAbort(error);
        if (aborted !== null) {
          return failure(aborted);
        }
        if (isProductMatchUniqueViolation(error) && fault === undefined) {
          return reconcileUniqueViolation(client, command, decisions);
        }
        return failure(translateDeliberateFailure(error));
      }
    },
  };
}

async function runTransaction(
  client: PrismaClient,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
  fault: DeliberateProductMatchEvaluationFault | undefined,
): Promise<SuccessResult | FailureResult> {
  return client.$transaction((tx) => evaluateInTransaction(tx, command, decisions, fault), {
    isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
    maxWait: decisions.maxWaitMs,
    timeout: decisions.transactionTimeoutMs,
  });
}

/**
 * A unique violation rolls the attempt back. One locked re-run classifies the
 * committed rows. A second unique violation, including an audit correlation
 * collision, stays transaction_aborted and writes nothing.
 */
async function reconcileUniqueViolation(
  client: PrismaClient,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
): Promise<SuccessResult | FailureResult> {
  try {
    return await runTransaction(client, command, decisions, undefined);
  } catch (error) {
    const aborted = directAbort(error);
    if (aborted !== null) {
      return failure(aborted);
    }
    if (isProductMatchUniqueViolation(error)) {
      return failure('transaction_aborted');
    }
    return failure(translateDeliberateFailure(error));
  }
}

async function evaluateInTransaction(
  tx: Prisma.TransactionClient,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
  fault: DeliberateProductMatchEvaluationFault | undefined,
): Promise<SuccessResult | FailureResult> {
  const configured = await configureTransaction(tx, decisions);
  if (!configured.ok) {
    return configured.result;
  }
  const locked = await lockAsset(tx, command, decisions);
  if (!locked.ok) {
    return locked.result;
  }
  const actor = await reloadActor(tx, command);
  if (!actor.ok) {
    return actor.result;
  }
  const ingestion = await loadIngestion(tx, command, decisions, locked.value.ingestionId);
  if (!ingestion.ok) {
    return ingestion.result;
  }
  const advisory = await loadAdvisory(tx, command, decisions);
  if (!advisory.ok) {
    return advisory.result;
  }
  const selected = await selectOccurrences(tx, command, ingestion.value, advisory.value);
  const selection = decisions.classifySelectionCount(selected.length);
  if (selection === 'malformed_persisted_state') {
    return failure('malformed_persisted_state');
  }
  if (selection === 'capacity_exceeded') {
    return failure('capacity_exceeded');
  }
  if (selection === 'empty') {
    return selected.length === 0
      ? completion(command, ingestion.value, emptyCounts())
      : failure('internal_failure');
  }
  if (selection !== 'within_cap' || selected.length > command.occurrenceCap) {
    return failure('internal_failure');
  }
  const classified = await classifyLoaded(tx, command, decisions, advisory.value, selected);
  if (!classified.ok) {
    return classified.result;
  }
  const counts = classified.value.counts;
  const inserts = classified.value.inserts;
  if (outcomeTotal(counts.inserted) !== inserts.length) {
    return failure('internal_failure');
  }
  if (inserts.length > 0) {
    const planned = decisions.planAudit({
      command,
      ingestionId: ingestion.value,
      selectedCount: counts.selected,
      insertedCount: inserts.length,
      replayedCount: outcomeTotal(counts.replayed),
      skippedCount: counts.versionNotKnown + counts.versionUnrepresentable,
      affectedCount: counts.inserted.affected,
      unaffectedCount: counts.inserted.unaffected,
      unknownCount: counts.inserted.unknown,
    });
    if (
      planned.kind !== 'write' ||
      planned.intent.action !== DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION
    ) {
      return failure('internal_failure');
    }
    throwFault(fault, 'before_evidence_insert');
    for (const plan of inserts) {
      const written = await writeProductMatchEvaluationEvidence(tx, {
        snapshot: plan.snapshot,
        familyId: advisory.value.revision.familyId,
        body: plan.body,
      });
      const reread = await readProductMatchEvidenceForIdentity(tx, plan.lookup);
      if (
        reread.kind !== 'row' ||
        reread.row.matchEvidenceId !== written.matchEvidenceId ||
        reread.row.outcome !== plan.outcome ||
        !sameCodes(reread.row.explanationCodes, plan.body.explanationCodes) ||
        reread.row.componentOccurrenceId !== plan.snapshot.componentOccurrenceId ||
        reread.row.advisoryRevisionId !== command.advisoryRevisionId ||
        reread.row.organizationId !== command.organizationId
      ) {
        throw new DeliberateEvaluationAbort('malformed_persisted_state');
      }
    }
    throwFault(fault, 'before_audit_insert');
    await tx.auditEvent.create({
      data: {
        organizationId: planned.intent.organizationId,
        actorUserId: planned.intent.actorUserId,
        actorMembershipId: planned.intent.actorMembershipId,
        actorType: planned.intent.actorType,
        action: planned.intent.action,
        subjectType: planned.intent.subjectType,
        subjectId: planned.intent.subjectId,
        requestId: planned.intent.requestId,
        correlationId: planned.intent.correlationId,
        payload: asJsonObject(cloneJson(planned.intent.payload), 'payload'),
        schemaVersion: planned.intent.schemaVersion,
        retentionCategory: planned.intent.retentionCategory,
      },
    });
    throwFault(fault, 'after_audit_insert');
  }
  return completion(command, ingestion.value, counts);
}

async function configureTransaction(
  tx: Prisma.TransactionClient,
  decisions: DeliberateProductMatchEvaluationDecisions,
): Promise<Step<true>> {
  if (
    decisions.statementTimeoutMs !== DELIBERATE_PRODUCT_MATCH_EVALUATION_STATEMENT_TIMEOUT_MS ||
    decisions.lockTimeoutMs !== DELIBERATE_PRODUCT_MATCH_EVALUATION_LOCK_TIMEOUT_MS ||
    decisions.occurrenceOrder !== DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_ORDER
  ) {
    return { ok: false, result: failure('internal_failure') };
  }
  await tx.$queryRaw`SELECT set_config('statement_timeout', '5000', true) AS configured`;
  await tx.$queryRaw`SELECT set_config('lock_timeout', '2000', true) AS configured`;
  const settings = await tx.$queryRaw<
    Array<{ statement_timeout: string; lock_timeout: string; isolation: string }>
  >`
    SELECT current_setting('statement_timeout') AS statement_timeout,
           current_setting('lock_timeout') AS lock_timeout,
           current_setting('transaction_isolation') AS isolation
  `;
  const setting = settings[0];
  if (
    settings.length !== 1 ||
    setting === undefined ||
    !acceptsTimeout(setting.statement_timeout, 5000) ||
    !acceptsTimeout(setting.lock_timeout, 2000) ||
    setting.isolation !== 'read committed'
  ) {
    return { ok: false, result: failure('internal_failure') };
  }
  return { ok: true, value: true };
}

async function lockAsset(
  tx: Prisma.TransactionClient,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
): Promise<Step<{ readonly ingestionId: string | null }>> {
  const lockKey = decisions.lockIdentity(command.organizationId, command.assetId);
  if (lockKey !== `${command.organizationId}:${command.assetId}`) {
    return { ok: false, result: failure('internal_failure') };
  }
  const taken = await tx.$queryRaw<Array<{ locked: number }>>`
    SELECT 1::int AS locked
    FROM (
      SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))
    ) AS taken
  `;
  if (taken.length !== 1) {
    return { ok: false, result: failure('internal_failure') };
  }
  const assets = await tx.$queryRaw<Array<{ ingestion_id: string | null }>>`
    SELECT "last_successful_sbom_ingestion_id"::text AS ingestion_id
    FROM "asset"
    WHERE "organization_id" = ${command.organizationId}::uuid
      AND "id" = ${command.assetId}::uuid
    FOR UPDATE
  `;
  const asset = assets[0];
  if (assets.length !== 1 || asset === undefined) {
    return { ok: false, result: failure('not_found') };
  }
  return { ok: true, value: { ingestionId: asset.ingestion_id } };
}

async function reloadActor(
  tx: Prisma.TransactionClient,
  command: DeliberateProductMatchEvaluationCommand,
): Promise<Step<true>> {
  const users = await tx.$queryRaw<Array<{ id: string; status: string }>>`
    SELECT "id"::text AS id, "status"::text AS status
    FROM "user"
    WHERE "id" = ${command.actorUserId}::uuid
  `;
  const user = users[0];
  if (users.length !== 1 || user === undefined || user.status !== 'active') {
    return { ok: false, result: failure('authority_rejected') };
  }
  const organizations = await tx.$queryRaw<Array<{ id: string; status: string }>>`
    SELECT "id"::text AS id, "status"::text AS status
    FROM "organization"
    WHERE "id" = ${command.organizationId}::uuid
  `;
  const organization = organizations[0];
  if (organizations.length !== 1 || organization === undefined) {
    return { ok: false, result: failure('malformed_persisted_state') };
  }
  if (organization.status !== 'active') {
    return { ok: false, result: failure('authority_rejected') };
  }
  const memberships = await tx.$queryRaw<
    Array<{ id: string; user_id: string; status: string; role: string }>
  >`
    SELECT "id"::text AS id,
           "user_id"::text AS user_id,
           "status"::text AS status,
           "role"::text AS role
    FROM "membership"
    WHERE "organization_id" = ${command.organizationId}::uuid
      AND "id" = ${command.membershipId}::uuid
    FOR SHARE
  `;
  const membership = memberships[0];
  if (memberships.length !== 1 || membership === undefined) {
    return { ok: false, result: failure('authority_rejected') };
  }
  const role = membershipRole(membership.role);
  const owner = role === 'owner' && roleGrantsProductMatchEvaluation(role);
  if (membership.user_id !== command.actorUserId || membership.status !== 'active' || !owner) {
    return { ok: false, result: failure('authority_rejected') };
  }
  return { ok: true, value: true };
}

async function loadIngestion(
  tx: Prisma.TransactionClient,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
  pointer: string | null,
): Promise<Step<string>> {
  if (pointer === null) {
    return ingestionStep(
      decisions.classifyIngestion({
        pointerPresent: false,
        ingestionState: null,
        normalizationVersion: null,
        sameAssetAndOrganization: false,
      }),
      null,
    );
  }
  if (!UUID_V4.test(pointer)) {
    return { ok: false, result: failure('malformed_persisted_state') };
  }
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      state: string;
      normalization_version: string;
      organization_id: string;
      asset_id: string;
    }>
  >`
    SELECT "id"::text AS id,
           "state"::text AS state,
           "normalization_version" AS normalization_version,
           "organization_id"::text AS organization_id,
           "asset_id"::text AS asset_id
    FROM "sbom_ingestion"
    WHERE "organization_id" = ${command.organizationId}::uuid
      AND "id" = ${pointer}::uuid
  `;
  const row = rows[0];
  if (rows.length !== 1 || row === undefined) {
    return { ok: false, result: failure('malformed_persisted_state') };
  }
  const version = numericVersion(row.normalization_version);
  return ingestionStep(
    decisions.classifyIngestion({
      pointerPresent: true,
      ingestionState: row.state,
      normalizationVersion: version ?? row.normalization_version,
      sameAssetAndOrganization:
        row.organization_id === command.organizationId && row.asset_id === command.assetId,
    }),
    row.id,
  );
}

function ingestionStep(
  decision: ReturnType<DeliberateProductMatchEvaluationDecisions['classifyIngestion']>,
  ingestionId: string | null,
): Step<string> {
  if (decision === 'ready' && ingestionId !== null) {
    return { ok: true, value: ingestionId };
  }
  if (
    decision === 'no_successful_ingestion' ||
    decision === 'ingestion_not_evaluable' ||
    decision === 'malformed_persisted_state'
  ) {
    return { ok: false, result: failure(decision) };
  }
  return { ok: false, result: failure('internal_failure') };
}

async function loadAdvisory(
  tx: PrismaClientLike,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
): Promise<Step<ProductMatchAdvisoryBundle>> {
  const revision = await tx.advisoryRevision.findFirst({
    where: { id: command.advisoryRevisionId },
    select: {
      id: true,
      advisoryFamilyId: true,
      origin: true,
      source: true,
      contentFingerprint: true,
      session14RangeFingerprint: true,
      packageIdentityKey: true,
      ecosystem: true,
      packageNamespace: true,
      packageName: true,
      authorIdentity: true,
      withdrawalClassification: true,
      quarantineClassification: true,
      revisionDisposition: true,
      supersedesRevisionDigest: true,
      spdxLicenseId: true,
      advisorySchemaVersion: true,
      trustClassification: true,
      successors: { select: { id: true }, take: 1 },
    },
  });
  if (revision === null) {
    return advisoryFailure(decisions, 'revision_missing');
  }
  const approval = await tx.maintainerReviewedAdvisoryApproval.findFirst({
    where: { advisoryRevisionId: revision.id },
    select: {
      id: true,
      advisoryRevisionId: true,
      advisoryFamilyId: true,
      advisoryVulnerabilityBindingId: true,
      authorIdentity: true,
      reviewerIdentity: true,
      reviewerClassification: true,
      approvalPurpose: true,
      approvalPolicyId: true,
      approvalPolicyVersion: true,
      sourceClassification: true,
      contentFingerprint: true,
      rangeFingerprint: true,
      packageIdentityKey: true,
      vulnerabilityId: true,
      sourceLicensePolicyId: true,
      sourceLicensePolicyVersion: true,
      approvedLicenseClassification: true,
      licenseDecisionCanonical: true,
    },
  });
  if (approval === null) {
    return advisoryFailure(decisions, 'approval_missing');
  }
  const binding = await tx.advisoryVulnerabilityBinding.findFirst({
    where: { advisoryRevisionId: revision.id },
    select: {
      id: true,
      advisoryRevisionId: true,
      vulnerabilityId: true,
      mappingReviewState: true,
      conflictClassification: true,
      mappingMethod: true,
      mappingPolicyId: true,
    },
  });
  if (binding === null) {
    return advisoryFailure(decisions, 'vulnerability_binding_missing');
  }
  const events = await tx.advisoryRevisionRangeEvent.findMany({
    where: { advisoryRevisionId: revision.id },
    select: {
      rangeOrdinal: true,
      eventOrdinal: true,
      eventName: true,
      eventValue: true,
    },
    orderBy: [{ rangeOrdinal: 'asc' }, { eventOrdinal: 'asc' }],
  });
  if (events.length === 0) {
    return advisoryFailure(decisions, 'range_evidence_missing');
  }
  const ranges = rangesFrom(events);
  if (ranges === null || revision.authorIdentity === null) {
    return { ok: false, result: failure('malformed_persisted_state') };
  }
  const bundle: ProductMatchAdvisoryBundle = {
    revision: {
      revisionId: revision.id,
      familyId: revision.advisoryFamilyId,
      origin: revision.origin,
      source: revision.source,
      contentFingerprint: revision.contentFingerprint,
      rangeFingerprint: revision.session14RangeFingerprint,
      packageIdentityKey: revision.packageIdentityKey,
      ecosystem: revision.ecosystem,
      namespace: revision.packageNamespace,
      name: revision.packageName,
      authorIdentity: revision.authorIdentity,
      withdrawalClassification: revision.withdrawalClassification,
      quarantineClassification: revision.quarantineClassification,
      revisionDisposition: revision.revisionDisposition,
      supersedesRevisionDigest: revision.supersedesRevisionDigest,
      supersededByAnotherRevision: revision.successors.length > 0,
      spdxLicenseId: revision.spdxLicenseId,
      advisorySchemaVersion: revision.advisorySchemaVersion,
      trustClassification: revision.trustClassification,
    },
    approval: {
      approvalId: approval.id,
      advisoryRevisionId: approval.advisoryRevisionId,
      advisoryFamilyId: approval.advisoryFamilyId,
      bindingId: approval.advisoryVulnerabilityBindingId,
      authorIdentity: approval.authorIdentity,
      reviewerIdentity: approval.reviewerIdentity,
      reviewerClassification: approval.reviewerClassification,
      approvalPurpose: approval.approvalPurpose,
      approvalPolicyId: approval.approvalPolicyId,
      approvalPolicyVersion: approval.approvalPolicyVersion,
      sourceClassification: approval.sourceClassification,
      contentFingerprint: approval.contentFingerprint,
      rangeFingerprint: approval.rangeFingerprint,
      packageIdentityKey: approval.packageIdentityKey,
      vulnerabilityId: approval.vulnerabilityId,
      sourceLicensePolicyId: approval.sourceLicensePolicyId,
      sourceLicensePolicyVersion: approval.sourceLicensePolicyVersion,
      approvedLicenseClassification: approval.approvedLicenseClassification,
      licenseDecisionCanonical: approval.licenseDecisionCanonical,
    },
    binding: {
      bindingId: binding.id,
      advisoryRevisionId: binding.advisoryRevisionId,
      vulnerabilityId: binding.vulnerabilityId,
      mappingReviewState: binding.mappingReviewState,
      conflictClassification: binding.conflictClassification,
      mappingMethod: binding.mappingMethod,
      mappingPolicyId: binding.mappingPolicyId,
    },
    ranges,
  };
  const assessment = decisions.assessAdvisory(bundle);
  if (!assessment.eligible) {
    return { ok: false, result: failure(decisions.advisoryFailureStatus(assessment.code)) };
  }
  return { ok: true, value: bundle };
}

function advisoryFailure(
  decisions: DeliberateProductMatchEvaluationDecisions,
  code: DeliberateAdvisoryRejectionCode,
): Step<ProductMatchAdvisoryBundle> {
  return { ok: false, result: failure(decisions.advisoryFailureStatus(code)) };
}

async function selectOccurrences(
  tx: Prisma.TransactionClient,
  command: DeliberateProductMatchEvaluationCommand,
  ingestionId: string,
  bundle: ProductMatchAdvisoryBundle,
): Promise<SelectedOccurrence[]> {
  if (
    command.selectionProbe !== DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE ||
    DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE !== 17 ||
    command.occurrenceCap !== 16
  ) {
    throw new DeliberateEvaluationAbort('internal_failure');
  }
  const namespacePredicate =
    bundle.revision.namespace === null
      ? Prisma.sql`component."namespace" IS NULL`
      : Prisma.sql`component."namespace" = ${bundle.revision.namespace}`;
  const rows = await tx.$queryRaw<
    Array<{
      occurrence_id: string;
      organization_id: string;
      asset_id: string;
      sbom_id: string;
      sbom_ingestion_id: string;
      component_id: string;
      version: string;
      version_known: boolean;
      identity_key: string;
      ecosystem: string | null;
      namespace: string | null;
      name: string;
      purl: string | null;
      identity_state: string;
      sbom_sha256: string;
    }>
  >(Prisma.sql`
    SELECT occurrence."id"::text AS occurrence_id,
           occurrence."organization_id"::text AS organization_id,
           occurrence."asset_id"::text AS asset_id,
           occurrence."sbom_id"::text AS sbom_id,
           occurrence."sbom_ingestion_id"::text AS sbom_ingestion_id,
           occurrence."component_id"::text AS component_id,
           occurrence."version" AS version,
           occurrence."version_known" AS version_known,
           component."identity_key" AS identity_key,
           component."ecosystem" AS ecosystem,
           component."namespace" AS namespace,
           component."name" AS name,
           component."purl" AS purl,
           component."identity_state"::text AS identity_state,
           sbom."sha256" AS sbom_sha256
    FROM "component_occurrence" AS occurrence
    INNER JOIN "component" AS component
      ON component."organization_id" = occurrence."organization_id"
     AND component."id" = occurrence."component_id"
    INNER JOIN "sbom" AS sbom
      ON sbom."organization_id" = occurrence."organization_id"
     AND sbom."id" = occurrence."sbom_id"
     AND sbom."asset_id" = occurrence."asset_id"
    WHERE occurrence."organization_id" = ${command.organizationId}::uuid
      AND occurrence."asset_id" = ${command.assetId}::uuid
      AND occurrence."sbom_ingestion_id" = ${ingestionId}::uuid
      AND component."ecosystem" = ${bundle.revision.ecosystem}
      AND component."name" = ${bundle.revision.name}
      AND ${namespacePredicate}
    ORDER BY occurrence."id"::text COLLATE "C" ASC
    LIMIT 17
    FOR UPDATE OF occurrence
  `);
  const selected: SelectedOccurrence[] = [];
  for (const row of rows) {
    if (typeof row.version_known !== 'boolean' || row.ecosystem === null) {
      throw new DeliberateEvaluationAbort('malformed_persisted_state');
    }
    selected.push({
      occurrenceId: row.occurrence_id,
      organizationId: row.organization_id,
      assetId: row.asset_id,
      sbomId: row.sbom_id,
      sbomIngestionId: row.sbom_ingestion_id,
      componentId: row.component_id,
      version: row.version,
      versionKnown: row.version_known,
      identityKey: row.identity_key,
      ecosystem: row.ecosystem,
      namespace: row.namespace,
      name: row.name,
      purl: row.purl,
      identityState: row.identity_state,
      sbomSha256: row.sbom_sha256,
    });
  }
  return selected;
}

async function classifyLoaded(
  tx: PrismaClientLike,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
  bundle: ProductMatchAdvisoryBundle,
  selected: readonly SelectedOccurrence[],
): Promise<Step<{ readonly counts: Counts; readonly inserts: readonly InsertPlan[] }>> {
  const counts = emptyCounts();
  const inserts: InsertPlan[] = [];
  for (const occurrence of selected) {
    const classified = await classifyOne(tx, command, decisions, bundle, occurrence);
    if (classified.kind === 'abort') {
      return { ok: false, result: classified.result };
    }
    counts.selected += 1;
    if (classified.kind === 'skip') {
      if (classified.reason === 'version_not_known') {
        counts.versionNotKnown += 1;
      } else {
        counts.versionUnrepresentable += 1;
      }
      continue;
    }
    if (classified.kind === 'replay') {
      counts.replayed[classified.outcome] += 1;
      continue;
    }
    counts.inserted[classified.plan.outcome] += 1;
    inserts.push(classified.plan);
  }
  return { ok: true, value: { counts, inserts } };
}

async function classifyOne(
  tx: PrismaClientLike,
  command: DeliberateProductMatchEvaluationCommand,
  decisions: DeliberateProductMatchEvaluationDecisions,
  bundle: ProductMatchAdvisoryBundle,
  occurrence: SelectedOccurrence,
): Promise<Classification> {
  if (
    occurrence.organizationId !== command.organizationId ||
    occurrence.assetId !== command.assetId ||
    occurrence.name.length === 0 ||
    occurrence.ecosystem.length === 0 ||
    !SHA256_HEX.test(occurrence.sbomSha256) ||
    !UUID_V4.test(occurrence.occurrenceId) ||
    occurrence.ecosystem !== bundle.revision.ecosystem ||
    occurrence.name !== bundle.revision.name ||
    occurrence.namespace !== bundle.revision.namespace ||
    occurrence.identityState !== 'resolved'
  ) {
    return abort('malformed_persisted_state');
  }
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: occurrence.ecosystem,
    observedNamespace: occurrence.namespace,
    observedName: occurrence.name,
    observedIdentity:
      occurrence.namespace === null
        ? occurrence.name
        : `${occurrence.namespace}/${occurrence.name}`,
  });
  if (
    identity.classification !== 'valid' ||
    identity.identityKey !== bundle.revision.packageIdentityKey
  ) {
    return abort('malformed_persisted_state');
  }
  const version = decisions.classifyOccurrenceVersion({
    versionKnown: occurrence.versionKnown,
    rawObservedVersion: occurrence.version,
  });
  if (version.decision === 'malformed_persisted_state') {
    return abort('malformed_persisted_state');
  }
  if (version.decision === 'skip') {
    return { kind: 'skip', reason: version.reason };
  }
  if (version.decision !== 'evaluable') {
    return abort('internal_failure');
  }
  const snapshot: ProductMatchComponentSnapshot = {
    organizationId: occurrence.organizationId,
    componentOccurrenceId: occurrence.occurrenceId,
    assetId: occurrence.assetId,
    sbomId: occurrence.sbomId,
    sbomIngestionId: occurrence.sbomIngestionId,
    componentId: occurrence.componentId,
    componentIdentityKey: occurrence.identityKey,
    sbomSha256: occurrence.sbomSha256,
    ecosystem: occurrence.ecosystem,
    namespace: occurrence.namespace,
    name: occurrence.name,
    purl: occurrence.purl,
    rawObservedVersion: occurrence.version,
    versionKnown: occurrence.versionKnown,
    identityState: occurrence.identityState,
  };
  const parsed = parseProductMatchEvaluationCommand({
    commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
    organizationId: snapshot.organizationId,
    componentOccurrenceId: snapshot.componentOccurrenceId,
    expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
      organizationId: snapshot.organizationId,
      componentOccurrenceId: snapshot.componentOccurrenceId,
      assetId: snapshot.assetId,
      sbomId: snapshot.sbomId,
      sbomIngestionId: snapshot.sbomIngestionId,
      componentId: snapshot.componentId,
      componentIdentityKey: snapshot.componentIdentityKey,
      ecosystem: snapshot.ecosystem,
      namespace: snapshot.namespace,
      name: snapshot.name,
      rawObservedVersion: snapshot.rawObservedVersion,
      versionKnown: snapshot.versionKnown,
      sbomSha256: snapshot.sbomSha256,
    }),
    expectedNpmPackageIdentity: bundle.revision.packageIdentityKey,
    expectedRawObservedVersion: snapshot.rawObservedVersion,
    advisoryRevisionId: bundle.revision.revisionId,
    approvalEvidenceId: bundle.approval.approvalId,
    expectedContentFingerprint: bundle.revision.contentFingerprint,
    expectedRangeFingerprint: bundle.revision.rangeFingerprint,
    expectedVulnerabilityId: bundle.binding.vulnerabilityId,
    evaluatorId: command.evaluatorId,
    evaluatorVersion: command.evaluatorVersion,
    matchingPolicyId: command.matchingPolicyId,
    matchingPolicyVersion: command.matchingPolicyVersion,
    productEvidencePolicyId: command.productEvidencePolicyId,
    productEvidencePolicyVersion: command.productEvidencePolicyVersion,
    correlationId: command.operationCorrelationId,
  });
  if (!parsed.accepted) {
    return abort('malformed_persisted_state');
  }
  if (assessProductMatchEligibility(parsed.command, snapshot, bundle) !== null) {
    return abort('malformed_persisted_state');
  }
  const lookup = lookupFrom(parsed.command);
  const existing = await readProductMatchEvidenceForIdentity(tx, lookup);
  if (existing.kind === 'malformed') {
    return abort('malformed_persisted_state');
  }
  if (existing.kind === 'row') {
    const disposition = classifyStoredProductMatchReplay(existing.row, parsed.command);
    if (disposition === 'applied') {
      const outcome = asOutcome(existing.row.outcome);
      return outcome === null ? abort('malformed_persisted_state') : { kind: 'replay', outcome };
    }
    if (disposition === 'conflict') {
      return abort('immutable_conflict');
    }
    return abort('malformed_persisted_state');
  }
  const decision = evaluateReviewedNpmRange({
    namespace: snapshot.namespace,
    name: snapshot.name,
    rawObservedVersion: snapshot.rawObservedVersion,
    ranges: bundle.ranges,
  });
  const outcome = asOutcome(decision.outcome);
  if (outcome === null || decision.explanationCodes.length === 0) {
    return abort('malformed_persisted_state');
  }
  const body: ProductMatchReplayBody = {
    organizationId: snapshot.organizationId,
    componentOccurrenceId: snapshot.componentOccurrenceId,
    componentEvidenceFingerprint: parsed.command.expectedComponentEvidenceFingerprint,
    packageIdentityKey: parsed.command.expectedNpmPackageIdentity,
    rawObservedVersion: snapshot.rawObservedVersion,
    advisoryRevisionId: parsed.command.advisoryRevisionId,
    approvalEvidenceId: parsed.command.approvalEvidenceId,
    contentFingerprint: parsed.command.expectedContentFingerprint,
    rangeFingerprint: parsed.command.expectedRangeFingerprint,
    vulnerabilityId: parsed.command.expectedVulnerabilityId,
    evaluatorId: parsed.command.evaluatorId,
    evaluatorVersion: parsed.command.evaluatorVersion,
    matchingPolicyId: parsed.command.matchingPolicyId,
    matchingPolicyVersion: parsed.command.matchingPolicyVersion,
    productEvidencePolicyId: parsed.command.productEvidencePolicyId,
    productEvidencePolicyVersion: String(parsed.command.productEvidencePolicyVersion),
    productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
    outcome,
    explanationCodes: decision.explanationCodes,
  };
  return { kind: 'insert', plan: { snapshot, lookup, body, outcome } };
}

function lookupFrom(
  command: Parameters<typeof assessProductMatchEligibility>[0],
): ProductMatchEvaluationLookup {
  return {
    organizationId: command.organizationId,
    componentOccurrenceId: command.componentOccurrenceId,
    advisoryRevisionId: command.advisoryRevisionId,
    approvalEvidenceId: command.approvalEvidenceId,
    evaluatorId: command.evaluatorId,
    evaluatorVersion: command.evaluatorVersion,
    matchingPolicyId: command.matchingPolicyId,
    matchingPolicyVersion: command.matchingPolicyVersion,
    productEvidencePolicyId: command.productEvidencePolicyId,
    productEvidencePolicyVersion: command.productEvidencePolicyVersion,
  };
}

function completion(
  command: DeliberateProductMatchEvaluationCommand,
  ingestionId: string,
  counts: Counts,
): SuccessResult | FailureResult {
  const skippedCount = counts.versionNotKnown + counts.versionUnrepresentable;
  const insertedCount = outcomeTotal(counts.inserted);
  const replayedCount = outcomeTotal(counts.replayed);
  const evaluatedCount = insertedCount + replayedCount;
  if (
    counts.selected !== evaluatedCount + skippedCount ||
    insertedCount !== outcomeTotal(counts.inserted)
  ) {
    return failure('internal_failure');
  }
  const status = completionStatus(counts.selected, insertedCount, replayedCount, evaluatedCount);
  if (status === null) {
    return failure('internal_failure');
  }
  const auditWritten = status === 'evaluated';
  return {
    status,
    assetId: command.assetId,
    advisoryRevisionId: command.advisoryRevisionId,
    ingestionId,
    selectedCount: counts.selected,
    evaluatedCount,
    insertedCount,
    replayedCount,
    skippedCount,
    skippedByReason: {
      version_not_known: counts.versionNotKnown,
      version_unrepresentable: counts.versionUnrepresentable,
    },
    outcomeCounts: {
      affected: counts.inserted.affected + counts.replayed.affected,
      unaffected: counts.inserted.unaffected + counts.replayed.unaffected,
      unknown: counts.inserted.unknown + counts.replayed.unknown,
    },
    findingCreation: PRODUCT_MATCH_FINDING_CREATION,
    findingWrites: DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES,
    providerCalls: DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS,
    auditWritten,
  };
}

function completionStatus(
  selected: number,
  inserted: number,
  replayed: number,
  evaluated: number,
): SuccessStatus | null {
  if (inserted >= 1) {
    return 'evaluated';
  }
  if (replayed >= 1 && inserted === 0) {
    return 'already_applied';
  }
  if (selected === 0 && evaluated === 0) {
    return 'no_relevant_occurrence';
  }
  if (selected >= 1 && evaluated === 0) {
    return 'no_evaluable_occurrence';
  }
  return null;
}

function failure(status: DeliberateProductMatchEvaluationFailureStatus): FailureResult {
  return {
    status,
    auditWritten: false,
    findingWrites: DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES,
    insertedCount: 0,
    providerCalls: DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS,
  };
}

function abort(status: DeliberateProductMatchEvaluationFailureStatus): Classification {
  return { kind: 'abort', result: failure(status) };
}

function emptyCounts(): Counts {
  return {
    selected: 0,
    versionNotKnown: 0,
    versionUnrepresentable: 0,
    inserted: { affected: 0, unaffected: 0, unknown: 0 },
    replayed: { affected: 0, unaffected: 0, unknown: 0 },
  };
}

function outcomeTotal(counts: OutcomeCounts): number {
  return counts.affected + counts.unaffected + counts.unknown;
}

function asOutcome(value: string): DeliberateProductMatchEvaluationOutcome | null {
  if (value === 'affected' || value === 'unaffected' || value === 'unknown') {
    return value;
  }
  return null;
}

function commandPinsAgree(command: DeliberateProductMatchEvaluationCommand): boolean {
  return (
    command.schemaVersion === DELIBERATE_PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION &&
    command.policyId === DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_ID &&
    command.policyVersion === DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_VERSION &&
    command.purpose === DELIBERATE_PRODUCT_MATCH_EVALUATION_PURPOSE &&
    command.role === 'owner' &&
    command.evaluatorId === PRODUCT_MATCH_EVALUATOR_ID &&
    command.evaluatorVersion === PRODUCT_MATCH_EVALUATOR_VERSION &&
    command.matchingPolicyId === PRODUCT_MATCH_MATCHING_POLICY_ID &&
    command.matchingPolicyVersion === PRODUCT_MATCH_MATCHING_POLICY_VERSION &&
    command.productEvidencePolicyId === PRODUCT_MATCH_EVALUATION_POLICY_ID &&
    command.productEvidencePolicyVersion === PRODUCT_MATCH_EVALUATION_POLICY_VERSION &&
    command.findingCreation === PRODUCT_MATCH_FINDING_CREATION &&
    command.suppressionAuthority === PRODUCT_MATCH_SUPPRESSION_AUTHORITY &&
    command.explicitVersionsUsed === false &&
    command.normalizationVersion === DELIBERATE_PRODUCT_MATCH_EVALUATION_NORMALIZATION_VERSION &&
    command.occurrenceCap === DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_CAP &&
    command.selectionProbe === DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE &&
    command.findingWrites === DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES &&
    command.providerCalls === DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS &&
    UUID_V4.test(command.organizationId) &&
    UUID_V4.test(command.assetId) &&
    UUID_V4.test(command.advisoryRevisionId) &&
    UUID_V4.test(command.actorUserId) &&
    UUID_V4.test(command.membershipId) &&
    UUID_V4.test(command.operationCorrelationId) &&
    DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSPORT_ID_PATTERN.test(command.requestId) &&
    DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSPORT_ID_PATTERN.test(command.correlationId)
  );
}

function decisionPinsAgree(decisions: DeliberateProductMatchEvaluationDecisions): boolean {
  return (
    decisions.statementTimeoutMs === DELIBERATE_PRODUCT_MATCH_EVALUATION_STATEMENT_TIMEOUT_MS &&
    decisions.lockTimeoutMs === DELIBERATE_PRODUCT_MATCH_EVALUATION_LOCK_TIMEOUT_MS &&
    decisions.maxWaitMs === DELIBERATE_PRODUCT_MATCH_EVALUATION_MAX_WAIT_MS &&
    decisions.transactionTimeoutMs === DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSACTION_TIMEOUT_MS &&
    decisions.occurrenceOrder === DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_ORDER &&
    typeof decisions.assessAdvisory === 'function' &&
    typeof decisions.advisoryFailureStatus === 'function' &&
    typeof decisions.classifyOccurrenceVersion === 'function' &&
    typeof decisions.classifyIngestion === 'function' &&
    typeof decisions.classifySelectionCount === 'function' &&
    typeof decisions.planAudit === 'function' &&
    typeof decisions.lockIdentity === 'function'
  );
}

function membershipRole(value: string): MembershipRole | null {
  switch (value) {
    case 'owner':
    case 'admin':
    case 'member':
    case 'viewer':
      return value;
    default:
      return null;
  }
}

function numericVersion(value: string): number | null {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function acceptsTimeout(value: string, milliseconds: number): boolean {
  const seconds = milliseconds / 1000;
  const normalized = value.trim().toLowerCase();
  return (
    normalized === String(milliseconds) ||
    normalized === `${milliseconds}ms` ||
    normalized === `${seconds}s`
  );
}

function sameCodes(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function throwFault(
  fault: DeliberateProductMatchEvaluationFault | undefined,
  stage: DeliberateProductMatchEvaluationFault,
): void {
  if (fault === stage) {
    throw new DeliberateEvaluationAbort('transaction_aborted');
  }
}

function cloneJson(value: {
  readonly schemaVersion: number;
  readonly metadata: object;
}): Prisma.JsonValue {
  const cloned: unknown = JSON.parse(JSON.stringify(value));
  if (cloned === null || typeof cloned !== 'object' || Array.isArray(cloned)) {
    throw new DeliberateEvaluationAbort('internal_failure');
  }
  return cloned as Prisma.JsonValue;
}

function directAbort(error: unknown): DeliberateProductMatchEvaluationFailureStatus | null {
  if (error instanceof DeliberateEvaluationAbort) {
    return error.status;
  }
  if (error instanceof Error && error.name === 'ProductMatchRowError') {
    return 'malformed_persisted_state';
  }
  if (error instanceof Error && error.cause !== undefined) {
    if (error.cause instanceof DeliberateEvaluationAbort) {
      return error.cause.status;
    }
    if (error.cause instanceof Error && error.cause.name === 'ProductMatchRowError') {
      return 'malformed_persisted_state';
    }
  }
  return null;
}

function translateDeliberateFailure(error: unknown): DeliberateProductMatchEvaluationFailureStatus {
  if (isDeliberateTimeout(error)) {
    return 'timeout';
  }
  const code = translateProductMatchFailure(error);
  if (code === 'database_unavailable' || code === 'timeout') {
    return code;
  }
  if (
    code === 'transaction_aborted' ||
    code === 'foreign_key_failure' ||
    code === 'check_constraint_failure'
  ) {
    return 'transaction_aborted';
  }
  return 'internal_failure';
}

function isDeliberateTimeout(error: unknown, depth = 0): boolean {
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P1008' || error.code === 'P2024' || error.code === 'P2028')
  ) {
    return true;
  }
  const state = sqlState(error);
  if (state === '55P03' || state === '57014') {
    return true;
  }
  if (
    error instanceof Error &&
    /55P03|57014|lock timeout|statement timeout|canceling statement due to statement timeout/i.test(
      error.message,
    )
  ) {
    return true;
  }
  return (
    depth < 4 &&
    error instanceof Error &&
    error.cause !== undefined &&
    isDeliberateTimeout(error.cause, depth + 1)
  );
}

function sqlState(error: unknown): string | undefined {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    return typeof metaCode === 'string' ? metaCode : undefined;
  }
  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    return /code: "([0-9A-Z]{5})"/.exec(error.message)?.[1];
  }
  return undefined;
}

function rangesFrom(
  events: readonly {
    readonly rangeOrdinal: number;
    readonly eventOrdinal: number;
    readonly eventName: string;
    readonly eventValue: string;
  }[],
): ProductMatchAdvisoryBundle['ranges'] | null {
  const grouped = new Map<
    number,
    { name: 'introduced' | 'fixed' | 'last_affected' | 'limit'; value: string }[]
  >();
  for (const event of events) {
    if (!EVENT_NAMES.has(event.eventName)) {
      return null;
    }
    const name = event.eventName as 'introduced' | 'fixed' | 'last_affected' | 'limit';
    const current = grouped.get(event.rangeOrdinal) ?? [];
    current.push({ name, value: event.eventValue });
    grouped.set(event.rangeOrdinal, current);
  }
  return [...grouped.entries()]
    .sort((left, right) => left[0] - right[0])
    .map((entry) => ({
      type: 'SEMVER' as const,
      events: entry[1],
    }));
}
