/**
 * Read-only PostgreSQL adapter for one asset-scoped Product Match candidate page.
 * Eligibility stays in assembleProductMatchCandidatePage.
 * This adapter writes no evidence, no Finding, and no audit row.
 * Production startup constructs it only from the API candidate runtime.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import { roleGrantsProductMatchDiscovery, type MembershipRole } from '@patchpilot/domain';
import type { ProductMatchAdvisoryBundle } from '@patchpilot/vulnerability-intelligence';
import {
  assembleProductMatchCandidatePage,
  productMatchIdentityKeyForGroup,
  type ProductMatchCandidateDecisions,
  type ProductMatchCandidateLoadedFacts,
  type ProductMatchCandidateOccurrenceGroup,
  type ProductMatchCandidatePort,
  type ProductMatchCandidateQuery,
  type ProductMatchCandidateRead,
} from '@patchpilot/vulnerability-intelligence/product-match-candidates';

import { isRootPrismaClient } from './guards.js';
import { translateProductMatchFailure } from './product-match-evaluation-persistence-errors.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVENT_NAMES = new Set(['introduced', 'fixed', 'last_affected', 'limit']);
const STATEMENT_TIMEOUT_MS = 5000;
const MAX_WAIT_MS = 2000;
const TRANSACTION_TIMEOUT_MS = 5000;

type Loaded =
  | { readonly kind: 'terminal'; readonly read: ProductMatchCandidateRead }
  | { readonly kind: 'facts'; readonly facts: ProductMatchCandidateLoadedFacts };

type RevisionRow = {
  readonly id: string;
  readonly advisoryFamilyId: string;
  readonly origin: string;
  readonly source: string;
  readonly contentFingerprint: string;
  readonly session14RangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly ecosystem: string;
  readonly packageNamespace: string | null;
  readonly packageName: string;
  readonly authorIdentity: string | null;
  readonly withdrawalClassification: string;
  readonly quarantineClassification: string;
  readonly revisionDisposition: string;
  readonly supersedesRevisionDigest: string;
  readonly spdxLicenseId: string | null;
  readonly advisorySchemaVersion: string;
  readonly trustClassification: string;
  readonly successors: readonly { readonly id: string }[];
};

type ApprovalRow = {
  readonly id: string;
  readonly advisoryRevisionId: string;
  readonly advisoryFamilyId: string;
  readonly advisoryVulnerabilityBindingId: string;
  readonly authorIdentity: string;
  readonly reviewerIdentity: string;
  readonly reviewerClassification: string;
  readonly approvalPurpose: string;
  readonly approvalPolicyId: string;
  readonly approvalPolicyVersion: number;
  readonly sourceClassification: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly vulnerabilityId: string;
  readonly sourceLicensePolicyId: string;
  readonly sourceLicensePolicyVersion: number;
  readonly approvedLicenseClassification: string;
  readonly licenseDecisionCanonical: string;
};

type BindingRow = {
  readonly id: string;
  readonly advisoryRevisionId: string;
  readonly vulnerabilityId: string;
  readonly mappingReviewState: string;
  readonly conflictClassification: string;
  readonly mappingMethod: string;
  readonly mappingPolicyId: string;
};

type RangeEventRow = {
  readonly advisoryRevisionId: string;
  readonly rangeOrdinal: number;
  readonly eventOrdinal: number;
  readonly eventName: string;
  readonly eventValue: string;
};

export function createProductMatchCandidatePersistence(
  client: PrismaClient,
): ProductMatchCandidatePort {
  if (!isRootPrismaClient(client)) {
    throw new Error('Product match candidate persistence requires the root Prisma client.');
  }
  return {
    async read(query, decisions) {
      try {
        return await readCandidates(client, query, decisions);
      } catch (error) {
        return translateReadFailure(error);
      }
    },
  };
}

async function readCandidates(
  client: PrismaClient,
  query: ProductMatchCandidateQuery,
  decisions: ProductMatchCandidateDecisions,
): Promise<ProductMatchCandidateRead> {
  if (!decisionsArePresent(decisions) || !queryIsPresent(query)) {
    return { status: 'internal_failure' };
  }
  const loaded = await client.$transaction((tx) => loadFacts(tx, query, decisions), {
    isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
    maxWait: MAX_WAIT_MS,
    timeout: TRANSACTION_TIMEOUT_MS,
  });
  if (loaded.kind === 'terminal') {
    return loaded.read;
  }
  return assembleProductMatchCandidatePage({
    assetId: query.assetId,
    limit: query.limit,
    cursor: query.cursor,
    facts: loaded.facts,
    decisions,
  });
}

async function loadFacts(
  tx: Prisma.TransactionClient,
  query: ProductMatchCandidateQuery,
  decisions: ProductMatchCandidateDecisions,
): Promise<Loaded> {
  const configured = await configureRead(tx);
  if (!configured) {
    return terminal('internal_failure');
  }
  const actor = await reloadActor(tx, query);
  if (!actor) {
    return terminal('authority_rejected');
  }
  const asset = await tx.asset.findFirst({
    where: { id: query.assetId, organizationId: query.organizationId },
    select: { lastSuccessfulSbomIngestionId: true },
  });
  if (asset === null) {
    return terminal('not_found');
  }
  const pointer = asset.lastSuccessfulSbomIngestionId;
  if (pointer === null) {
    return {
      kind: 'facts',
      facts: emptyFacts({
        pointerPresent: false,
        ingestionId: null,
        ingestionState: null,
        normalizationVersion: null,
        sameAssetAndOrganization: false,
      }),
    };
  }
  if (!UUID_V4.test(pointer)) {
    return terminal('malformed_persisted_state');
  }
  const ingestion = await tx.sbomIngestion.findFirst({
    where: { id: pointer, organizationId: query.organizationId },
    select: {
      id: true,
      state: true,
      normalizationVersion: true,
      organizationId: true,
      assetId: true,
    },
  });
  if (ingestion === null) {
    return terminal('malformed_persisted_state');
  }
  const version = numericVersion(ingestion.normalizationVersion);
  const ingestionFacts = {
    pointerPresent: true,
    ingestionId: ingestion.id,
    ingestionState: ingestion.state,
    normalizationVersion: version ?? ingestion.normalizationVersion,
    sameAssetAndOrganization:
      ingestion.organizationId === query.organizationId && ingestion.assetId === query.assetId,
  };
  const readiness = decisions.classifyIngestion(ingestionFacts);
  if (readiness === 'malformed_persisted_state') {
    return terminal('malformed_persisted_state');
  }
  if (readiness !== 'ready') {
    return { kind: 'facts', facts: emptyFacts(ingestionFacts) };
  }
  const groups = await loadOccurrenceGroups(tx, query, ingestion.id);
  if (groups === 'malformed') {
    return terminal('malformed_persisted_state');
  }
  const identityKeys = identityKeysFor(groups, decisions);
  const advisories = identityKeys.length === 0 ? [] : await loadAdvisories(tx, identityKeys);
  if (advisories === 'malformed') {
    return terminal('malformed_persisted_state');
  }
  const evaluatedRevisionIds = await loadEvaluatedRevisionIds(
    tx,
    query,
    ingestion.id,
    advisories.map((bundle) => bundle.revision.revisionId),
  );
  return {
    kind: 'facts',
    facts: {
      ingestion: ingestionFacts,
      occurrenceGroups: groups,
      advisories,
      evaluatedRevisionIds,
    },
  };
}

async function configureRead(tx: Prisma.TransactionClient): Promise<boolean> {
  await tx.$queryRaw`SELECT set_config('statement_timeout', '5000', true) AS configured`;
  const settings = await tx.$queryRaw<Array<{ statement_timeout: string; isolation: string }>>`
    SELECT current_setting('statement_timeout') AS statement_timeout,
           current_setting('transaction_isolation') AS isolation
  `;
  const setting = settings[0];
  return (
    settings.length === 1 &&
    setting !== undefined &&
    acceptsTimeout(setting.statement_timeout, STATEMENT_TIMEOUT_MS) &&
    setting.isolation === 'read committed'
  );
}

async function reloadActor(
  tx: Prisma.TransactionClient,
  query: ProductMatchCandidateQuery,
): Promise<boolean> {
  const users = await tx.user.findMany({
    where: { id: query.actorUserId },
    select: { id: true, status: true },
    take: 2,
  });
  const user = users[0];
  if (users.length !== 1 || user === undefined || user.status !== 'active') {
    return false;
  }
  const organizations = await tx.organization.findMany({
    where: { id: query.organizationId },
    select: { id: true, status: true },
    take: 2,
  });
  const organization = organizations[0];
  if (
    organizations.length !== 1 ||
    organization === undefined ||
    organization.status !== 'active'
  ) {
    return false;
  }
  const memberships = await tx.membership.findMany({
    where: { id: query.membershipId, organizationId: query.organizationId },
    select: { id: true, userId: true, status: true, role: true },
    take: 2,
  });
  const membership = memberships[0];
  if (memberships.length !== 1 || membership === undefined) {
    return false;
  }
  const role = membershipRole(membership.role);
  return (
    membership.userId === query.actorUserId &&
    membership.status === 'active' &&
    role === 'owner' &&
    roleGrantsProductMatchDiscovery(role)
  );
}

async function loadOccurrenceGroups(
  tx: Prisma.TransactionClient,
  query: ProductMatchCandidateQuery,
  ingestionId: string,
): Promise<readonly ProductMatchCandidateOccurrenceGroup[] | 'malformed'> {
  const rows = await tx.$queryRaw<
    Array<{
      ecosystem: string | null;
      namespace: string | null;
      name: string | null;
      occurrence_count: bigint | number | string;
    }>
  >`
    SELECT component."ecosystem" AS ecosystem,
           component."namespace" AS namespace,
           component."name" AS name,
           COUNT(*)::bigint AS occurrence_count
    FROM "component_occurrence" AS occurrence
    INNER JOIN "component" AS component
      ON component."organization_id" = occurrence."organization_id"
     AND component."id" = occurrence."component_id"
    WHERE occurrence."organization_id" = ${query.organizationId}::uuid
      AND occurrence."asset_id" = ${query.assetId}::uuid
      AND occurrence."sbom_ingestion_id" = ${ingestionId}::uuid
    GROUP BY component."ecosystem", component."namespace", component."name"
  `;
  const groups: ProductMatchCandidateOccurrenceGroup[] = [];
  for (const row of rows) {
    const count = countValue(row.occurrence_count);
    if (count === null || typeof row.name !== 'string' || row.name.length === 0) {
      return 'malformed';
    }
    groups.push({
      ecosystem: row.ecosystem,
      namespace: row.namespace,
      name: row.name,
      count,
    });
  }
  return groups;
}

function identityKeysFor(
  groups: readonly ProductMatchCandidateOccurrenceGroup[],
  decisions: ProductMatchCandidateDecisions,
): readonly string[] {
  const keys = new Set<string>();
  for (const group of groups) {
    const identityKey = productMatchIdentityKeyForGroup(group, decisions.classifyIdentity);
    if (identityKey !== null) {
      keys.add(identityKey);
    }
  }
  return [...keys];
}

async function loadAdvisories(
  tx: Prisma.TransactionClient,
  identityKeys: readonly string[],
): Promise<readonly ProductMatchAdvisoryBundle[] | 'malformed'> {
  const revisions = await tx.advisoryRevision.findMany({
    where: {
      ecosystem: 'npm',
      packageIdentityKey: { in: [...identityKeys] },
    },
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
  if (revisions.length === 0) {
    return [];
  }
  const revisionIds = revisions.map((revision) => revision.id);
  const approvals = await tx.maintainerReviewedAdvisoryApproval.findMany({
    where: { advisoryRevisionId: { in: revisionIds } },
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
  const bindings = await tx.advisoryVulnerabilityBinding.findMany({
    where: { advisoryRevisionId: { in: revisionIds } },
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
  const events = await tx.advisoryRevisionRangeEvent.findMany({
    where: { advisoryRevisionId: { in: revisionIds } },
    select: {
      advisoryRevisionId: true,
      rangeOrdinal: true,
      eventOrdinal: true,
      eventName: true,
      eventValue: true,
    },
    orderBy: [{ advisoryRevisionId: 'asc' }, { rangeOrdinal: 'asc' }, { eventOrdinal: 'asc' }],
  });
  return bundlesFrom(revisions, approvals, bindings, events);
}

function bundlesFrom(
  revisions: readonly RevisionRow[],
  approvals: readonly ApprovalRow[],
  bindings: readonly BindingRow[],
  events: readonly RangeEventRow[],
): readonly ProductMatchAdvisoryBundle[] | 'malformed' {
  const approvalByRevision = indexOne(approvals, (row) => row.advisoryRevisionId);
  const bindingByRevision = indexOne(bindings, (row) => row.advisoryRevisionId);
  if (approvalByRevision === 'malformed' || bindingByRevision === 'malformed') {
    return 'malformed';
  }
  const eventsByRevision = new Map<string, RangeEventRow[]>();
  for (const event of events) {
    const current = eventsByRevision.get(event.advisoryRevisionId) ?? [];
    current.push(event);
    eventsByRevision.set(event.advisoryRevisionId, current);
  }
  const bundles: ProductMatchAdvisoryBundle[] = [];
  for (const revision of revisions) {
    const approval = approvalByRevision.get(revision.id);
    const binding = bindingByRevision.get(revision.id);
    if (approval === undefined || binding === undefined || revision.authorIdentity === null) {
      continue;
    }
    const ranges = rangesFrom(eventsByRevision.get(revision.id) ?? []);
    if (ranges === null) {
      continue;
    }
    bundles.push({
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
    });
  }
  return bundles;
}

async function loadEvaluatedRevisionIds(
  tx: Prisma.TransactionClient,
  query: ProductMatchCandidateQuery,
  ingestionId: string,
  revisionIds: readonly string[],
): Promise<readonly string[]> {
  if (revisionIds.length === 0) {
    return [];
  }
  const rows = await tx.productMatchEvaluationEvidence.findMany({
    where: {
      organizationId: query.organizationId,
      assetId: query.assetId,
      sbomIngestionId: ingestionId,
      advisoryRevisionId: { in: [...revisionIds] },
    },
    select: { advisoryRevisionId: true },
    distinct: ['advisoryRevisionId'],
  });
  return rows.map((row) => row.advisoryRevisionId);
}

function emptyFacts(
  ingestion: ProductMatchCandidateLoadedFacts['ingestion'],
): ProductMatchCandidateLoadedFacts {
  return {
    ingestion,
    occurrenceGroups: [],
    advisories: [],
    evaluatedRevisionIds: [],
  };
}

function terminal(
  status: 'authority_rejected' | 'not_found' | 'malformed_persisted_state' | 'internal_failure',
): Loaded {
  return { kind: 'terminal', read: { status } };
}

function indexOne<T>(rows: readonly T[], keyOf: (row: T) => string): Map<string, T> | 'malformed' {
  const indexed = new Map<string, T>();
  for (const row of rows) {
    const key = keyOf(row);
    if (indexed.has(key)) {
      return 'malformed';
    }
    indexed.set(key, row);
  }
  return indexed;
}

function rangesFrom(events: readonly RangeEventRow[]): ProductMatchAdvisoryBundle['ranges'] | null {
  if (events.length === 0) {
    return [];
  }
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

function countValue(value: bigint | number | string): number | null {
  if (typeof value === 'bigint') {
    if (value < 1n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      return null;
    }
    return Number(value);
  }
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 1 ? value : null;
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function numericVersion(value: string): number | null {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
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

function acceptsTimeout(value: string, milliseconds: number): boolean {
  const seconds = milliseconds / 1000;
  const normalized = value.trim().toLowerCase();
  return (
    normalized === String(milliseconds) ||
    normalized === `${milliseconds}ms` ||
    normalized === `${seconds}s`
  );
}

function queryIsPresent(query: ProductMatchCandidateQuery): boolean {
  return (
    UUID_V4.test(query.organizationId) &&
    UUID_V4.test(query.membershipId) &&
    UUID_V4.test(query.actorUserId) &&
    UUID_V4.test(query.assetId) &&
    Number.isInteger(query.limit) &&
    query.limit >= 1 &&
    query.limit <= 20
  );
}

function decisionsArePresent(decisions: ProductMatchCandidateDecisions): boolean {
  return (
    typeof decisions.assessAdvisory === 'function' &&
    typeof decisions.classifyIdentity === 'function' &&
    typeof decisions.classifyIngestion === 'function'
  );
}

function translateReadFailure(error: unknown): ProductMatchCandidateRead {
  if (isReadTimeout(error)) {
    return { status: 'database_unavailable' };
  }
  const code = translateProductMatchFailure(error);
  if (code === 'database_unavailable' || code === 'timeout') {
    return { status: 'database_unavailable' };
  }
  return { status: 'internal_failure' };
}

function isReadTimeout(error: unknown, depth = 0): boolean {
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P1008' || error.code === 'P2024' || error.code === 'P2028')
  ) {
    return true;
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    if (metaCode === '57014' || metaCode === '55P03') {
      return true;
    }
  }
  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    const state = /code: "([0-9A-Z]{5})"/.exec(error.message)?.[1];
    if (state === '57014' || state === '55P03') {
      return true;
    }
  }
  return depth < 4 && error instanceof Error && error.cause !== undefined
    ? isReadTimeout(error.cause, depth + 1)
    : false;
}
