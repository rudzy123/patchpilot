/**
 * Uncomposed PostgreSQL adapter for one legal product-match evaluation.
 * Production startup does not construct this factory.
 */

import { createHash } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
import {
  PRODUCT_MATCH_EVALUATION_ORIGIN,
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATION_SCHEMA_VERSION,
  PRODUCT_MATCH_FINDING_AUTHORITY,
  PRODUCT_MATCH_FINDING_CREATION,
  PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
  assessProductMatchEligibility,
  classifyStoredProductMatchReplay,
  evaluateReviewedNpmRange,
  isFirstEcosystemExplanationCode,
  productMatchReplayFingerprint,
  type ProductMatchAdvisoryBundle,
  type ProductMatchComponentSnapshot,
  type ProductMatchEvaluationPort,
  type ProductMatchEvaluationProjection,
  type ProductMatchEvaluationRejectionCode,
  type ProductMatchEvaluationResult,
  type ProductMatchReplayBody,
  type StoredProductMatchRecord,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';
import {
  isProductMatchUniqueViolation,
  translateProductMatchFailure,
} from './product-match-evaluation-persistence-errors.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVENT_NAMES = new Set(['introduced', 'fixed', 'last_affected', 'limit']);
const OUTCOMES = new Set(['affected', 'unaffected', 'unknown']);

const EVIDENCE_SELECT = {
  id: true,
  organizationId: true,
  componentOccurrenceId: true,
  componentEvidenceFingerprint: true,
  packageIdentityKey: true,
  rawObservedVersion: true,
  advisoryRevisionId: true,
  approvalId: true,
  contentFingerprint: true,
  rangeFingerprint: true,
  vulnerabilityId: true,
  evaluatorId: true,
  evaluatorVersion: true,
  matchingPolicyId: true,
  matchingPolicyVersion: true,
  productEvidencePolicyId: true,
  productEvidencePolicyVersion: true,
  productOrigin: true,
  outcome: true,
  replayFingerprint: true,
  findingCreation: true,
  suppressionAuthority: true,
  createdAt: true,
  explanations: {
    select: { ordinal: true, explanationCode: true },
    orderBy: { ordinal: 'asc' as const },
  },
} as const;

type EvidenceRow = Prisma.ProductMatchEvaluationEvidenceGetPayload<{
  select: typeof EVIDENCE_SELECT;
}>;

class ProductMatchRowError extends Error {
  public constructor() {
    super('persisted product match row failed closed validation');
    this.name = 'ProductMatchRowError';
  }
}

export function createProductMatchEvaluationPersistence(
  client: PrismaClient,
): ProductMatchEvaluationPort {
  if (!isRootPrismaClient(client)) {
    throw new Error('Product match evaluation persistence requires the root database client.');
  }
  return new PrismaProductMatchEvaluationPersistence(client);
}

class PrismaProductMatchEvaluationPersistence implements ProductMatchEvaluationPort {
  public constructor(private readonly client: PrismaClient) {}

  public async findExisting(query: {
    readonly organizationId: string;
    readonly componentOccurrenceId: string;
    readonly advisoryRevisionId: string;
  }): Promise<
    | { readonly kind: 'none' }
    | { readonly kind: 'row'; readonly row: StoredProductMatchRecord }
    | {
        readonly kind: 'rejected';
        readonly code: 'database_unavailable' | 'malformed_persisted_state';
      }
  > {
    try {
      const row = await this.client.productMatchEvaluationEvidence.findFirst({
        where: {
          organizationId: query.organizationId,
          OR: [
            { componentOccurrenceId: query.componentOccurrenceId },
            { advisoryRevisionId: query.advisoryRevisionId },
          ],
        },
        select: EVIDENCE_SELECT,
      });
      if (row === null) {
        return { kind: 'none' };
      }
      return { kind: 'row', row: storedFrom(row) };
    } catch (error) {
      if (error instanceof ProductMatchRowError) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      const code = translateProductMatchFailure(error);
      return {
        kind: 'rejected',
        code: code === 'database_unavailable' ? code : 'database_unavailable',
      };
    }
  }

  public async inspectComponent(query: {
    readonly organizationId: string;
    readonly componentOccurrenceId: string;
  }) {
    if (!UUID_V4.test(query.organizationId) || !UUID_V4.test(query.componentOccurrenceId)) {
      return { kind: 'malformed' as const };
    }
    try {
      const occurrence = await this.client.componentOccurrence.findFirst({
        where: {
          organizationId: query.organizationId,
          id: query.componentOccurrenceId,
        },
        select: {
          id: true,
          organizationId: true,
          assetId: true,
          sbomId: true,
          sbomIngestionId: true,
          componentId: true,
          version: true,
          versionKnown: true,
        },
      });
      if (occurrence === null || occurrence.organizationId !== query.organizationId) {
        return { kind: 'not_found' as const };
      }
      const component = await this.client.component.findFirst({
        where: { organizationId: occurrence.organizationId, id: occurrence.componentId },
        select: {
          identityKey: true,
          ecosystem: true,
          namespace: true,
          name: true,
          purl: true,
          identityState: true,
        },
      });
      const sbom = await this.client.sbom.findFirst({
        where: {
          organizationId: occurrence.organizationId,
          id: occurrence.sbomId,
          assetId: occurrence.assetId,
        },
        select: { sha256: true },
      });
      if (
        component === null ||
        sbom === null ||
        component.ecosystem === null ||
        component.name.length === 0 ||
        !/^[a-f0-9]{64}$/.test(sbom.sha256)
      ) {
        return { kind: 'malformed' as const };
      }
      return {
        kind: 'found' as const,
        snapshot: {
          organizationId: occurrence.organizationId,
          componentOccurrenceId: occurrence.id,
          assetId: occurrence.assetId,
          sbomId: occurrence.sbomId,
          sbomIngestionId: occurrence.sbomIngestionId,
          componentId: occurrence.componentId,
          componentIdentityKey: component.identityKey,
          sbomSha256: sbom.sha256,
          ecosystem: component.ecosystem,
          namespace: component.namespace,
          name: component.name,
          purl: component.purl,
          rawObservedVersion: occurrence.version,
          versionKnown: occurrence.versionKnown,
          identityState: component.identityState,
        },
      };
    } catch {
      return { kind: 'unavailable' as const };
    }
  }

  public async inspectAdvisory(query: {
    readonly advisoryRevisionId: string;
    readonly approvalEvidenceId: string;
  }) {
    if (!UUID_V4.test(query.advisoryRevisionId) || !UUID_V4.test(query.approvalEvidenceId)) {
      return { kind: 'malformed' as const };
    }
    try {
      const revision = await this.client.advisoryRevision.findFirst({
        where: { id: query.advisoryRevisionId },
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
        return { kind: 'revision_missing' as const };
      }
      const approval = await this.client.maintainerReviewedAdvisoryApproval.findFirst({
        where: { id: query.approvalEvidenceId },
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
        return { kind: 'approval_missing' as const };
      }
      const binding = await this.client.advisoryVulnerabilityBinding.findFirst({
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
        return { kind: 'binding_missing' as const };
      }
      const events = await this.client.advisoryRevisionRangeEvent.findMany({
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
        return { kind: 'range_missing' as const };
      }
      const ranges = rangesFrom(events);
      if (ranges === null || revision.authorIdentity === null) {
        return { kind: 'malformed' as const };
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
      return { kind: 'found' as const, bundle };
    } catch {
      return { kind: 'unavailable' as const };
    }
  }

  public async commit(
    input: Parameters<ProductMatchEvaluationPort['commit']>[0],
  ): Promise<ProductMatchEvaluationResult> {
    let evaluatorCalls: 0 | 1 = 0;
    try {
      return await this.client.$transaction(async (tx) => {
        const locked = await tx.$queryRaw<Array<{ id: string }>>`
          SELECT "id"
          FROM "component_occurrence"
          WHERE "organization_id" = ${input.command.organizationId}::uuid
            AND "id" = ${input.command.componentOccurrenceId}::uuid
          FOR UPDATE
        `;
        const existing = await tx.productMatchEvaluationEvidence.findFirst({
          where: {
            organizationId: input.command.organizationId,
            OR: [
              { componentOccurrenceId: input.command.componentOccurrenceId },
              { advisoryRevisionId: input.command.advisoryRevisionId },
            ],
          },
          select: EVIDENCE_SELECT,
        });
        if (existing !== null) {
          const stored = storedFrom(existing);
          const disposition = classifyStoredProductMatchReplay(stored, input.command);
          if (disposition === 'malformed') {
            throw new ProductMatchRowError();
          }
          if (disposition === 'applied') {
            return applied(projectFrom(stored), 0, 0);
          }
          return {
            kind: 'immutable_conflict' as const,
            evaluatorCalls: 0 as const,
            providerCalls: 0 as const,
            parserCalls: 0 as const,
            findingWrites: 0 as const,
            inserts: 0 as const,
          };
        }
        if (locked.length !== 1) {
          return rejectedResult('component_occurrence_missing', 0);
        }
        const component = await this.inspectComponent({
          organizationId: input.command.organizationId,
          componentOccurrenceId: input.command.componentOccurrenceId,
        });
        if (component.kind !== 'found') {
          return rejectedResult(componentRejection(component.kind), 0);
        }
        const advisory = await this.inspectAdvisory({
          advisoryRevisionId: input.command.advisoryRevisionId,
          approvalEvidenceId: input.command.approvalEvidenceId,
        });
        if (advisory.kind !== 'found') {
          return rejectedResult(advisoryRejection(advisory.kind), 0);
        }
        const failure = assessProductMatchEligibility(
          input.command,
          component.snapshot,
          advisory.bundle,
        );
        if (failure !== null) {
          return rejectedResult(failure, 0);
        }
        const decision = evaluateReviewedNpmRange({
          namespace: component.snapshot.namespace,
          name: component.snapshot.name,
          rawObservedVersion: component.snapshot.rawObservedVersion,
          ranges: advisory.bundle.ranges,
        });
        evaluatorCalls = 1;
        const body = replayBody(input.command, component.snapshot, decision);
        const created = await tx.productMatchEvaluationEvidence.create({
          data: {
            organizationId: component.snapshot.organizationId,
            componentOccurrenceId: component.snapshot.componentOccurrenceId,
            assetId: component.snapshot.assetId,
            sbomId: component.snapshot.sbomId,
            sbomIngestionId: component.snapshot.sbomIngestionId,
            componentId: component.snapshot.componentId,
            sbomSha256: component.snapshot.sbomSha256,
            componentIdentityKey: component.snapshot.componentIdentityKey,
            componentEvidenceFingerprint: body.componentEvidenceFingerprint,
            evidenceSchemaVersion: PRODUCT_MATCH_EVALUATION_SCHEMA_VERSION,
            packageIdentityKey: body.packageIdentityKey,
            rawObservedVersion: body.rawObservedVersion,
            rawObservedVersionSha256: sha256(body.rawObservedVersion),
            advisoryFamilyId: advisory.bundle.revision.familyId,
            advisoryRevisionId: body.advisoryRevisionId,
            approvalId: body.approvalEvidenceId,
            contentFingerprint: body.contentFingerprint,
            rangeFingerprint: body.rangeFingerprint,
            vulnerabilityId: body.vulnerabilityId,
            evaluatorId: body.evaluatorId,
            evaluatorVersion: body.evaluatorVersion,
            matchingPolicyId: body.matchingPolicyId,
            matchingPolicyVersion: body.matchingPolicyVersion,
            productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
            productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
            outcome: body.outcome,
            productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
            replayFingerprint: productMatchReplayFingerprint(body),
            findingCreation: PRODUCT_MATCH_FINDING_CREATION,
            suppressionAuthority: PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
            explanations: {
              create: body.explanationCodes.map((code, index) => ({
                ordinal: index + 1,
                explanationCode: code,
              })),
            },
          },
          select: EVIDENCE_SELECT,
        });
        return applied(projectFrom(storedFrom(created)), 1, 1);
      });
    } catch (error) {
      if (error instanceof ProductMatchRowError) {
        return rejectedResult('malformed_persisted_state', evaluatorCalls);
      }
      if (isProductMatchUniqueViolation(error)) {
        return {
          kind: 'immutable_conflict',
          evaluatorCalls,
          providerCalls: 0,
          parserCalls: 0,
          findingWrites: 0,
          inserts: 0,
        };
      }
      return rejectedResult(translateProductMatchFailure(error), evaluatorCalls);
    }
  }

  public async inspect(query: { readonly organizationId: string; readonly evidenceId: string }) {
    if (
      typeof query.organizationId !== 'string' ||
      typeof query.evidenceId !== 'string' ||
      !UUID_V4.test(query.organizationId) ||
      !UUID_V4.test(query.evidenceId)
    ) {
      return { kind: 'rejected' as const, code: 'invalid_command' as const };
    }
    try {
      const row = await this.client.productMatchEvaluationEvidence.findFirst({
        where: { organizationId: query.organizationId, id: query.evidenceId },
        select: EVIDENCE_SELECT,
      });
      if (row === null) {
        return { kind: 'not_found' as const };
      }
      return { kind: 'found' as const, projection: projectFrom(storedFrom(row)) };
    } catch (error) {
      if (error instanceof ProductMatchRowError) {
        return { kind: 'not_found' as const };
      }
      return { kind: 'rejected' as const, code: 'database_unavailable' as const };
    }
  }
}

function replayBody(
  command: Parameters<ProductMatchEvaluationPort['commit']>[0]['command'],
  component: ProductMatchComponentSnapshot,
  decision: ReturnType<typeof evaluateReviewedNpmRange>,
): ProductMatchReplayBody {
  return {
    organizationId: component.organizationId,
    componentOccurrenceId: component.componentOccurrenceId,
    componentEvidenceFingerprint: command.expectedComponentEvidenceFingerprint,
    packageIdentityKey: command.expectedNpmPackageIdentity,
    rawObservedVersion: component.rawObservedVersion,
    advisoryRevisionId: command.advisoryRevisionId,
    approvalEvidenceId: command.approvalEvidenceId,
    contentFingerprint: command.expectedContentFingerprint,
    rangeFingerprint: command.expectedRangeFingerprint,
    vulnerabilityId: command.expectedVulnerabilityId,
    evaluatorId: command.evaluatorId,
    evaluatorVersion: command.evaluatorVersion,
    matchingPolicyId: command.matchingPolicyId,
    matchingPolicyVersion: command.matchingPolicyVersion,
    productEvidencePolicyId: command.productEvidencePolicyId,
    productEvidencePolicyVersion: String(command.productEvidencePolicyVersion),
    productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
    outcome: decision.outcome,
    explanationCodes: decision.explanationCodes,
  };
}

function componentRejection(
  kind: 'not_found' | 'malformed' | 'unavailable',
): ProductMatchEvaluationRejectionCode {
  if (kind === 'not_found') {
    return 'component_occurrence_missing';
  }
  if (kind === 'malformed') {
    return 'malformed_component';
  }
  return 'database_unavailable';
}

function advisoryRejection(
  kind:
    | 'revision_missing'
    | 'approval_missing'
    | 'binding_missing'
    | 'range_missing'
    | 'malformed'
    | 'unavailable',
): ProductMatchEvaluationRejectionCode {
  if (kind === 'revision_missing') {
    return 'revision_missing';
  }
  if (kind === 'approval_missing') {
    return 'approval_missing';
  }
  if (kind === 'binding_missing') {
    return 'vulnerability_binding_missing';
  }
  if (kind === 'range_missing') {
    return 'range_evidence_missing';
  }
  if (kind === 'malformed') {
    return 'malformed_persisted_state';
  }
  return 'database_unavailable';
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function storedFrom(row: EvidenceRow): StoredProductMatchRecord {
  if (
    row.productOrigin !== PRODUCT_MATCH_EVALUATION_ORIGIN ||
    row.findingCreation !== PRODUCT_MATCH_FINDING_CREATION ||
    row.suppressionAuthority !== false ||
    !OUTCOMES.has(row.outcome) ||
    row.explanations.length === 0
  ) {
    throw new ProductMatchRowError();
  }
  const codes: StoredProductMatchRecord['explanationCodes'][number][] = [];
  for (const explanation of row.explanations) {
    if (!isFirstEcosystemExplanationCode(explanation.explanationCode)) {
      throw new ProductMatchRowError();
    }
    codes.push(explanation.explanationCode);
  }
  const createdAt = row.createdAt.toISOString();
  const record: StoredProductMatchRecord = {
    matchEvidenceId: row.id,
    organizationId: row.organizationId,
    componentOccurrenceId: row.componentOccurrenceId,
    componentEvidenceFingerprint: row.componentEvidenceFingerprint,
    packageIdentityKey: row.packageIdentityKey,
    rawObservedVersion: row.rawObservedVersion,
    advisoryRevisionId: row.advisoryRevisionId,
    approvalEvidenceId: row.approvalId,
    contentFingerprint: row.contentFingerprint,
    rangeFingerprint: row.rangeFingerprint,
    vulnerabilityId: row.vulnerabilityId,
    evaluatorId: row.evaluatorId,
    evaluatorVersion: row.evaluatorVersion,
    matchingPolicyId: row.matchingPolicyId,
    matchingPolicyVersion: row.matchingPolicyVersion,
    productEvidencePolicyId: row.productEvidencePolicyId,
    productEvidencePolicyVersion: String(row.productEvidencePolicyVersion),
    productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
    outcome: row.outcome as StoredProductMatchRecord['outcome'],
    explanationCodes: codes,
    replayFingerprint: row.replayFingerprint,
    createdAt,
    findingCreation: PRODUCT_MATCH_FINDING_CREATION,
    suppressionAuthority: PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
  };
  if (record.replayFingerprint !== productMatchReplayFingerprint(record)) {
    throw new ProductMatchRowError();
  }
  return record;
}

function projectFrom(row: StoredProductMatchRecord): ProductMatchEvaluationProjection {
  return {
    matchEvidenceId: row.matchEvidenceId,
    componentOccurrenceId: row.componentOccurrenceId,
    packageIdentityKey: row.packageIdentityKey,
    rawObservedVersion: row.rawObservedVersion,
    vulnerabilityId: row.vulnerabilityId,
    advisoryRevisionId: row.advisoryRevisionId,
    evaluatorId: row.evaluatorId,
    evaluatorVersion: row.evaluatorVersion,
    matchingPolicyId: row.matchingPolicyId,
    matchingPolicyVersion: row.matchingPolicyVersion,
    outcome: row.outcome,
    explanationCodes: row.explanationCodes,
    productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
    createdAt: row.createdAt,
    findingAuthority: PRODUCT_MATCH_FINDING_AUTHORITY,
    findingCreation: row.findingCreation,
    suppressionAuthority: row.suppressionAuthority,
  };
}

function applied(
  projection: ProductMatchEvaluationProjection,
  evaluatorCalls: 0 | 1,
  inserts: 0 | 1,
): ProductMatchEvaluationResult {
  return {
    kind: evaluatorCalls === 0 ? 'already_applied' : 'recorded',
    projection,
    evaluatorCalls,
    providerCalls: 0,
    parserCalls: 0,
    findingWrites: 0,
    inserts,
  };
}

function rejectedResult(
  code: ProductMatchEvaluationRejectionCode,
  evaluatorCalls: 0 | 1,
): ProductMatchEvaluationResult {
  return {
    kind: 'rejected',
    code,
    evaluatorCalls,
    providerCalls: 0,
    parserCalls: 0,
    findingWrites: 0,
    inserts: 0,
  };
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
