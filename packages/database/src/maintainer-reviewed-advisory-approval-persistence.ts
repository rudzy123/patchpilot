/**
 * Uncomposed PostgreSQL adapter for immutable maintainer-reviewed approvals.
 * Production startup does not construct this factory.
 */

import { Prisma, PrismaClient } from '@prisma/client';
import {
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_APPROVAL_LICENSE_CANONICAL,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_ZERO_EFFECTS,
  MAINTAINER_REVIEWED_ORIGIN,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyStoredMaintainerReviewedApproval,
  maintainerReviewedApprovalReplayFingerprint,
  parseMaintainerReviewedAdvisoryApprovalCommand,
  parseMaintainerReviewedAdvisoryApprovalInspection,
  projectInspectedMaintainerReviewedApproval,
  type MaintainerReviewedAdvisoryApprovalPersistencePort,
  type MaintainerReviewedAdvisoryApprovalProjection,
  type MaintainerReviewedApprovalEffects,
  type MaintainerReviewedApprovalInspectionResult,
  type MaintainerReviewedApprovalPersistenceResult,
  type MaintainerReviewedApprovalRejectionCode,
  type ParsedMaintainerReviewedAdvisoryApprovalCommand,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';
import { translateMaintainerReviewedApprovalFailure } from './maintainer-reviewed-advisory-approval-persistence-errors.js';

const ROOT_CLIENT_REQUIRED =
  'Maintainer-reviewed approval persistence requires the root database client.';

class ApprovalRowIntegrityFailure extends Error {
  public constructor() {
    super('persisted approval row failed closed validation');
    this.name = 'ApprovalRowIntegrityFailure';
  }
}

const STORED_SELECT = {
  id: true,
  createdAt: true,
  approvalSchemaVersion: true,
  advisoryRevisionId: true,
  familyDigest: true,
  approvalPolicyId: true,
  approvalPolicyVersion: true,
  approvalPurpose: true,
  sourceClassification: true,
  authorIdentity: true,
  reviewerIdentity: true,
  reviewerClassification: true,
  contentFingerprint: true,
  rangeFingerprint: true,
  packageIdentityKey: true,
  vulnerabilityId: true,
  sourceLicensePolicyId: true,
  sourceLicensePolicyVersion: true,
  approvedLicenseClassification: true,
  licenseDecisionCanonical: true,
  replayFingerprint: true,
} as const;

type StoredApprovalRow = {
  readonly id: string;
  readonly createdAt: Date;
  readonly approvalSchemaVersion: string;
  readonly advisoryRevisionId: string;
  readonly familyDigest: string;
  readonly approvalPolicyId: string;
  readonly approvalPolicyVersion: number;
  readonly approvalPurpose: string;
  readonly sourceClassification: string;
  readonly authorIdentity: string;
  readonly reviewerIdentity: string;
  readonly reviewerClassification: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly vulnerabilityId: string;
  readonly sourceLicensePolicyId: string;
  readonly sourceLicensePolicyVersion: number;
  readonly approvedLicenseClassification: string;
  readonly licenseDecisionCanonical: string;
  readonly replayFingerprint: string;
};

function rejected(
  code: MaintainerReviewedApprovalRejectionCode,
): MaintainerReviewedApprovalPersistenceResult {
  return { kind: 'rejected', code, effects: MAINTAINER_REVIEWED_APPROVAL_ZERO_EFFECTS };
}

function recordedEffects(): MaintainerReviewedApprovalEffects {
  return {
    inserts: 1,
    updates: 0,
    deletes: 0,
    timestampChanges: 0,
    authorityRenewals: 0,
    evaluatorCalls: 0,
    matchEvidenceWrites: 0,
    findingWrites: 0,
    findingObservationWrites: 0,
    riskCalculations: 0,
    suppressionOperations: 0,
    remediationOperations: 0,
    verificationOperations: 0,
    providerCalls: 0,
  };
}

function databaseTimestamp(value: Date): string | null {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return null;
  }
  return value.toISOString();
}

function semanticRecord(row: StoredApprovalRow): Record<string, unknown> {
  return {
    approvalSchemaVersion: row.approvalSchemaVersion,
    advisoryRevisionId: row.advisoryRevisionId,
    familyDigest: row.familyDigest,
    approvalPolicyId: row.approvalPolicyId,
    approvalPolicyVersion: row.approvalPolicyVersion,
    approvalPurpose: row.approvalPurpose,
    sourceClassification: row.sourceClassification,
    authorIdentity: row.authorIdentity,
    reviewerIdentity: row.reviewerIdentity,
    reviewerClassification: row.reviewerClassification,
    contentFingerprint: row.contentFingerprint,
    rangeFingerprint: row.rangeFingerprint,
    packageIdentityKey: row.packageIdentityKey,
    vulnerabilityId: row.vulnerabilityId,
    sourceLicensePolicyId: row.sourceLicensePolicyId,
    sourceLicensePolicyVersion: row.sourceLicensePolicyVersion,
    approvedLicenseClassification: row.approvedLicenseClassification,
    licenseDecisionCanonical: row.licenseDecisionCanonical,
    replayFingerprint: row.replayFingerprint,
  };
}

function projectRow(row: StoredApprovalRow): MaintainerReviewedAdvisoryApprovalProjection | null {
  const createdAt = databaseTimestamp(row.createdAt);
  if (createdAt === null) {
    return null;
  }
  return projectInspectedMaintainerReviewedApproval({
    id: row.id,
    advisoryRevisionId: row.advisoryRevisionId,
    sourceClassification: row.sourceClassification,
    approvalPolicyId: row.approvalPolicyId,
    approvalPolicyVersion: row.approvalPolicyVersion,
    approvalPurpose: row.approvalPurpose,
    reviewerClassification: row.reviewerClassification,
    approvedLicenseClassification: row.approvedLicenseClassification,
    createdAt,
  });
}

function classifyRow(
  row: StoredApprovalRow,
  command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
): MaintainerReviewedApprovalPersistenceResult {
  const classification = classifyStoredMaintainerReviewedApproval(semanticRecord(row), command);
  if (classification === 'malformed') {
    return rejected('malformed_persisted_state');
  }
  if (classification === 'conflict') {
    return { kind: 'immutable_conflict', effects: MAINTAINER_REVIEWED_APPROVAL_ZERO_EFFECTS };
  }
  const projection = projectRow(row);
  if (projection === null) {
    return rejected('malformed_persisted_state');
  }
  return {
    kind: 'already_applied',
    projection,
    effects: MAINTAINER_REVIEWED_APPROVAL_ZERO_EFFECTS,
  };
}

export function createMaintainerReviewedAdvisoryApprovalPersistence(
  client: PrismaClient,
): MaintainerReviewedAdvisoryApprovalPersistencePort {
  if (!isRootPrismaClient(client)) {
    throw new Error(ROOT_CLIENT_REQUIRED);
  }
  return new PrismaMaintainerReviewedAdvisoryApprovalPersistence(client);
}

export class PrismaMaintainerReviewedAdvisoryApprovalPersistence implements MaintainerReviewedAdvisoryApprovalPersistencePort {
  public constructor(private readonly client: PrismaClient) {}

  public async recordMaintainerReviewedAdvisoryApproval(
    command: unknown,
  ): Promise<MaintainerReviewedApprovalPersistenceResult> {
    const parsed = parseMaintainerReviewedAdvisoryApprovalCommand(command);
    if (!parsed.accepted) {
      return rejected(parsed.code);
    }
    return rejected('capability_authority_required');
  }

  public async insertParsedMaintainerReviewedAdvisoryApproval(
    tx: Prisma.TransactionClient,
    command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
  ): Promise<MaintainerReviewedApprovalPersistenceResult> {
    return this.recordInTransaction(tx, command);
  }

  public async inspectMaintainerReviewedAdvisoryApproval(
    query: unknown,
  ): Promise<MaintainerReviewedApprovalInspectionResult> {
    const parsed = parseMaintainerReviewedAdvisoryApprovalInspection(query);
    if (!parsed.accepted) {
      return { kind: 'rejected', code: parsed.code };
    }
    try {
      const row = await this.client.maintainerReviewedAdvisoryApproval.findUnique({
        where: { id: parsed.inspection.approvalId },
        select: {
          id: true,
          advisoryRevisionId: true,
          sourceClassification: true,
          approvalPolicyId: true,
          approvalPolicyVersion: true,
          approvalPurpose: true,
          reviewerClassification: true,
          approvedLicenseClassification: true,
          createdAt: true,
        },
      });
      if (row === null) {
        return { kind: 'not_found' };
      }
      const createdAt = databaseTimestamp(row.createdAt);
      if (createdAt === null) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      const projection = projectInspectedMaintainerReviewedApproval({
        id: row.id,
        advisoryRevisionId: row.advisoryRevisionId,
        sourceClassification: row.sourceClassification,
        approvalPolicyId: row.approvalPolicyId,
        approvalPolicyVersion: row.approvalPolicyVersion,
        approvalPurpose: row.approvalPurpose,
        reviewerClassification: row.reviewerClassification,
        approvedLicenseClassification: row.approvedLicenseClassification,
        createdAt,
      });
      if (projection === null) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      return { kind: 'found', projection };
    } catch (error) {
      return { kind: 'rejected', code: translateMaintainerReviewedApprovalFailure(error) };
    }
  }

  private async recordInTransaction(
    tx: Prisma.TransactionClient,
    command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
  ): Promise<MaintainerReviewedApprovalPersistenceResult> {
    if (
      maintainerReviewedApprovalReplayFingerprint({
        advisoryRevisionId: command.advisoryRevisionId,
        familyDigest: command.expectedAdvisoryFamilyIdentity,
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
        sourceLicensePolicyId: command.sourceLicensePolicyId,
        sourceLicensePolicyVersion: command.sourceLicensePolicyVersion,
        approvedLicenseClassification: command.approvedLicenseClassification,
        licenseDecisionCanonical: command.licenseDecisionCanonical,
      }) !== command.approvalReplayFingerprint
    ) {
      return rejected('invalid_command');
    }
    await tx.$executeRaw`LOCK TABLE "advisory_revision" IN SHARE ROW EXCLUSIVE MODE`;
    const revision = await tx.advisoryRevision.findUnique({
      where: { id: command.advisoryRevisionId },
      select: {
        id: true,
        advisoryFamilyId: true,
        familyDigest: true,
        source: true,
        origin: true,
        trustClassification: true,
        revisionDisposition: true,
        withdrawalClassification: true,
        quarantineClassification: true,
        contentFingerprint: true,
        session14RangeFingerprint: true,
        packageIdentityKey: true,
        authorIdentity: true,
        spdxLicenseId: true,
        sourceLicenseRegistryVersion: true,
        sourceLicensePolicyVersion: true,
        binding: {
          select: {
            id: true,
            vulnerabilityId: true,
            mappingPolicyId: true,
            mappingMethod: true,
            mappingReviewState: true,
            conflictClassification: true,
            bindingSchemaVersion: true,
          },
        },
      },
    });
    if (revision === null) {
      return rejected('revision_missing');
    }
    if (
      revision.origin !== MAINTAINER_REVIEWED_ORIGIN ||
      revision.source !== MAINTAINER_REVIEWED_ORIGIN
    ) {
      return rejected('source_mismatch');
    }
    if (revision.trustClassification !== 'unreviewed') {
      return rejected('revision_mismatch');
    }
    if (revision.familyDigest !== command.expectedAdvisoryFamilyIdentity) {
      return rejected('revision_mismatch');
    }
    if (revision.contentFingerprint !== command.expectedContentFingerprint) {
      return rejected('content_fingerprint_mismatch');
    }
    if (revision.session14RangeFingerprint !== command.expectedRangeFingerprint) {
      return rejected('range_fingerprint_mismatch');
    }
    if (revision.packageIdentityKey !== command.expectedNpmPackageIdentity) {
      return rejected('package_mismatch');
    }
    if (revision.authorIdentity !== command.authorIdentity) {
      return rejected('author_mismatch');
    }
    if (revision.withdrawalClassification === 'withdrawn') {
      return rejected('withdrawn_revision');
    }
    if (
      revision.quarantineClassification === 'quarantined' ||
      revision.revisionDisposition === 'quarantined'
    ) {
      return rejected('quarantined_revision');
    }
    if (
      revision.revisionDisposition !== 'recorded' &&
      revision.revisionDisposition !== 'superseding'
    ) {
      return rejected('revision_mismatch');
    }
    const successor = await tx.advisoryRevision.findFirst({
      where: { supersedesAdvisoryRevisionId: revision.id },
      select: { id: true },
    });
    if (successor !== null) {
      return rejected('superseded_revision');
    }
    if (
      revision.spdxLicenseId !== command.approvedLicenseClassification ||
      revision.sourceLicenseRegistryVersion !== command.sourceLicensePolicyId ||
      revision.sourceLicensePolicyVersion !== String(command.sourceLicensePolicyVersion)
    ) {
      return rejected('license_rejected');
    }
    const binding = revision.binding;
    if (binding === null) {
      return rejected('vulnerability_binding_missing');
    }
    if (
      binding.vulnerabilityId !== command.expectedVulnerabilityId ||
      binding.mappingPolicyId !== VULNERABILITY_MAPPING_POLICY_ID ||
      binding.mappingMethod !== EXACT_MAPPING_METHOD ||
      binding.mappingReviewState !== 'reviewed' ||
      binding.conflictClassification !== 'none' ||
      binding.bindingSchemaVersion !== MAINTAINER_REVIEWED_APPROVAL_PINS.bindingSchema
    ) {
      return rejected('vulnerability_mismatch');
    }
    const existing = await this.findStored(tx, command);
    if (existing.length > 1) {
      return { kind: 'immutable_conflict', effects: MAINTAINER_REVIEWED_APPROVAL_ZERO_EFFECTS };
    }
    const stored = existing[0];
    if (stored !== undefined) {
      return classifyRow(stored, command);
    }
    const created = await tx.maintainerReviewedAdvisoryApproval.create({
      data: {
        approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
        advisoryRevisionId: revision.id,
        advisoryFamilyId: revision.advisoryFamilyId,
        familyDigest: revision.familyDigest,
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
      select: STORED_SELECT,
    });
    const projection = projectRow(created);
    const agreement = classifyStoredMaintainerReviewedApproval(semanticRecord(created), command);
    if (projection === null || agreement !== 'match') {
      throw new ApprovalRowIntegrityFailure();
    }
    return { kind: 'recorded', projection, effects: recordedEffects() };
  }

  private async findStored(
    tx: Prisma.TransactionClient | PrismaClient,
    command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
  ): Promise<StoredApprovalRow[]> {
    return tx.maintainerReviewedAdvisoryApproval.findMany({
      where: {
        OR: [
          { advisoryRevisionId: command.advisoryRevisionId },
          { replayFingerprint: command.approvalReplayFingerprint },
        ],
      },
      select: STORED_SELECT,
      take: 2,
    });
  }
}
