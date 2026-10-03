/**
 * Uncomposed PostgreSQL adapter for durable reviewer-capability issuance
 * and atomic approval consumption. Production startup does not construct it.
 */

import { PrismaClient, type Prisma } from '@prisma/client';
import {
  DURABLE_REVIEWER_CAPABILITY_ISSUANCE_SCHEMA_VERSION,
  DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
  classifyStoredMaintainerReviewedApproval,
  issuanceCommandMatchesStored,
  openDurableConsumptionCommand,
  openDurableIssuanceCommand,
  openDurableLifecycleCommand,
  parseDurableCapabilityInspection,
  projectDurableCapabilityInspection,
  projectInspectedMaintainerReviewedApproval,
  approvalMatchesCapability,
  validateStoredCapabilityRecord,
  type DurableApprovalConsumptionResult,
  type DurableCapabilityInspectionProjection,
  type DurableCapabilityInspectionResult,
  type DurableCapabilityIssuanceResult,
  type DurableCapabilityLifecycleResult,
  type DurableReviewerApprovalCapabilityPersistencePort,
  type DurableReviewerCapabilityEffects,
  type DurableReviewerCapabilityRejectionCode,
  type MaintainerReviewedApprovalPersistenceResult,
  type ParsedMaintainerReviewedAdvisoryApprovalCommand,
  type SealedDurableConsumptionCommand,
  type SealedDurableIssuanceCommand,
  type SealedDurableLifecycleCommand,
  type StoredCapabilityRecord,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';
import { PrismaMaintainerReviewedAdvisoryApprovalPersistence } from './maintainer-reviewed-advisory-approval-persistence.js';
import {
  asDurableRejectionCode,
  isDurableCapabilityUniqueViolation,
  translateDurableCapabilityFailure,
} from './reviewer-capability-persistence-errors.js';

const ROOT_CLIENT_REQUIRED =
  'Durable reviewer-capability persistence requires the root database client.';

class CapabilityIntegrityFailure extends Error {
  public constructor() {
    super('persisted reviewer capability failed closed validation');
    this.name = 'CapabilityIntegrityFailure';
  }
}

const ISSUANCE_SELECT = {
  id: true,
  issuanceSchemaVersion: true,
  capabilityPolicyId: true,
  capabilityPolicyVersion: true,
  approvalPolicyId: true,
  approvalPolicyVersion: true,
  approvalPurpose: true,
  issuerAuthorizationId: true,
  issuerDecisionFingerprint: true,
  approvalClaimFingerprint: true,
  advisoryFamilyIdentity: true,
  advisoryRevisionId: true,
  contentFingerprint: true,
  affectedRangeFingerprint: true,
  npmPackageIdentity: true,
  vulnerabilityId: true,
  sourceLicensePolicyId: true,
  sourceLicensePolicyVersion: true,
  approvedLicenseClassification: true,
  licenseDecisionCanonical: true,
  sourceClassification: true,
  authorIdentity: true,
  reviewerIdentity: true,
  correlationId: true,
  issuedAt: true,
  expiresAt: true,
  observation: {
    select: {
      observationClassification: true,
      approvalId: true,
      lifecycleAuthorizationId: true,
      decisionFingerprint: true,
    },
  },
} as const;

type IssuanceRow = {
  readonly id: string;
  readonly issuanceSchemaVersion: string;
  readonly capabilityPolicyId: string;
  readonly capabilityPolicyVersion: number;
  readonly approvalPolicyId: string;
  readonly approvalPolicyVersion: number;
  readonly approvalPurpose: string;
  readonly issuerAuthorizationId: string;
  readonly issuerDecisionFingerprint: string;
  readonly approvalClaimFingerprint: string;
  readonly advisoryFamilyIdentity: string;
  readonly advisoryRevisionId: string;
  readonly contentFingerprint: string;
  readonly affectedRangeFingerprint: string;
  readonly npmPackageIdentity: string;
  readonly vulnerabilityId: string;
  readonly sourceLicensePolicyId: string;
  readonly sourceLicensePolicyVersion: number;
  readonly approvedLicenseClassification: string;
  readonly licenseDecisionCanonical: string;
  readonly sourceClassification: string;
  readonly authorIdentity: string;
  readonly reviewerIdentity: string;
  readonly correlationId: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly observation: {
    readonly observationClassification: string;
    readonly approvalId: string | null;
    readonly lifecycleAuthorizationId: string | null;
    readonly decisionFingerprint: string | null;
  } | null;
};

function rejected(code: DurableReviewerCapabilityRejectionCode): DurableCapabilityIssuanceResult {
  return { kind: 'rejected', code, effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS };
}

function wrote(inserts: number): DurableReviewerCapabilityEffects {
  return {
    inserts,
    updates: 0,
    deletes: 0,
    timestampChanges: 0,
    capabilityExpiryChanges: 0,
    authorityRenewals: 0,
    evaluatorCalls: 0,
    matchEvidenceWrites: 0,
    findingWrites: 0,
    findingObservationWrites: 0,
    providerCalls: 0,
    riskCalculations: 0,
    suppressionOperations: 0,
    assignmentOperations: 0,
    remediationOperations: 0,
    verificationOperations: 0,
  };
}

function toRecord(row: IssuanceRow): StoredCapabilityRecord | null {
  const classification = row.observation?.observationClassification;
  if (
    classification !== undefined &&
    classification !== 'consumed' &&
    classification !== 'revoked' &&
    classification !== 'cancelled'
  ) {
    return null;
  }
  return {
    id: row.id,
    issuanceSchemaVersion: row.issuanceSchemaVersion,
    capabilityPolicyId: row.capabilityPolicyId,
    capabilityPolicyVersion: row.capabilityPolicyVersion,
    approvalPolicyId: row.approvalPolicyId,
    approvalPolicyVersion: row.approvalPolicyVersion,
    approvalPurpose: row.approvalPurpose,
    issuerAuthorizationId: row.issuerAuthorizationId,
    issuerDecisionFingerprint: row.issuerDecisionFingerprint,
    approvalClaimFingerprint: row.approvalClaimFingerprint,
    advisoryFamilyIdentity: row.advisoryFamilyIdentity,
    advisoryRevisionId: row.advisoryRevisionId,
    contentFingerprint: row.contentFingerprint,
    affectedRangeFingerprint: row.affectedRangeFingerprint,
    npmPackageIdentity: row.npmPackageIdentity,
    vulnerabilityId: row.vulnerabilityId,
    sourceLicensePolicyId: row.sourceLicensePolicyId,
    sourceLicensePolicyVersion: row.sourceLicensePolicyVersion,
    approvedLicenseClassification: row.approvedLicenseClassification,
    licenseDecisionCanonical: row.licenseDecisionCanonical,
    sourceClassification: row.sourceClassification,
    authorIdentity: row.authorIdentity,
    reviewerIdentity: row.reviewerIdentity,
    correlationId: row.correlationId,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
    observation:
      row.observation === null || classification === undefined
        ? null
        : {
            classification,
            approvalId: row.observation.approvalId,
            lifecycleAuthorizationId: row.observation.lifecycleAuthorizationId,
            decisionFingerprint: row.observation.decisionFingerprint,
          },
  };
}

export function createDurableReviewerApprovalCapabilityPersistence(
  client: PrismaClient,
): DurableReviewerApprovalCapabilityPersistencePort {
  if (!isRootPrismaClient(client)) {
    throw new Error(ROOT_CLIENT_REQUIRED);
  }
  return new PrismaDurableReviewerApprovalCapabilityPersistence(client);
}

class PrismaDurableReviewerApprovalCapabilityPersistence implements DurableReviewerApprovalCapabilityPersistencePort {
  private readonly approvals: PrismaMaintainerReviewedAdvisoryApprovalPersistence;

  public constructor(private readonly client: PrismaClient) {
    this.approvals = new PrismaMaintainerReviewedAdvisoryApprovalPersistence(client);
  }

  public async issueDurableReviewerApprovalCapability(
    command: unknown,
  ): Promise<DurableCapabilityIssuanceResult> {
    const parsed = openDurableIssuanceCommand(command);
    if (!parsed.accepted) {
      return rejected(parsed.code);
    }
    try {
      return await this.client.$transaction((tx) => this.insertIssuance(tx, parsed.command));
    } catch (error) {
      if (error instanceof CapabilityIntegrityFailure) {
        return rejected('malformed_persisted_state');
      }
      if (isDurableCapabilityUniqueViolation(error)) {
        return this.reloadIssuance(parsed.command);
      }
      return rejected(translateDurableCapabilityFailure(error));
    }
  }

  public async inspectDurableReviewerApprovalCapability(
    query: unknown,
  ): Promise<DurableCapabilityInspectionResult> {
    const parsed = parseDurableCapabilityInspection(query);
    if (!parsed.accepted) {
      return { kind: 'rejected', code: parsed.code };
    }
    try {
      const row = await this.client.reviewerCapabilityIssuance.findUnique({
        where: { id: parsed.inspection.capabilityIssuanceId },
        select: ISSUANCE_SELECT,
      });
      if (row === null) {
        return { kind: 'not_found' };
      }
      const projected = await this.projectRow(this.client, row);
      if (projected === null) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      return { kind: 'found', projection: projected.projection };
    } catch (error) {
      return { kind: 'rejected', code: translateDurableCapabilityFailure(error) };
    }
  }

  public async persistMaintainerReviewedAdvisoryApprovalWithCapability(
    command: unknown,
  ): Promise<DurableApprovalConsumptionResult> {
    const parsed = openDurableConsumptionCommand(command);
    if (!parsed.accepted) {
      return {
        kind: 'rejected',
        code: parsed.code,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    try {
      return await this.client.$transaction((tx) => this.consume(tx, parsed.command));
    } catch (error) {
      if (
        error instanceof CapabilityIntegrityFailure ||
        (error instanceof Error && error.name === 'ApprovalRowIntegrityFailure')
      ) {
        return {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        };
      }
      if (isDurableCapabilityUniqueViolation(error)) {
        return this.reloadApproval(parsed.command.approval, parsed.command.capabilityIssuanceId);
      }
      return {
        kind: 'rejected',
        code: translateDurableCapabilityFailure(error),
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
  }

  public async revokeDurableReviewerApprovalCapability(
    command: unknown,
  ): Promise<DurableCapabilityLifecycleResult> {
    return this.applyLifecycle(command, 'revoke_issued_reviewer_approval_capability');
  }

  public async cancelDurableReviewerApprovalCapability(
    command: unknown,
  ): Promise<DurableCapabilityLifecycleResult> {
    return this.applyLifecycle(command, 'cancel_issued_reviewer_approval_capability');
  }

  private async insertIssuance(
    tx: Prisma.TransactionClient,
    command: SealedDurableIssuanceCommand,
  ): Promise<DurableCapabilityIssuanceResult> {
    const request = command.request;
    const created = await tx.reviewerCapabilityIssuance.create({
      data: {
        issuanceSchemaVersion: DURABLE_REVIEWER_CAPABILITY_ISSUANCE_SCHEMA_VERSION,
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
      select: ISSUANCE_SELECT,
    });
    const projected = await this.projectRow(tx, created);
    if (projected === null || !issuanceCommandMatchesStored(command, projected.record)) {
      throw new CapabilityIntegrityFailure();
    }
    return { kind: 'issued', projection: projected.projection, effects: wrote(1) };
  }

  private async reloadIssuance(
    command: SealedDurableIssuanceCommand,
  ): Promise<DurableCapabilityIssuanceResult> {
    const rows = await this.client.reviewerCapabilityIssuance.findMany({
      where: {
        OR: [
          { approvalClaimFingerprint: command.approvalClaimFingerprint },
          { issuerAuthorizationId: command.issuerAuthorizationId },
        ],
      },
      select: ISSUANCE_SELECT,
      take: 2,
    });
    if (rows.length !== 1) {
      return rows.length > 1
        ? { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS }
        : rejected('unique_violation');
    }
    const row = rows[0];
    if (row === undefined) {
      return rejected('unique_violation');
    }
    const projected = await this.projectRow(this.client, row);
    if (projected === null) {
      return rejected('malformed_persisted_state');
    }
    if (!issuanceCommandMatchesStored(command, projected.record)) {
      return { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS };
    }
    return {
      kind: 'already_issued',
      projection: projected.projection,
      effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
    };
  }

  private async consume(
    tx: Prisma.TransactionClient,
    command: SealedDurableConsumptionCommand,
  ): Promise<DurableApprovalConsumptionResult> {
    // Exact approval replay is classified before the capability lock.
    // Stored approval evidence stays authoritative: this path does not insert
    // a second approval, a second consumption, or an extended expiry.
    const prior = await this.classifyApproval(tx, command.approval);
    if (prior.kind !== 'absent') {
      return prior.result;
    }
    const locked = await tx.$queryRaw<Array<{ id: string }>>`
      SELECT "id"
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${command.capabilityIssuanceId}::uuid
      FOR UPDATE
    `;
    if (locked.length !== 1) {
      return {
        kind: 'rejected',
        code: 'capability_missing',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const row = await tx.reviewerCapabilityIssuance.findUnique({
      where: { id: command.capabilityIssuanceId },
      select: ISSUANCE_SELECT,
    });
    const record = row === null ? null : toRecord(row);
    if (record === null || validateStoredCapabilityRecord(record) !== null) {
      return {
        kind: 'rejected',
        code: 'capability_malformed',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const mismatch = approvalMatchesCapability(command.approval, record);
    if (mismatch !== null) {
      return {
        kind: 'rejected',
        code: mismatch,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const raced = await this.classifyApproval(tx, command.approval);
    if (raced.kind !== 'absent') {
      return raced.result;
    }
    const gate = await this.lifecycleGate(tx, record);
    if (gate !== null) {
      return { kind: 'rejected', code: gate, effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS };
    }
    const inserted = await this.approvals.insertParsedMaintainerReviewedAdvisoryApproval(
      tx,
      command.approval,
    );
    if (inserted.kind !== 'recorded') {
      return this.mapApproval(inserted);
    }
    await tx.reviewerCapabilityLifecycleObservation.create({
      data: {
        capabilityIssuanceId: record.id,
        observationClassification: 'consumed',
        approvalId: inserted.projection.approvalId,
      },
    });
    const stored = await tx.reviewerCapabilityIssuance.findUnique({
      where: { id: record.id },
      select: ISSUANCE_SELECT,
    });
    const projected = stored === null ? null : await this.projectRow(tx, stored);
    if (projected === null || projected.projection.lifecycleClassification !== 'consumed') {
      throw new CapabilityIntegrityFailure();
    }
    return {
      kind: 'recorded',
      projection: inserted.projection,
      capability: projected.projection,
      effects: wrote(2),
    };
  }

  private async applyLifecycle(
    command: unknown,
    purpose: SealedDurableLifecycleCommand['lifecyclePurpose'],
  ): Promise<DurableCapabilityLifecycleResult> {
    const parsed = openDurableLifecycleCommand(command);
    if (!parsed.accepted) {
      return {
        kind: 'rejected',
        code: parsed.code,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    if (parsed.command.lifecyclePurpose !== purpose) {
      return {
        kind: 'rejected',
        code: 'invalid_purpose',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    try {
      return await this.client.$transaction((tx) => this.observe(tx, parsed.command));
    } catch (error) {
      if (error instanceof CapabilityIntegrityFailure) {
        return {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        };
      }
      if (isDurableCapabilityUniqueViolation(error)) {
        return this.reloadLifecycle(parsed.command);
      }
      return {
        kind: 'rejected',
        code: translateDurableCapabilityFailure(error),
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
  }

  private async observe(
    tx: Prisma.TransactionClient,
    command: SealedDurableLifecycleCommand,
  ): Promise<DurableCapabilityLifecycleResult> {
    const locked = await tx.$queryRaw<Array<{ id: string }>>`
      SELECT "id"
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${command.capabilityIssuanceId}::uuid
      FOR UPDATE
    `;
    if (locked.length !== 1) {
      return {
        kind: 'rejected',
        code: 'capability_missing',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const row = await tx.reviewerCapabilityIssuance.findUnique({
      where: { id: command.capabilityIssuanceId },
      select: ISSUANCE_SELECT,
    });
    const record = row === null ? null : toRecord(row);
    if (record === null || validateStoredCapabilityRecord(record) !== null) {
      return {
        kind: 'rejected',
        code: 'capability_malformed',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    if (record.issuerDecisionFingerprint !== command.decisionFingerprint) {
      return {
        kind: 'rejected',
        code: 'authority_wrong_target',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const existing = this.terminalCode(record, command);
    if (existing === 'already_recorded') {
      const projected = await this.projectRow(tx, row as IssuanceRow);
      if (projected === null) {
        return {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        };
      }
      return {
        kind: 'already_recorded',
        projection: projected.projection,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    if (existing !== null) {
      return {
        kind: 'rejected',
        code: existing,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const gate = await this.lifecycleGate(tx, record);
    if (gate !== null) {
      return { kind: 'rejected', code: gate, effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS };
    }
    const classification =
      command.lifecyclePurpose === 'revoke_issued_reviewer_approval_capability'
        ? 'revoked'
        : 'cancelled';
    await tx.reviewerCapabilityLifecycleObservation.create({
      data: {
        capabilityIssuanceId: record.id,
        observationClassification: classification,
        lifecycleAuthorizationId: command.lifecycleAuthorizationId,
        decisionFingerprint: command.decisionFingerprint,
      },
    });
    const stored = await tx.reviewerCapabilityIssuance.findUnique({
      where: { id: record.id },
      select: ISSUANCE_SELECT,
    });
    const projected = stored === null ? null : await this.projectRow(tx, stored);
    if (projected === null || projected.projection.lifecycleClassification !== classification) {
      throw new CapabilityIntegrityFailure();
    }
    return { kind: 'recorded', projection: projected.projection, effects: wrote(1) };
  }

  private terminalCode(
    record: StoredCapabilityRecord,
    command: SealedDurableLifecycleCommand,
  ): DurableReviewerCapabilityRejectionCode | 'already_recorded' | null {
    const observation = record.observation;
    if (observation === null) {
      return null;
    }
    const expected =
      command.lifecyclePurpose === 'revoke_issued_reviewer_approval_capability'
        ? 'revoked'
        : 'cancelled';
    if (
      observation.classification === expected &&
      observation.lifecycleAuthorizationId === command.lifecycleAuthorizationId &&
      observation.decisionFingerprint === command.decisionFingerprint
    ) {
      return 'already_recorded';
    }
    if (observation.classification === 'consumed') {
      return 'authority_consumed';
    }
    if (observation.classification === 'revoked') {
      return 'authority_revoked';
    }
    if (observation.classification === 'cancelled') {
      return 'authority_cancelled';
    }
    return 'capability_malformed';
  }

  private async lifecycleGate(
    tx: Prisma.TransactionClient,
    record: StoredCapabilityRecord,
  ): Promise<DurableReviewerCapabilityRejectionCode | null> {
    if (record.observation?.classification === 'consumed') {
      return 'authority_consumed';
    }
    if (record.observation?.classification === 'revoked') {
      return 'authority_revoked';
    }
    if (record.observation?.classification === 'cancelled') {
      return 'authority_cancelled';
    }
    const clock = await tx.$queryRaw<Array<{ expired: boolean }>>`
      SELECT patchpilot_reviewer_capability_is_expired("expires_at", clock_timestamp()) AS expired
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${record.id}::uuid
    `;
    const expired = clock[0]?.expired;
    if (expired !== true && expired !== false) {
      return 'malformed_persisted_state';
    }
    return expired ? 'authority_expired' : null;
  }

  private async classifyApproval(
    tx: Prisma.TransactionClient,
    command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
  ): Promise<
    | { readonly kind: 'absent' }
    | { readonly kind: 'present'; readonly result: DurableApprovalConsumptionResult }
  > {
    const rows = await tx.maintainerReviewedAdvisoryApproval.findMany({
      where: {
        OR: [
          { advisoryRevisionId: command.advisoryRevisionId },
          { replayFingerprint: command.approvalReplayFingerprint },
        ],
      },
      select: {
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
      },
      take: 2,
    });
    if (rows.length > 1) {
      return {
        kind: 'present',
        result: { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS },
      };
    }
    const row = rows[0];
    if (row === undefined) {
      return { kind: 'absent' };
    }
    const classification = classifyStoredMaintainerReviewedApproval(
      {
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
      },
      command,
    );
    if (classification === 'malformed') {
      return {
        kind: 'present',
        result: {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        },
      };
    }
    if (classification === 'conflict') {
      return {
        kind: 'present',
        result: { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS },
      };
    }
    const createdAt = timestamp(row.createdAt);
    const projection =
      createdAt === null
        ? null
        : projectInspectedMaintainerReviewedApproval({
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
      return {
        kind: 'present',
        result: {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        },
      };
    }
    return {
      kind: 'present',
      result: {
        kind: 'already_applied',
        projection,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      },
    };
  }

  private mapApproval(
    inserted: Exclude<MaintainerReviewedApprovalPersistenceResult, { kind: 'recorded' }>,
  ): DurableApprovalConsumptionResult {
    if (inserted.kind === 'already_applied') {
      return {
        kind: 'already_applied',
        projection: inserted.projection,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    if (inserted.kind === 'immutable_conflict') {
      return { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS };
    }
    return {
      kind: 'rejected',
      code: asDurableRejectionCode(inserted.code),
      effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
    };
  }

  private async reloadApproval(
    command: ParsedMaintainerReviewedAdvisoryApprovalCommand,
    capabilityIssuanceId: string,
  ): Promise<DurableApprovalConsumptionResult> {
    const classified = await this.classifyApproval(this.client, command);
    if (classified.kind !== 'absent') {
      return classified.result;
    }
    const row = await this.client.reviewerCapabilityIssuance.findUnique({
      where: { id: capabilityIssuanceId },
      select: ISSUANCE_SELECT,
    });
    const record = row === null ? null : toRecord(row);
    if (record === null || validateStoredCapabilityRecord(record) !== null) {
      return {
        kind: 'rejected',
        code: record === null ? 'unique_violation' : 'malformed_persisted_state',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const classification = record.observation?.classification;
    if (
      classification === 'consumed' ||
      classification === 'revoked' ||
      classification === 'cancelled'
    ) {
      const code =
        classification === 'consumed'
          ? 'authority_consumed'
          : classification === 'revoked'
            ? 'authority_revoked'
            : 'authority_cancelled';
      return {
        kind: 'rejected',
        code,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    return {
      kind: 'rejected',
      code: 'unique_violation',
      effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
    };
  }

  private async reloadLifecycle(
    command: SealedDurableLifecycleCommand,
  ): Promise<DurableCapabilityLifecycleResult> {
    const row = await this.client.reviewerCapabilityIssuance.findUnique({
      where: { id: command.capabilityIssuanceId },
      select: ISSUANCE_SELECT,
    });
    const record = row === null ? null : toRecord(row);
    if (record === null) {
      return {
        kind: 'rejected',
        code: 'unique_violation',
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    const terminal = this.terminalCode(record, command);
    if (terminal === 'already_recorded') {
      const projected = await this.projectRow(this.client, row as IssuanceRow);
      if (projected === null) {
        return {
          kind: 'rejected',
          code: 'malformed_persisted_state',
          effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
        };
      }
      return {
        kind: 'already_recorded',
        projection: projected.projection,
        effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
      };
    }
    return {
      kind: 'rejected',
      code: terminal ?? 'unique_violation',
      effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
    };
  }

  private async projectRow(
    tx: Prisma.TransactionClient | PrismaClient,
    row: IssuanceRow,
  ): Promise<{
    readonly record: StoredCapabilityRecord;
    readonly projection: DurableCapabilityInspectionProjection;
  } | null> {
    const record = toRecord(row);
    if (record === null || validateStoredCapabilityRecord(record) !== null) {
      return null;
    }
    const clock = await tx.$queryRaw<Array<{ expired: boolean }>>`
      SELECT patchpilot_reviewer_capability_is_expired("expires_at", clock_timestamp()) AS expired
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${record.id}::uuid
    `;
    const expired = clock[0]?.expired;
    if (expired !== true && expired !== false) {
      return null;
    }
    const projection = projectDurableCapabilityInspection(record, expired);
    if (projection === null || projection.reusableAuthority !== false) {
      return null;
    }
    return { record, projection };
  }
}

function timestamp(value: Date): string | null {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return null;
  }
  return value.toISOString();
}
