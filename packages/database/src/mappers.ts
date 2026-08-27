import type {
  AssetOwnerRecord,
  AssetRecord,
  AuditEventRecord,
  AuditPayloadJson,
  EnvironmentRecord,
  EvidenceMetadataJson,
  FindingObservationEvidenceJson,
  FindingRecord,
  IdempotencyRecordRecord,
  IdempotencyResponseJson,
  LocalCredentialRecord,
  MembershipRecord,
  OrganizationRecord,
  OutboxEventRecord,
  OutboxPayloadJson,
  RemediationTaskRecord,
  RiskPolicyDefinitionJson,
  RiskPolicyRecord,
  SbomRecord,
  SessionRecord,
  TeamMembershipRecord,
  TeamRecord,
  UserRecord,
} from '@patchpilot/domain';

import { readJsonObject } from './guards.js';

type DateTimeFields = {
  createdAt: Date;
};

export function mapOrganization(row: {
  id: string;
  slug: string;
  name: string;
  status: OrganizationRecord['status'];
  version: number;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}): OrganizationRecord {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    status: row.status,
    version: row.version,
    archivedAt: row.archivedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function mapUser(row: {
  id: string;
  email: string;
  displayName: string;
  status: UserRecord['status'];
  version: number;
  disabledAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}): UserRecord {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    status: row.status,
    version: row.version,
    disabledAt: row.disabledAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function mapMembership(row: {
  id: string;
  organizationId: string;
  userId: string;
  role: MembershipRecord['role'];
  status: MembershipRecord['status'];
  invitedAt: Date | null;
  joinedAt: Date | null;
  revokedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): MembershipRecord {
  return { ...row };
}

export function mapLocalCredential(row: {
  id: string;
  userId: string;
  passwordHash: string;
  passwordRevision: number;
  algorithm: LocalCredentialRecord['algorithm'];
  createdAt: Date;
  updatedAt: Date;
}): LocalCredentialRecord {
  return { ...row };
}

export function mapSession(row: {
  id: string;
  userId: string;
  tokenHash: string;
  csrfTokenHash: string;
  activeOrganizationId: string | null;
  authenticationMethod: SessionRecord['authenticationMethod'];
  passwordRevision: number;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  revokedAt: Date | null;
  revokeReason: string | null;
  userAgent: string | null;
}): SessionRecord {
  return { ...row };
}

export function mapTeam(row: {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  status: TeamRecord['status'];
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): TeamRecord {
  return { ...row };
}

export function mapTeamMembership(row: {
  id: string;
  organizationId: string;
  teamId: string;
  userId: string;
  createdAt: Date;
}): TeamMembershipRecord {
  return { ...row };
}

export function mapEnvironment(row: {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  sensitivityClass: EnvironmentRecord['sensitivityClass'];
  status: EnvironmentRecord['status'];
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): EnvironmentRecord {
  return { ...row };
}

export function mapAsset(row: {
  id: string;
  organizationId: string;
  name: string;
  description: string | null;
  assetType: AssetRecord['assetType'];
  lifecycleStatus: AssetRecord['lifecycleStatus'];
  environmentId: string | null;
  owningTeamId: string | null;
  businessCriticality: AssetRecord['businessCriticality'];
  internetExposure: AssetRecord['internetExposure'];
  dataClassification: AssetRecord['dataClassification'];
  repositoryUrl: string | null;
  deploymentContext: string | null;
  lastObservedAt: Date | null;
  lastSuccessfulSbomIngestionId: string | null;
  lastSuccessfulSbomIngestionAt: Date | null;
  archivedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): AssetRecord {
  return { ...row };
}

export function mapAssetOwner(row: {
  id: string;
  organizationId: string;
  assetId: string;
  userId: string | null;
  teamId: string | null;
  role: AssetOwnerRecord['role'];
  createdAt: Date;
  updatedAt: Date;
}): AssetOwnerRecord {
  return { ...row };
}

export function mapSbom(row: {
  id: string;
  organizationId: string;
  assetId: string;
  objectKey: string;
  sha256: string;
  byteLength: number;
  declaredContentType: string;
  specificationType: SbomRecord['specificationType'];
  specificationVersion: string | null;
  source: SbomRecord['source'];
  originalFilename: string | null;
  uploadedByMembershipId: string | null;
  capturedAt: Date | null;
  receivedAt: Date;
  parserVersionLastSucceeded: string | null;
  createdAt: Date;
}): SbomRecord {
  return {
    ...row,
    specificationVersion: asSbomSpecificationVersion(row.specificationVersion),
  };
}

function asSbomSpecificationVersion(value: string | null): SbomRecord['specificationVersion'] {
  if (value === null) {
    return null;
  }

  if (value === '1.4' || value === '1.5' || value === '1.6') {
    return value;
  }

  throw new Error('SBOM specificationVersion must be an allowlisted CycloneDX version.');
}

export function mapFinding(row: {
  id: string;
  organizationId: string;
  assetId: string;
  vulnerabilityId: string;
  componentId: string;
  componentOccurrenceId: string | null;
  state: FindingRecord['state'];
  firstObservedAt: Date;
  lastObservedAt: Date;
  resolvedAt: Date | null;
  reopenedAt: Date | null;
  assignedMembershipId: string | null;
  assignedTeamId: string | null;
  dueAt: Date | null;
  currentRiskCalculationId: string | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): FindingRecord {
  return { ...row };
}

export function mapRiskPolicy(row: {
  id: string;
  organizationId: string | null;
  scope: RiskPolicyRecord['scope'];
  policyKey: string;
  name: string;
  version: number;
  status: RiskPolicyRecord['status'];
  policySchemaVersion: number;
  definition: unknown;
  publishedAt: Date | null;
  retiredAt: Date | null;
  createdByMembershipId: string | null;
  createdAt: Date;
}): RiskPolicyRecord {
  return {
    ...row,
    definition: readJsonObject<RiskPolicyDefinitionJson>(row.definition as never, 'definition'),
  };
}

export function mapRemediationTask(row: {
  id: string;
  organizationId: string;
  findingId: string;
  status: RemediationTaskRecord['status'];
  title: string;
  description: string | null;
  assignedMembershipId: string | null;
  assignedTeamId: string | null;
  dueAt: Date | null;
  startedAt: Date | null;
  submittedAt: Date | null;
  verificationRequestedAt: Date | null;
  completedAt: Date | null;
  cancelledAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): RemediationTaskRecord {
  return { ...row };
}

export function mapAuditEvent(row: {
  id: string;
  organizationId: string | null;
  actorUserId: string | null;
  actorMembershipId: string | null;
  actorType: AuditEventRecord['actorType'];
  action: string;
  subjectType: string;
  subjectId: string;
  occurredAt: Date;
  requestId: string | null;
  correlationId: string;
  sourceIp: string | null;
  userAgent: string | null;
  payload: unknown;
  schemaVersion: number;
  retentionCategory: AuditEventRecord['retentionCategory'];
}): AuditEventRecord {
  return {
    ...row,
    payload: readJsonObject<AuditPayloadJson>(row.payload as never, 'payload'),
  };
}

export function mapOutboxEvent(row: {
  id: string;
  organizationId: string | null;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  eventSchemaVersion: number;
  payload: unknown;
  dedupeKey: string;
  occurredAt: Date;
  availableAt: Date;
  claimedAt: Date | null;
  leaseExpiresAt: Date | null;
  processedAt: Date | null;
  attemptCount: number;
  lastFailureCategory: string | null;
  lastFailureCode: string | null;
  status: OutboxEventRecord['status'];
  createdAt: Date;
}): OutboxEventRecord {
  return {
    ...row,
    payload: readJsonObject<OutboxPayloadJson>(row.payload as never, 'payload'),
  };
}

export function mapIdempotencyRecord(row: {
  id: string;
  organizationId: string;
  scope: string;
  keyHash: string;
  requestFingerprint: string;
  status: IdempotencyRecordRecord['status'];
  responseStatus: number | null;
  response: unknown;
  createdAt: Date;
  expiresAt: Date;
  completedAt: Date | null;
}): IdempotencyRecordRecord {
  return {
    ...row,
    response:
      row.response === null
        ? null
        : readJsonObject<IdempotencyResponseJson>(row.response as never, 'response'),
  };
}

export type { DateTimeFields, EvidenceMetadataJson, FindingObservationEvidenceJson };
