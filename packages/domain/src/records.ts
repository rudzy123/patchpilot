import type {
  AssetDataClassification,
  AssetLifecycleStatus,
  AssetOwnerRole,
  AssetType,
  AuditActorType,
  AuditRetentionCategory,
  BackgroundJobStatus,
  BusinessCriticality,
  ComponentIdentityState,
  DependencyRelationshipType,
  EnvironmentSensitivityClass,
  EnvironmentStatus,
  EvidenceKind,
  ExternalCredentialStatus,
  FindingObservationResult,
  FindingState,
  GraphCompleteness,
  IdempotencyRecordStatus,
  IntegrationProviderKey,
  IntegrationState,
  InternetExposure,
  MembershipRole,
  MembershipStatus,
  OrganizationStatus,
  OutboxEventStatus,
  PasswordHashAlgorithm,
  RemediationTaskStatus,
  RepositoryConnectionStatus,
  RepositoryProvider,
  RiskAcceptanceStatus,
  RiskCalculationReason,
  RiskPolicyStatus,
  SbomIngestionStage,
  SbomIngestionState,
  SbomSource,
  SbomSpecificationType,
  SbomSpecificationVersion,
  SecretStorageProvider,
  SessionAuthenticationMethod,
  TeamStatus,
  UserStatus,
  VulnerabilitySource,
  VulnerabilityStatus,
  RiskPolicyScope,
} from './lifecycle.js';
import type {
  AuditPayloadJson,
  EvidenceMetadataJson,
  FindingObservationEvidenceJson,
  IdempotencyResponseJson,
  IntegrationConfigJson,
  OutboxPayloadJson,
  RiskCalculationFactorsJson,
  RiskCalculationResultJson,
  RiskPolicyDefinitionJson,
  VulnerabilityNormalizedJson,
} from './json-documents.js';
import type { SafeFailureCategory, SafeFailureCode } from './sbom/failures.js';
import type { ComponentVersion } from './sbom/version.js';

export type OrganizationRecord = {
  id: string;
  slug: string;
  name: string;
  status: OrganizationStatus;
  version: number;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type UserRecord = {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
  version: number;
  disabledAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type MembershipRecord = {
  id: string;
  organizationId: string;
  userId: string;
  role: MembershipRole;
  status: MembershipStatus;
  invitedAt: Date | null;
  joinedAt: Date | null;
  revokedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type LocalCredentialRecord = {
  id: string;
  userId: string;
  passwordHash: string;
  passwordRevision: number;
  algorithm: PasswordHashAlgorithm;
  createdAt: Date;
  updatedAt: Date;
};

export type SessionRecord = {
  id: string;
  userId: string;
  tokenHash: string;
  csrfTokenHash: string;
  activeOrganizationId: string | null;
  authenticationMethod: SessionAuthenticationMethod;
  passwordRevision: number;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  revokedAt: Date | null;
  revokeReason: string | null;
  userAgent: string | null;
};

export type TeamRecord = {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  status: TeamStatus;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type TeamMembershipRecord = {
  id: string;
  organizationId: string;
  teamId: string;
  userId: string;
  createdAt: Date;
};

export type EnvironmentRecord = {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  sensitivityClass: EnvironmentSensitivityClass;
  status: EnvironmentStatus;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type AssetRecord = {
  id: string;
  organizationId: string;
  name: string;
  description: string | null;
  assetType: AssetType;
  lifecycleStatus: AssetLifecycleStatus;
  environmentId: string | null;
  owningTeamId: string | null;
  businessCriticality: BusinessCriticality;
  internetExposure: InternetExposure;
  dataClassification: AssetDataClassification;
  repositoryUrl: string | null;
  deploymentContext: string | null;
  lastObservedAt: Date | null;
  lastSuccessfulSbomIngestionId: string | null;
  lastSuccessfulSbomIngestionAt: Date | null;
  archivedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type AssetOwnerRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  userId: string | null;
  teamId: string | null;
  role: AssetOwnerRole;
  createdAt: Date;
  updatedAt: Date;
};

export type AssetTagRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  tag: string;
  createdAt: Date;
};

export type AssetExternalIdentifierRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  namespace: string;
  identifier: string;
  createdAt: Date;
};

export type RepositoryConnectionRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  provider: RepositoryProvider;
  externalRepositoryId: string | null;
  displayUrl: string | null;
  defaultBranch: string | null;
  status: RepositoryConnectionStatus;
  integrationId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type SbomRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  objectKey: string;
  sha256: string;
  byteLength: number;
  declaredContentType: string;
  specificationType: SbomSpecificationType;
  specificationVersion: SbomSpecificationVersion | null;
  source: SbomSource;
  originalFilename: string | null;
  uploadedByMembershipId: string | null;
  capturedAt: Date | null;
  receivedAt: Date;
  parserVersionLastSucceeded: string | null;
  createdAt: Date;
};

export type SbomIngestionRecord = {
  id: string;
  organizationId: string;
  sbomId: string;
  assetId: string;
  state: SbomIngestionState;
  stage: SbomIngestionStage | null;
  attemptNumber: number;
  parserVersion: string;
  normalizationVersion: string | null;
  idempotencyKey: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  graphCompleteness: GraphCompleteness | null;
  componentCount: number | null;
  dependencyEdgeCount: number | null;
  warningCount: number | null;
  failureCategory: SafeFailureCategory | null;
  failureCode: SafeFailureCode | null;
  quarantineReason: string | null;
  leaseExpiresAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type ComponentRecord = {
  id: string;
  organizationId: string;
  identityKey: string;
  purl: string | null;
  ecosystem: string;
  namespace: string | null;
  name: string;
  identityState: ComponentIdentityState;
  createdAt: Date;
};

export type ComponentOccurrenceRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  sbomId: string;
  sbomIngestionId: string;
  componentId: string;
  bomRef: string | null;
  version: ComponentVersion;
  versionedPurl: string | null;
  isDirect: boolean | null;
  createdAt: Date;
};

export type DependencyRelationshipRecord = {
  id: string;
  organizationId: string;
  sbomId: string;
  sbomIngestionId: string;
  fromOccurrenceId: string;
  toOccurrenceId: string;
  relationshipType: DependencyRelationshipType;
  createdAt: Date;
};

export type VulnerabilityRecord = {
  id: string;
  osvId: string;
  cveId: string | null;
  status: VulnerabilityStatus;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  withdrawnAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type VulnerabilityAliasRecord = {
  id: string;
  vulnerabilityId: string;
  alias: string;
  createdAt: Date;
};

export type VulnerabilitySourceRecordRecord = {
  id: string;
  vulnerabilityId: string;
  source: VulnerabilitySource;
  sourceIdentity: string;
  sourceUrl: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  retrievedAt: Date;
  payloadSha256: string;
  normalizationVersion: string;
  withdrawnAt: Date | null;
  rawObjectKey: string | null;
  normalized: VulnerabilityNormalizedJson;
  supersedesRecordId: string | null;
  createdAt: Date;
};

export type FindingRecord = {
  id: string;
  organizationId: string;
  assetId: string;
  vulnerabilityId: string;
  componentId: string;
  componentOccurrenceId: string | null;
  state: FindingState;
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
};

export type FindingObservationRecord = {
  id: string;
  organizationId: string;
  findingId: string;
  sbomId: string;
  sbomIngestionId: string;
  occurrenceId: string | null;
  result: FindingObservationResult;
  method: string;
  observedAt: Date;
  evidence: FindingObservationEvidenceJson;
  createdAt: Date;
};

export type RiskPolicyRecord = {
  id: string;
  organizationId: string | null;
  scope: RiskPolicyScope;
  policyKey: string;
  name: string;
  version: number;
  status: RiskPolicyStatus;
  policySchemaVersion: number;
  definition: RiskPolicyDefinitionJson;
  publishedAt: Date | null;
  retiredAt: Date | null;
  createdByMembershipId: string | null;
  createdAt: Date;
};

export type RiskCalculationRecord = {
  id: string;
  organizationId: string;
  findingId: string;
  riskPolicyId: string;
  policyVersion: number;
  policyDefinitionSha256: string;
  calculatedAt: Date;
  factors: RiskCalculationFactorsJson;
  result: RiskCalculationResultJson;
  calculationEngineVersion: string;
  calculationReason: RiskCalculationReason;
  inputFingerprint: string;
  sbomIngestionId: string | null;
  createdAt: Date;
};

export type RemediationTaskRecord = {
  id: string;
  organizationId: string;
  findingId: string;
  status: RemediationTaskStatus;
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
};

export type RiskAcceptanceRecord = {
  id: string;
  organizationId: string;
  findingId: string;
  status: RiskAcceptanceStatus;
  requestedByMembershipId: string;
  approvedByMembershipId: string | null;
  reason: string;
  compensatingControls: string | null;
  startsAt: Date;
  expiresAt: Date;
  reviewAt: Date;
  approvedAt: Date | null;
  revokedAt: Date | null;
  revocationReason: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type EvidenceRecord = {
  id: string;
  organizationId: string;
  kind: EvidenceKind;
  findingId: string | null;
  sbomId: string | null;
  assetId: string | null;
  objectKey: string | null;
  sha256: string | null;
  byteLength: number | null;
  contentType: string | null;
  description: string | null;
  submittedByMembershipId: string | null;
  metadata: EvidenceMetadataJson;
  createdAt: Date;
};

export type AuditEventRecord = {
  id: string;
  organizationId: string | null;
  actorUserId: string | null;
  actorMembershipId: string | null;
  actorType: AuditActorType;
  action: string;
  subjectType: string;
  subjectId: string;
  occurredAt: Date;
  requestId: string | null;
  correlationId: string;
  sourceIp: string | null;
  userAgent: string | null;
  payload: AuditPayloadJson;
  schemaVersion: number;
  retentionCategory: AuditRetentionCategory;
};

export type IntegrationProviderRecord = {
  id: string;
  providerKey: IntegrationProviderKey;
  displayName: string;
  createdAt: Date;
};

export type IntelligenceSourceRecord = {
  id: string;
  providerKey: IntegrationProviderKey;
  state: IntegrationState;
  config: IntegrationConfigJson;
  lastSuccessfulSyncAt: Date | null;
  lastFailureAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type IntegrationRecord = {
  id: string;
  organizationId: string;
  providerId: string;
  displayName: string;
  state: IntegrationState;
  config: IntegrationConfigJson;
  externalAccountId: string | null;
  lastSuccessfulSyncAt: Date | null;
  lastFailureAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type ExternalCredentialRecord = {
  id: string;
  organizationId: string;
  integrationId: string;
  storageProvider: SecretStorageProvider;
  secretReference: string;
  keyVersion: string;
  status: ExternalCredentialStatus;
  expiresAt: Date | null;
  rotatedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type OutboxEventRecord = {
  id: string;
  organizationId: string | null;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  eventSchemaVersion: number;
  payload: OutboxPayloadJson;
  dedupeKey: string;
  occurredAt: Date;
  availableAt: Date;
  claimedAt: Date | null;
  leaseExpiresAt: Date | null;
  processedAt: Date | null;
  attemptCount: number;
  lastFailureCategory: string | null;
  lastFailureCode: string | null;
  status: OutboxEventStatus;
  createdAt: Date;
};

export type BackgroundJobRecord = {
  id: string;
  organizationId: string | null;
  outboxEventId: string | null;
  jobType: string;
  status: BackgroundJobStatus;
  attempt: number;
  startedAt: Date | null;
  leaseExpiresAt: Date | null;
  completedAt: Date | null;
  failureCategory: string | null;
  failureCode: string | null;
  workerIdentifier: string | null;
  createdAt: Date;
};

export type IdempotencyRecordRecord = {
  id: string;
  organizationId: string;
  scope: string;
  keyHash: string;
  requestFingerprint: string;
  status: IdempotencyRecordStatus;
  responseStatus: number | null;
  response: IdempotencyResponseJson | null;
  createdAt: Date;
  expiresAt: Date;
  completedAt: Date | null;
};
