import type { Page, PageRequest } from './pagination.js';
import type {
  AssetOwnerRecord,
  AssetRecord,
  AuditEventRecord,
  EnvironmentRecord,
  FindingRecord,
  IdempotencyRecordRecord,
  MembershipRecord,
  OrganizationRecord,
  OutboxEventRecord,
  RemediationTaskRecord,
  RiskPolicyRecord,
  SbomRecord,
  TeamMembershipRecord,
  TeamRecord,
} from './records.js';
import type {
  AssetDataClassification,
  AssetLifecycleStatus,
  AssetOwnerRole,
  AssetType,
  AuditActorType,
  AuditRetentionCategory,
  BusinessCriticality,
  EnvironmentSensitivityClass,
  FindingState,
  IdempotencyRecordStatus,
  InternetExposure,
  MembershipRole,
  OrganizationStatus,
  OutboxEventStatus,
  RemediationTaskStatus,
  RiskPolicyStatus,
  TeamStatus,
} from './lifecycle.js';
import type {
  AuditPayloadJson,
  IdempotencyResponseJson,
  OutboxPayloadJson,
  RiskPolicyDefinitionJson,
} from './json-documents.js';

export type CreateOrganizationInput = {
  slug: string;
  name: string;
  status?: OrganizationStatus;
};

export type CreateMembershipInput = {
  organizationId: string;
  userId: string;
  role: MembershipRole;
  invitedAt?: Date;
  joinedAt?: Date;
};

export type CreateTeamInput = {
  organizationId: string;
  name: string;
  slug: string;
  status?: TeamStatus;
};

export type CreateEnvironmentInput = {
  organizationId: string;
  name: string;
  slug: string;
  sensitivityClass: EnvironmentSensitivityClass;
};

export type CreateAssetInput = {
  organizationId: string;
  name: string;
  description?: string;
  assetType: AssetType;
  lifecycleStatus?: AssetLifecycleStatus;
  environmentId?: string;
  owningTeamId?: string;
  businessCriticality?: BusinessCriticality;
  internetExposure?: InternetExposure;
  dataClassification?: AssetDataClassification;
  repositoryUrl?: string;
  deploymentContext?: string;
  tags?: readonly string[];
};

export type CreateSbomInput = {
  organizationId: string;
  assetId: string;
  objectKey: string;
  sha256: string;
  byteLength: number;
  declaredContentType: string;
  specificationVersion?: string;
  originalFilename?: string;
  uploadedByUserId?: string;
  capturedAt?: Date;
  receivedAt?: Date;
};

export type CreateFindingInput = {
  organizationId: string;
  assetId: string;
  vulnerabilityId: string;
  componentId: string;
  componentOccurrenceId?: string;
  state?: FindingState;
  firstObservedAt: Date;
  lastObservedAt: Date;
  assignedUserId?: string;
  assignedTeamId?: string;
  dueAt?: Date;
};

export type CreateRiskPolicyInput = {
  organizationId: string;
  policyKey: string;
  name: string;
  version: number;
  status: RiskPolicyStatus;
  policySchemaVersion: number;
  definition: RiskPolicyDefinitionJson;
  publishedAt?: Date;
  createdByUserId?: string;
};

export type CreateRemediationTaskInput = {
  organizationId: string;
  findingId: string;
  title: string;
  description?: string;
  status?: RemediationTaskStatus;
  assignedUserId?: string;
  assignedTeamId?: string;
  dueAt?: Date;
};

export type AppendAuditEventInput = {
  organizationId?: string;
  actorUserId?: string;
  actorType: AuditActorType;
  action: string;
  subjectType: string;
  subjectId: string;
  occurredAt?: Date;
  requestId?: string;
  correlationId: string;
  sourceIp?: string;
  userAgent?: string;
  payload: AuditPayloadJson;
  schemaVersion?: number;
  retentionCategory?: AuditRetentionCategory;
};

export type CreateOutboxEventInput = {
  organizationId?: string;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  eventSchemaVersion?: number;
  payload: OutboxPayloadJson;
  dedupeKey: string;
  occurredAt?: Date;
  availableAt?: Date;
  status?: OutboxEventStatus;
};

export type UpsertIdempotencyRecordInput = {
  organizationId: string;
  scope: string;
  keyHash: string;
  requestFingerprint: string;
  status?: IdempotencyRecordStatus;
  responseStatus?: number;
  response?: IdempotencyResponseJson;
  expiresAt: Date;
};

export type OrganizationRepository = {
  create(input: CreateOrganizationInput): Promise<OrganizationRecord>;
  findById(organizationId: string, id: string): Promise<OrganizationRecord | undefined>;
  findBySlug(organizationId: string, slug: string): Promise<OrganizationRecord | undefined>;
  findBySlugGlobally(slug: string): Promise<OrganizationRecord | undefined>;
  listForOrganization(
    organizationId: string,
    page?: PageRequest,
  ): Promise<Page<OrganizationRecord>>;
};

export type MembershipRepository = {
  create(input: CreateMembershipInput): Promise<MembershipRecord>;
  findById(organizationId: string, id: string): Promise<MembershipRecord | undefined>;
  findByUser(organizationId: string, userId: string): Promise<MembershipRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<MembershipRecord>>;
};

export type TeamRepository = {
  create(input: CreateTeamInput): Promise<TeamRecord>;
  findById(organizationId: string, id: string): Promise<TeamRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<TeamRecord>>;
  addMember(organizationId: string, teamId: string, userId: string): Promise<TeamMembershipRecord>;
};

export type EnvironmentRepository = {
  create(input: CreateEnvironmentInput): Promise<EnvironmentRecord>;
  findById(organizationId: string, id: string): Promise<EnvironmentRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<EnvironmentRecord>>;
};

export type AssetRepository = {
  create(input: CreateAssetInput): Promise<AssetRecord>;
  findById(organizationId: string, id: string): Promise<AssetRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<AssetRecord>>;
  addOwner(
    organizationId: string,
    assetId: string,
    owner: { userId?: string; teamId?: string; role: AssetOwnerRole },
  ): Promise<AssetOwnerRecord>;
};

export type SbomMetadataRepository = {
  create(input: CreateSbomInput): Promise<SbomRecord>;
  findById(organizationId: string, id: string): Promise<SbomRecord | undefined>;
  findByAssetAndHash(
    organizationId: string,
    assetId: string,
    sha256: string,
  ): Promise<SbomRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<SbomRecord>>;
};

export type FindingRepository = {
  create(input: CreateFindingInput): Promise<FindingRecord>;
  findById(organizationId: string, id: string): Promise<FindingRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<FindingRecord>>;
};

export type RiskPolicyRepository = {
  create(input: CreateRiskPolicyInput): Promise<RiskPolicyRecord>;
  findById(organizationId: string, id: string): Promise<RiskPolicyRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<RiskPolicyRecord>>;
};

export type RemediationRepository = {
  create(input: CreateRemediationTaskInput): Promise<RemediationTaskRecord>;
  findById(organizationId: string, id: string): Promise<RemediationTaskRecord | undefined>;
  listForOrganization(
    organizationId: string,
    page?: PageRequest,
  ): Promise<Page<RemediationTaskRecord>>;
};

export type AuditAppendRepository = {
  append(input: AppendAuditEventInput): Promise<AuditEventRecord>;
  findById(organizationId: string, id: string): Promise<AuditEventRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<AuditEventRecord>>;
};

export type OutboxRepository = {
  create(input: CreateOutboxEventInput): Promise<OutboxEventRecord>;
  findById(organizationId: string, id: string): Promise<OutboxEventRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<OutboxEventRecord>>;
};

export type IdempotencyRepository = {
  create(input: UpsertIdempotencyRecordInput): Promise<IdempotencyRecordRecord>;
  findByKey(
    organizationId: string,
    scope: string,
    keyHash: string,
  ): Promise<IdempotencyRecordRecord | undefined>;
  listForOrganization(
    organizationId: string,
    page?: PageRequest,
  ): Promise<Page<IdempotencyRecordRecord>>;
};

export type RepositoryBundle = {
  organizations: OrganizationRepository;
  memberships: MembershipRepository;
  teams: TeamRepository;
  environments: EnvironmentRepository;
  assets: AssetRepository;
  sboms: SbomMetadataRepository;
  findings: FindingRepository;
  riskPolicies: RiskPolicyRepository;
  remediationTasks: RemediationRepository;
  auditEvents: AuditAppendRepository;
  outboxEvents: OutboxRepository;
  idempotencyRecords: IdempotencyRepository;
};

export type PersistenceUnitOfWork = {
  runInTransaction<T>(work: (repos: RepositoryBundle) => Promise<T>): Promise<T>;
};
