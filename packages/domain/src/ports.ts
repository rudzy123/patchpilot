import type { Page, PageRequest } from './pagination.js';
import type {
  AssetOwnerRecord,
  AssetRecord,
  AuditEventRecord,
  EnvironmentRecord,
  FindingRecord,
  IdempotencyRecordRecord,
  LocalCredentialRecord,
  MembershipRecord,
  OrganizationRecord,
  OutboxEventRecord,
  RemediationTaskRecord,
  RiskPolicyRecord,
  SbomRecord,
  SessionRecord,
  TeamMembershipRecord,
  TeamRecord,
  UserRecord,
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
  SessionAuthenticationMethod,
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
  uploadedByMembershipId?: string;
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
  assignedMembershipId?: string;
  assignedTeamId?: string;
  dueAt?: Date;
};

export type CreateBuiltinRiskPolicyInput = {
  policyKey: string;
  name: string;
  version: number;
  status: RiskPolicyStatus;
  policySchemaVersion: number;
  definition: RiskPolicyDefinitionJson;
  publishedAt?: Date;
};

export type CreateOrganizationRiskPolicyInput = {
  organizationId: string;
  policyKey: string;
  name: string;
  version: number;
  status: RiskPolicyStatus;
  policySchemaVersion: number;
  definition: RiskPolicyDefinitionJson;
  publishedAt?: Date;
  createdByMembershipId?: string;
};

export type CreateRemediationTaskInput = {
  organizationId: string;
  findingId: string;
  title: string;
  description?: string;
  status?: RemediationTaskStatus;
  assignedMembershipId?: string;
  assignedTeamId?: string;
  dueAt?: Date;
};

export type AppendAuditEventInput = {
  organizationId?: string;
  actorUserId?: string;
  actorMembershipId?: string;
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

export type UserRepository = {
  findById(userId: string): Promise<UserRecord | undefined>;
  findByNormalizedEmail(email: string): Promise<UserRecord | undefined>;
};

export type UpdateLocalCredentialPasswordHashInput = {
  userId: string;
  passwordHash: string;
  passwordRevision: number;
};

export type LocalCredentialRepository = {
  findByUserId(userId: string): Promise<LocalCredentialRecord | undefined>;
  updatePasswordHash(
    input: UpdateLocalCredentialPasswordHashInput,
  ): Promise<LocalCredentialRecord | undefined>;
};

export type CreateSessionInput = {
  userId: string;
  tokenHash: string;
  csrfTokenHash: string;
  activeOrganizationId?: string;
  authenticationMethod?: SessionAuthenticationMethod;
  passwordRevision: number;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  userAgent?: string;
};

export type UpdateThrottledLastSeenInput = {
  tokenHash: string;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  minLastSeenAt: Date;
};

export type RotateSessionInput = {
  currentTokenHash: string;
  nextTokenHash: string;
  nextCsrfTokenHash: string;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  activeOrganizationId?: string | null;
};

export type ReplaceCsrfTokenInput = {
  tokenHash: string;
  nextCsrfTokenHash: string;
};

export type RevokeCurrentSessionInput = {
  tokenHash: string;
  revokedAt: Date;
  revokeReason: string;
};

export type RevokeAllSessionsForUserInput = {
  userId: string;
  revokedAt: Date;
  revokeReason: string;
};

export type ClearActiveOrganizationInput = {
  userId: string;
  organizationId: string;
};

export type SessionRepository = {
  create(input: CreateSessionInput): Promise<SessionRecord>;
  findByTokenHash(tokenHash: string): Promise<SessionRecord | undefined>;
  updateThrottledLastSeen(input: UpdateThrottledLastSeenInput): Promise<SessionRecord | undefined>;
  rotate(input: RotateSessionInput): Promise<SessionRecord | undefined>;
  replaceCsrfToken(input: ReplaceCsrfTokenInput): Promise<SessionRecord | undefined>;
  revokeCurrent(input: RevokeCurrentSessionInput): Promise<SessionRecord | undefined>;
  revokeAllForUser(input: RevokeAllSessionsForUserInput): Promise<number>;
  clearActiveOrganization(input: ClearActiveOrganizationInput): Promise<number>;
};

/** Authentication-boundary join of an active membership in an active organization. */
export type ActiveMembershipWithOrganization = {
  membership: MembershipRecord;
  organization: OrganizationRecord;
};

export type MembershipRepository = {
  create(input: CreateMembershipInput): Promise<MembershipRecord>;
  findById(organizationId: string, id: string): Promise<MembershipRecord | undefined>;
  findByUser(organizationId: string, userId: string): Promise<MembershipRecord | undefined>;
  listForOrganization(organizationId: string, page?: PageRequest): Promise<Page<MembershipRecord>>;
  /**
   * Authentication-boundary query. Lists active Memberships in active
   * Organizations for one User. Callers must pass the authenticated user id.
   * This is not a tenant-scoped lookup and does not replace findByUser.
   */
  listActiveInActiveOrganizationsForUser(
    userId: string,
  ): Promise<readonly ActiveMembershipWithOrganization[]>;
  /**
   * Authentication-boundary query. Resolves one active Membership in one
   * active Organization for one User. Callers must pass the authenticated
   * user id. This is not a tenant-scoped lookup and does not replace findByUser.
   */
  findActiveInActiveOrganization(
    userId: string,
    organizationId: string,
  ): Promise<ActiveMembershipWithOrganization | undefined>;
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
  createBuiltin(input: CreateBuiltinRiskPolicyInput): Promise<RiskPolicyRecord>;
  createForOrganization(input: CreateOrganizationRiskPolicyInput): Promise<RiskPolicyRecord>;
  findBuiltinById(id: string): Promise<RiskPolicyRecord | undefined>;
  findBuiltinByKeyVersion(
    policyKey: string,
    version: number,
  ): Promise<RiskPolicyRecord | undefined>;
  findById(organizationId: string, id: string): Promise<RiskPolicyRecord | undefined>;
  listBuiltins(page?: PageRequest): Promise<Page<RiskPolicyRecord>>;
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
  users: UserRepository;
  memberships: MembershipRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
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
