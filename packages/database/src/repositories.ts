import { Prisma } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';
import type {
  AssetOwnerRecord,
  AssetRepository,
  AuditAppendRepository,
  CreateAssetInput,
  CreateEnvironmentInput,
  CreateFindingInput,
  CreateMembershipInput,
  CreateOrganizationInput,
  CreateOutboxEventInput,
  CreateRemediationTaskInput,
  CreateRiskPolicyInput,
  CreateSbomInput,
  CreateTeamInput,
  EnvironmentRepository,
  FindingRepository,
  IdempotencyRepository,
  MembershipRepository,
  OrganizationRepository,
  OutboxRepository,
  PageRequest,
  PersistenceUnitOfWork,
  RemediationRepository,
  RepositoryBundle,
  RiskPolicyRepository,
  SbomMetadataRepository,
  TeamRepository,
  UpsertIdempotencyRecordInput,
} from '@patchpilot/domain';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { asJsonObject, normalizeSlug, requirePositiveByteLength, requireSha256 } from './guards.js';
import {
  mapAsset,
  mapAssetOwner,
  mapAuditEvent,
  mapEnvironment,
  mapFinding,
  mapIdempotencyRecord,
  mapMembership,
  mapOrganization,
  mapOutboxEvent,
  mapRemediationTask,
  mapRiskPolicy,
  mapSbom,
  mapTeam,
  mapTeamMembership,
} from './mappers.js';
import { afterIdWhere, paginateById } from './paging.js';
import { getPrismaClient } from './client.js';

function tenantWhere(organizationId: string, id: string): { organizationId: string; id: string } {
  return { organizationId, id };
}

export function createRepositories(client: PrismaClientLike): RepositoryBundle {
  return {
    organizations: new PrismaOrganizationRepository(client),
    memberships: new PrismaMembershipRepository(client),
    teams: new PrismaTeamRepository(client),
    environments: new PrismaEnvironmentRepository(client),
    assets: new PrismaAssetRepository(client),
    sboms: new PrismaSbomMetadataRepository(client),
    findings: new PrismaFindingRepository(client),
    riskPolicies: new PrismaRiskPolicyRepository(client),
    remediationTasks: new PrismaRemediationRepository(client),
    auditEvents: new PrismaAuditAppendRepository(client),
    outboxEvents: new PrismaOutboxRepository(client),
    idempotencyRecords: new PrismaIdempotencyRepository(client),
  };
}

export function createPrismaUnitOfWork(options?: {
  databaseUrl?: string;
  client?: PrismaClient;
}): PersistenceUnitOfWork {
  return {
    async runInTransaction(work) {
      const prisma = options?.client ?? getPrismaClient(options);
      return prisma.$transaction(async (tx) => work(createRepositories(tx)));
    },
  };
}

class PrismaOrganizationRepository implements OrganizationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateOrganizationInput) {
    const row = await this.client.organization.create({
      data: {
        slug: normalizeSlug(input.slug, 'slug'),
        name: input.name.trim(),
        ...(input.status === undefined ? {} : { status: input.status }),
      },
    });
    return mapOrganization(row);
  }

  public async findById(organizationId: string, id: string) {
    if (organizationId !== id) {
      return undefined;
    }

    const row = await this.client.organization.findFirst({
      where: { id: organizationId },
    });
    return row === null ? undefined : mapOrganization(row);
  }

  public async findBySlug(organizationId: string, slug: string) {
    const row = await this.client.organization.findFirst({
      where: { id: organizationId, slug: normalizeSlug(slug, 'slug') },
    });
    return row === null ? undefined : mapOrganization(row);
  }

  public async findBySlugGlobally(slug: string) {
    const row = await this.client.organization.findFirst({
      where: { slug: normalizeSlug(slug, 'slug') },
    });
    return row === null ? undefined : mapOrganization(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.organization.findMany({
        where:
          cursorId === undefined || cursorId < organizationId
            ? { id: organizationId }
            : { id: { in: [] } },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapOrganization);
    }, page);
  }
}

class PrismaMembershipRepository implements MembershipRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateMembershipInput) {
    const row = await this.client.membership.create({
      data: {
        organizationId: input.organizationId,
        userId: input.userId,
        role: input.role,
        ...(input.invitedAt === undefined ? {} : { invitedAt: input.invitedAt }),
        ...(input.joinedAt === undefined ? {} : { joinedAt: input.joinedAt }),
      },
    });
    return mapMembership(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.membership.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapMembership(row);
  }

  public async findByUser(organizationId: string, userId: string) {
    const row = await this.client.membership.findFirst({
      where: { organizationId, userId },
    });
    return row === null ? undefined : mapMembership(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.membership.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapMembership);
    }, page);
  }
}

class PrismaTeamRepository implements TeamRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateTeamInput) {
    const row = await this.client.team.create({
      data: {
        organizationId: input.organizationId,
        name: input.name.trim(),
        slug: normalizeSlug(input.slug, 'slug'),
        ...(input.status === undefined ? {} : { status: input.status }),
      },
    });
    return mapTeam(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.team.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapTeam(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.team.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapTeam);
    }, page);
  }

  public async addMember(organizationId: string, teamId: string, userId: string) {
    const row = await this.client.teamMembership.create({
      data: { organizationId, teamId, userId },
    });
    return mapTeamMembership(row);
  }
}

class PrismaEnvironmentRepository implements EnvironmentRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateEnvironmentInput) {
    const row = await this.client.environment.create({
      data: {
        organizationId: input.organizationId,
        name: input.name.trim(),
        slug: normalizeSlug(input.slug, 'slug'),
        sensitivityClass: input.sensitivityClass,
      },
    });
    return mapEnvironment(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.environment.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapEnvironment(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.environment.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapEnvironment);
    }, page);
  }
}

class PrismaAssetRepository implements AssetRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateAssetInput) {
    const row = await this.client.asset.create({
      data: {
        organizationId: input.organizationId,
        name: input.name.trim(),
        assetType: input.assetType,
        ...(input.description === undefined ? {} : { description: input.description }),
        ...(input.lifecycleStatus === undefined ? {} : { lifecycleStatus: input.lifecycleStatus }),
        ...(input.environmentId === undefined ? {} : { environmentId: input.environmentId }),
        ...(input.owningTeamId === undefined ? {} : { owningTeamId: input.owningTeamId }),
        ...(input.businessCriticality === undefined
          ? {}
          : { businessCriticality: input.businessCriticality }),
        ...(input.internetExposure === undefined
          ? {}
          : { internetExposure: input.internetExposure }),
        ...(input.dataClassification === undefined
          ? {}
          : { dataClassification: input.dataClassification }),
        ...(input.repositoryUrl === undefined ? {} : { repositoryUrl: input.repositoryUrl }),
        ...(input.deploymentContext === undefined
          ? {}
          : { deploymentContext: input.deploymentContext }),
        ...(input.tags === undefined
          ? {}
          : {
              tags: {
                create: input.tags.map((tag) => ({
                  organizationId: input.organizationId,
                  tag: tag.trim().toLowerCase(),
                })),
              },
            }),
      },
    });
    return mapAsset(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.asset.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapAsset(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.asset.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapAsset);
    }, page);
  }

  public async addOwner(
    organizationId: string,
    assetId: string,
    owner: { userId?: string; teamId?: string; role: AssetOwnerRecord['role'] },
  ) {
    const row = await this.client.assetOwner.create({
      data: {
        organizationId,
        assetId,
        role: owner.role,
        ...(owner.userId === undefined ? {} : { userId: owner.userId }),
        ...(owner.teamId === undefined ? {} : { teamId: owner.teamId }),
      },
    });
    return mapAssetOwner(row);
  }
}

class PrismaSbomMetadataRepository implements SbomMetadataRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateSbomInput) {
    const row = await this.client.sbom.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.assetId,
        objectKey: input.objectKey,
        sha256: requireSha256(input.sha256, 'sha256'),
        byteLength: requirePositiveByteLength(input.byteLength, 'byteLength'),
        declaredContentType: input.declaredContentType,
        receivedAt: input.receivedAt ?? new Date(),
        ...(input.specificationVersion === undefined
          ? {}
          : { specificationVersion: input.specificationVersion }),
        ...(input.originalFilename === undefined
          ? {}
          : { originalFilename: input.originalFilename }),
        ...(input.uploadedByUserId === undefined
          ? {}
          : { uploadedByUserId: input.uploadedByUserId }),
        ...(input.capturedAt === undefined ? {} : { capturedAt: input.capturedAt }),
      },
    });
    return mapSbom(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.sbom.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapSbom(row);
  }

  public async findByAssetAndHash(organizationId: string, assetId: string, sha256: string) {
    const row = await this.client.sbom.findFirst({
      where: {
        organizationId,
        assetId,
        sha256: requireSha256(sha256, 'sha256'),
      },
    });
    return row === null ? undefined : mapSbom(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.sbom.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapSbom);
    }, page);
  }
}

class PrismaFindingRepository implements FindingRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateFindingInput) {
    const row = await this.client.finding.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.assetId,
        vulnerabilityId: input.vulnerabilityId,
        componentId: input.componentId,
        firstObservedAt: input.firstObservedAt,
        lastObservedAt: input.lastObservedAt,
        ...(input.state === undefined ? {} : { state: input.state }),
        ...(input.componentOccurrenceId === undefined
          ? {}
          : { componentOccurrenceId: input.componentOccurrenceId }),
        ...(input.assignedUserId === undefined ? {} : { assignedUserId: input.assignedUserId }),
        ...(input.assignedTeamId === undefined ? {} : { assignedTeamId: input.assignedTeamId }),
        ...(input.dueAt === undefined ? {} : { dueAt: input.dueAt }),
      },
    });
    return mapFinding(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.finding.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapFinding(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.finding.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapFinding);
    }, page);
  }
}

class PrismaRiskPolicyRepository implements RiskPolicyRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateRiskPolicyInput) {
    const row = await this.client.riskPolicy.create({
      data: {
        organizationId: input.organizationId,
        policyKey: input.policyKey,
        name: input.name,
        version: input.version,
        status: input.status,
        policySchemaVersion: input.policySchemaVersion,
        definition: asJsonObject(input.definition as unknown as Prisma.JsonValue, 'definition'),
        ...(input.publishedAt === undefined ? {} : { publishedAt: input.publishedAt }),
        ...(input.createdByUserId === undefined ? {} : { createdByUserId: input.createdByUserId }),
      },
    });
    return mapRiskPolicy(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.riskPolicy.findFirst({
      where: { organizationId, id },
    });
    return row === null ? undefined : mapRiskPolicy(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.riskPolicy.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapRiskPolicy);
    }, page);
  }
}

class PrismaRemediationRepository implements RemediationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateRemediationTaskInput) {
    const row = await this.client.remediationTask.create({
      data: {
        organizationId: input.organizationId,
        findingId: input.findingId,
        title: input.title,
        ...(input.description === undefined ? {} : { description: input.description }),
        ...(input.status === undefined ? {} : { status: input.status }),
        ...(input.assignedUserId === undefined ? {} : { assignedUserId: input.assignedUserId }),
        ...(input.assignedTeamId === undefined ? {} : { assignedTeamId: input.assignedTeamId }),
        ...(input.dueAt === undefined ? {} : { dueAt: input.dueAt }),
      },
    });
    return mapRemediationTask(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.remediationTask.findFirst({
      where: tenantWhere(organizationId, id),
    });
    return row === null ? undefined : mapRemediationTask(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.remediationTask.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapRemediationTask);
    }, page);
  }
}

class PrismaAuditAppendRepository implements AuditAppendRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async append(input: Parameters<AuditAppendRepository['append']>[0]) {
    const row = await this.client.auditEvent.create({
      data: {
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        correlationId: input.correlationId,
        payload: asJsonObject(input.payload as unknown as Prisma.JsonValue, 'payload'),
        schemaVersion: input.schemaVersion ?? JSON_SCHEMA_VERSION_V1,
        ...(input.organizationId === undefined ? {} : { organizationId: input.organizationId }),
        ...(input.actorUserId === undefined ? {} : { actorUserId: input.actorUserId }),
        ...(input.occurredAt === undefined ? {} : { occurredAt: input.occurredAt }),
        ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
        ...(input.sourceIp === undefined ? {} : { sourceIp: input.sourceIp }),
        ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
        ...(input.retentionCategory === undefined
          ? {}
          : { retentionCategory: input.retentionCategory }),
      },
    });
    return mapAuditEvent(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.auditEvent.findFirst({
      where: { organizationId, id },
    });
    return row === null ? undefined : mapAuditEvent(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.auditEvent.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapAuditEvent);
    }, page);
  }
}

class PrismaOutboxRepository implements OutboxRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: CreateOutboxEventInput) {
    const row = await this.client.outboxEvent.create({
      data: {
        aggregateType: input.aggregateType,
        aggregateId: input.aggregateId,
        eventType: input.eventType,
        eventSchemaVersion: input.eventSchemaVersion ?? JSON_SCHEMA_VERSION_V1,
        payload: asJsonObject(input.payload as unknown as Prisma.JsonValue, 'payload'),
        dedupeKey: input.dedupeKey,
        ...(input.organizationId === undefined ? {} : { organizationId: input.organizationId }),
        ...(input.occurredAt === undefined ? {} : { occurredAt: input.occurredAt }),
        ...(input.availableAt === undefined ? {} : { availableAt: input.availableAt }),
        ...(input.status === undefined ? {} : { status: input.status }),
      },
    });
    return mapOutboxEvent(row);
  }

  public async findById(organizationId: string, id: string) {
    const row = await this.client.outboxEvent.findFirst({
      where: { organizationId, id },
    });
    return row === null ? undefined : mapOutboxEvent(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.outboxEvent.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapOutboxEvent);
    }, page);
  }
}

class PrismaIdempotencyRepository implements IdempotencyRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async create(input: UpsertIdempotencyRecordInput) {
    const row = await this.client.idempotencyRecord.create({
      data: {
        organizationId: input.organizationId,
        scope: input.scope,
        keyHash: requireSha256(input.keyHash, 'keyHash'),
        requestFingerprint: requireSha256(input.requestFingerprint, 'requestFingerprint'),
        expiresAt: input.expiresAt,
        ...(input.status === undefined ? {} : { status: input.status }),
        ...(input.responseStatus === undefined ? {} : { responseStatus: input.responseStatus }),
        ...(input.response === undefined
          ? {}
          : { response: asJsonObject(input.response as unknown as Prisma.JsonValue, 'response') }),
      },
    });
    return mapIdempotencyRecord(row);
  }

  public async findByKey(organizationId: string, scope: string, keyHash: string) {
    const row = await this.client.idempotencyRecord.findFirst({
      where: {
        organizationId,
        scope,
        keyHash: requireSha256(keyHash, 'keyHash'),
      },
    });
    return row === null ? undefined : mapIdempotencyRecord(row);
  }

  public async listForOrganization(organizationId: string, page?: PageRequest) {
    return paginateById(async ({ take, cursorId }) => {
      const rows = await this.client.idempotencyRecord.findMany({
        where: { organizationId, ...afterIdWhere(cursorId) },
        orderBy: { id: 'asc' },
        take,
      });
      return rows.map(mapIdempotencyRecord);
    }, page);
  }
}
