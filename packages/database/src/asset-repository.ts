import { Prisma, PrismaClient } from '@prisma/client';
import {
  ASSET_LIST_CURSOR_VERSION,
  ASSET_NAME_CONFLICT,
  ORGANIZATION_CONTEXT_REQUIRED,
  assetValidationError,
  err,
  ok,
  type AssetCompareAndSetOutcome,
  type AssetListQuery,
  type AssetOwnerAssignment,
  type AssetOwnerRecord,
  type AssetRepository,
  type CreateAssetInput,
  type NormalizedCreateAssetCommand,
  type NormalizedExternalIdentifier,
  type NormalizedUpdateAssetCommand,
  type Result,
} from '@patchpilot/domain';

import { buildAssetListQuery } from './asset-list-query.js';
import {
  mapAssetDetail,
  mapAssetSummary,
  type AssetDetailRelationRow,
  type AssetListRow,
} from './asset-mappers.js';
import type { PrismaClientLike } from './guards.js';
import { isUuid } from './guards.js';
import { mapAsset, mapAssetOwner } from './mappers.js';

const INACTIVE_MEMBERSHIP = assetValidationError('Membership is not an active assignment target.');
const INACTIVE_TEAM = assetValidationError('Team is not an active assignment target.');
const INACTIVE_ENVIRONMENT = assetValidationError(
  'Environment is not an active assignment target.',
);
const DUPLICATE_OWNERS = assetValidationError('Asset owner assignments must be unique.');
const DUPLICATE_TAGS = assetValidationError('Asset tags must be unique.');
const DUPLICATE_IDENTIFIERS = assetValidationError(
  'External identifier namespaces must be unique per asset.',
);

const assetDetailInclude = {
  environment: true,
  owningTeam: true,
  tags: { orderBy: { tag: 'asc' as const } },
  externalIdentifiers: { orderBy: { namespace: 'asc' as const } },
  owners: {
    include: {
      team: true,
      user: true,
      membership: true,
    },
  },
} as const;

export class PrismaAssetRepository implements AssetRepository {
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

  public async createAggregate(organizationId: string, command: NormalizedCreateAssetCommand) {
    const scoped = requireOrganization(organizationId);
    if (!scoped.ok) {
      return scoped;
    }

    return this.runInTransaction(async (repo) => {
      const targets = await repo.validateAssignmentTargets({
        organizationId,
        owners: command.owners,
        ...(command.environmentId === undefined ? {} : { environmentId: command.environmentId }),
        ...(command.owningTeamId === undefined ? {} : { owningTeamId: command.owningTeamId }),
      });
      if (!targets.ok) {
        return targets;
      }

      const uniqueness = rejectDuplicateCollections({
        owners: command.owners,
        tags: command.tags,
        identifiers: command.externalIdentifiers,
      });
      if (!uniqueness.ok) {
        return uniqueness;
      }

      try {
        const row = await repo.client.asset.create({
          data: {
            organizationId,
            name: command.name,
            assetType: command.assetType,
            businessCriticality: command.businessCriticality,
            internetExposure: command.internetExposure,
            dataClassification: command.dataClassification,
            ...(command.description === undefined ? {} : { description: command.description }),
            ...(command.repositoryUrl === undefined
              ? {}
              : { repositoryUrl: command.repositoryUrl }),
            ...(command.deploymentContext === undefined
              ? {}
              : { deploymentContext: command.deploymentContext }),
            ...(command.environmentId === undefined
              ? {}
              : { environmentId: command.environmentId }),
            ...(command.owningTeamId === undefined ? {} : { owningTeamId: command.owningTeamId }),
          },
        });

        if (command.tags.length > 0) {
          await repo.client.assetTag.createMany({
            data: command.tags.map((tag) => ({ organizationId, assetId: row.id, tag })),
          });
        }

        if (command.externalIdentifiers.length > 0) {
          await repo.client.assetExternalIdentifier.createMany({
            data: command.externalIdentifiers.map((identifier) => ({
              organizationId,
              assetId: row.id,
              namespace: identifier.namespace,
              identifier: identifier.identifier,
            })),
          });
        }

        if (command.owners.length > 0) {
          await repo.client.assetOwner.createMany({
            data: ownerCreateData(organizationId, command.owners, targets.value).map((owner) => ({
              ...owner,
              assetId: row.id,
            })),
          });
        }

        const detail = await repo.findDetailById(organizationId, row.id);
        if (detail === undefined) {
          throw new Error('Created asset could not be reloaded.');
        }
        return ok(detail);
      } catch (error) {
        if (isUniqueViolation(error)) {
          return err(ASSET_NAME_CONFLICT);
        }
        throw error;
      }
    });
  }

  public async findById(organizationId: string, id: string) {
    if (!isUuid(organizationId) || !isUuid(id)) {
      return undefined;
    }

    const row = await this.client.asset.findFirst({
      where: { organizationId, id },
    });
    return row === null ? undefined : mapAsset(row);
  }

  public async findDetailById(organizationId: string, id: string) {
    if (!isUuid(organizationId) || !isUuid(id)) {
      return undefined;
    }

    const row = await this.client.asset.findFirst({
      where: { organizationId, id },
      include: assetDetailInclude,
    });
    return row === null ? undefined : mapAssetDetail(row as AssetDetailRelationRow);
  }

  public async listForOrganization(organizationId: string, query?: AssetListQuery) {
    const compiled = buildAssetListQuery(organizationId, query);
    if (compiled.empty) {
      return { items: [], nextCursor: undefined };
    }

    const rows = await this.client.$queryRaw<AssetListRow[]>(compiled.sql);
    const limit = compiled.take - 1;
    const pageRows = rows.length > limit ? rows.slice(0, limit) : rows;
    const last = pageRows[pageRows.length - 1];
    const nextCursor: AssetListQuery['cursor'] =
      rows.length > limit && last !== undefined
        ? { v: ASSET_LIST_CURSOR_VERSION, n: last.name, i: last.id }
        : undefined;

    return {
      items: pageRows.map(mapAssetSummary),
      nextCursor,
    };
  }

  public async compareAndSetUpdate(
    organizationId: string,
    assetId: string,
    command: NormalizedUpdateAssetCommand,
  ) {
    const scoped = requireOrganization(organizationId);
    if (!scoped.ok) {
      return scoped;
    }
    if (!isUuid(assetId)) {
      return ok({ kind: 'not_found' } satisfies AssetCompareAndSetOutcome);
    }

    return this.runInTransaction(async (repo) => {
      const targets = await repo.validateAssignmentTargets({
        organizationId,
        ...('environmentId' in command ? { environmentId: command.environmentId } : {}),
        ...('owningTeamId' in command ? { owningTeamId: command.owningTeamId } : {}),
        ...(command.owners === undefined ? {} : { owners: command.owners }),
      });
      if (!targets.ok) {
        return targets;
      }

      const uniqueness = rejectDuplicateCollections({
        ...(command.owners === undefined ? {} : { owners: command.owners }),
        ...(command.tags === undefined ? {} : { tags: command.tags }),
        ...(command.externalIdentifiers === undefined
          ? {}
          : { identifiers: command.externalIdentifiers }),
      });
      if (!uniqueness.ok) {
        return uniqueness;
      }

      try {
        const updated = await repo.client.asset.updateMany({
          where: {
            organizationId,
            id: assetId,
            version: command.expectedVersion,
            lifecycleStatus: 'active',
          },
          data: scalarUpdateData(command),
        });

        if (updated.count === 0) {
          return ok(await repo.classifyCompareAndSetMiss(organizationId, assetId));
        }

        if (command.owners !== undefined) {
          const replaced = await repo.replaceOwners(organizationId, assetId, command.owners);
          if (!replaced.ok) {
            return replaced;
          }
        }

        if (command.tags !== undefined) {
          const replaced = await repo.replaceTags(organizationId, assetId, command.tags);
          if (!replaced.ok) {
            return replaced;
          }
        }

        if (command.externalIdentifiers !== undefined) {
          const replaced = await repo.replaceExternalIdentifiers(
            organizationId,
            assetId,
            command.externalIdentifiers,
          );
          if (!replaced.ok) {
            return replaced;
          }
        }

        const asset = await repo.findDetailById(organizationId, assetId);
        if (asset === undefined) {
          return ok({ kind: 'not_found' } satisfies AssetCompareAndSetOutcome);
        }

        return ok({ kind: 'updated', asset } satisfies AssetCompareAndSetOutcome);
      } catch (error) {
        if (isUniqueViolation(error)) {
          return err(ASSET_NAME_CONFLICT);
        }
        throw error;
      }
    });
  }

  public async compareAndSetArchive(
    organizationId: string,
    assetId: string,
    expectedVersion: number,
  ) {
    if (!isUuid(organizationId) || !isUuid(assetId)) {
      return { kind: 'not_found' } satisfies AssetCompareAndSetOutcome;
    }

    return this.runInTransaction(async (repo) => {
      const updated = await repo.client.asset.updateMany({
        where: {
          organizationId,
          id: assetId,
          version: expectedVersion,
          lifecycleStatus: 'active',
        },
        data: {
          lifecycleStatus: 'archived',
          archivedAt: new Date(),
          version: { increment: 1 },
        },
      });

      if (updated.count === 0) {
        return repo.classifyCompareAndSetMiss(organizationId, assetId);
      }

      const asset = await repo.findDetailById(organizationId, assetId);
      if (asset === undefined) {
        return { kind: 'not_found' } satisfies AssetCompareAndSetOutcome;
      }

      return { kind: 'updated', asset } satisfies AssetCompareAndSetOutcome;
    });
  }

  public async replaceOwners(
    organizationId: string,
    assetId: string,
    owners: readonly AssetOwnerAssignment[],
  ) {
    const uniqueness = rejectDuplicateOwners(owners);
    if (!uniqueness.ok) {
      return uniqueness;
    }

    return this.runInTransaction(async (repo) => {
      const targets = await repo.validateAssignmentTargets({
        organizationId,
        owners,
      });
      if (!targets.ok) {
        return targets;
      }

      const current = await repo.client.assetOwner.findMany({
        where: { organizationId, assetId },
        include: { membership: true },
        orderBy: { id: 'asc' },
      });
      if (sameOwners(current, owners)) {
        return ok(undefined);
      }

      await repo.client.assetOwner.deleteMany({ where: { organizationId, assetId } });
      if (owners.length > 0) {
        await repo.client.assetOwner.createMany({
          data: ownerCreateData(organizationId, owners, targets.value).map((owner) => ({
            ...owner,
            assetId,
          })),
        });
      }

      return ok(undefined);
    });
  }

  public async replaceTags(organizationId: string, assetId: string, tags: readonly string[]) {
    const uniqueness = rejectDuplicateTags(tags);
    if (!uniqueness.ok) {
      return uniqueness;
    }

    return this.runInTransaction(async (repo) => {
      const current = await repo.client.assetTag.findMany({
        where: { organizationId, assetId },
        select: { tag: true },
        orderBy: { tag: 'asc' },
      });
      const next = [...tags].sort((left, right) => left.localeCompare(right));
      if (
        current.length === next.length &&
        current.every((row, index) => row.tag === next[index])
      ) {
        return ok(undefined);
      }

      await repo.client.assetTag.deleteMany({ where: { organizationId, assetId } });
      if (next.length > 0) {
        await repo.client.assetTag.createMany({
          data: next.map((tag) => ({ organizationId, assetId, tag })),
        });
      }

      return ok(undefined);
    });
  }

  public async replaceExternalIdentifiers(
    organizationId: string,
    assetId: string,
    identifiers: readonly NormalizedExternalIdentifier[],
  ) {
    const uniqueness = rejectDuplicateIdentifiers(identifiers);
    if (!uniqueness.ok) {
      return uniqueness;
    }

    return this.runInTransaction(async (repo) => {
      const current = await repo.client.assetExternalIdentifier.findMany({
        where: { organizationId, assetId },
        select: { namespace: true, identifier: true },
        orderBy: { namespace: 'asc' },
      });
      const next = [...identifiers].sort((left, right) =>
        left.namespace.localeCompare(right.namespace),
      );
      if (
        current.length === next.length &&
        current.every(
          (row, index) =>
            row.namespace === next[index]?.namespace && row.identifier === next[index]?.identifier,
        )
      ) {
        return ok(undefined);
      }

      await repo.client.assetExternalIdentifier.deleteMany({ where: { organizationId, assetId } });
      if (next.length > 0) {
        await repo.client.assetExternalIdentifier.createMany({
          data: next.map((identifier) => ({
            organizationId,
            assetId,
            namespace: identifier.namespace,
            identifier: identifier.identifier,
          })),
        });
      }

      return ok(undefined);
    });
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

  private async classifyCompareAndSetMiss(
    organizationId: string,
    assetId: string,
  ): Promise<AssetCompareAndSetOutcome> {
    const asset = await this.findDetailById(organizationId, assetId);
    if (asset === undefined) {
      return { kind: 'not_found' };
    }

    if (asset.lifecycleStatus === 'archived') {
      return { kind: 'archived', asset };
    }

    return { kind: 'version_conflict', asset };
  }

  private async validateAssignmentTargets(input: {
    organizationId: string;
    environmentId?: string | null;
    owningTeamId?: string | null;
    owners?: readonly AssetOwnerAssignment[];
  }): Promise<Result<AssignmentTargets>> {
    const membershipIds = uniqueIds(
      (input.owners ?? [])
        .filter((owner) => owner.kind === 'membership')
        .map((owner) => owner.membershipId),
    );
    const teamIds = uniqueIds([
      ...(input.owningTeamId === undefined || input.owningTeamId === null
        ? []
        : [input.owningTeamId]),
      ...(input.owners ?? []).filter((owner) => owner.kind === 'team').map((owner) => owner.teamId),
    ]);

    const [memberships, teams, environment] = await Promise.all([
      membershipIds.length === 0
        ? Promise.resolve([])
        : this.client.membership.findMany({
            where: {
              organizationId: input.organizationId,
              id: { in: membershipIds },
              status: 'active',
            },
            select: { id: true, userId: true },
          }),
      teamIds.length === 0
        ? Promise.resolve([])
        : this.client.team.findMany({
            where: {
              organizationId: input.organizationId,
              id: { in: teamIds },
              status: 'active',
            },
            select: { id: true },
          }),
      input.environmentId === undefined || input.environmentId === null
        ? Promise.resolve(null)
        : this.client.environment.findFirst({
            where: {
              organizationId: input.organizationId,
              id: input.environmentId,
              status: 'active',
            },
            select: { id: true },
          }),
    ]);

    if (memberships.length !== membershipIds.length) {
      return err(INACTIVE_MEMBERSHIP);
    }

    if (teams.length !== teamIds.length) {
      return err(INACTIVE_TEAM);
    }

    if (input.environmentId !== undefined && input.environmentId !== null && environment === null) {
      return err(INACTIVE_ENVIRONMENT);
    }

    return ok({
      membershipUserIds: new Map(memberships.map((row) => [row.id, row.userId])),
    });
  }

  private async runInTransaction<T>(work: (repo: PrismaAssetRepository) => Promise<T>): Promise<T> {
    if (isRootPrismaClient(this.client)) {
      return this.client.$transaction(async (tx) => work(new PrismaAssetRepository(tx)));
    }

    return work(this);
  }
}

type AssignmentTargets = {
  membershipUserIds: ReadonlyMap<string, string>;
};

function requireOrganization(organizationId: string): Result<string> {
  if (!isUuid(organizationId)) {
    return err(ORGANIZATION_CONTEXT_REQUIRED);
  }

  return ok(organizationId);
}

function scalarUpdateData(
  command: NormalizedUpdateAssetCommand,
): Prisma.AssetUncheckedUpdateManyInput {
  const data: Prisma.AssetUncheckedUpdateManyInput = {
    version: { increment: 1 },
  };

  if (command.name !== undefined) {
    data.name = command.name;
  }
  if (command.assetType !== undefined) {
    data.assetType = command.assetType;
  }
  if (command.businessCriticality !== undefined) {
    data.businessCriticality = command.businessCriticality;
  }
  if (command.internetExposure !== undefined) {
    data.internetExposure = command.internetExposure;
  }
  if (command.dataClassification !== undefined) {
    data.dataClassification = command.dataClassification;
  }
  if ('environmentId' in command) {
    data.environmentId = command.environmentId;
  }
  if ('owningTeamId' in command) {
    data.owningTeamId = command.owningTeamId;
  }
  if ('description' in command) {
    data.description = command.description;
  }
  if ('repositoryUrl' in command) {
    data.repositoryUrl = command.repositoryUrl;
  }
  if ('deploymentContext' in command) {
    data.deploymentContext = command.deploymentContext;
  }

  return data;
}

function ownerCreateData(
  organizationId: string,
  owners: readonly AssetOwnerAssignment[],
  targets: AssignmentTargets,
): Array<
  | { organizationId: string; role: AssetOwnerAssignment['role']; userId: string }
  | { organizationId: string; role: AssetOwnerAssignment['role']; teamId: string }
> {
  return owners.map((owner) => {
    if (owner.kind === 'membership') {
      const userId = targets.membershipUserIds.get(owner.membershipId);
      if (userId === undefined) {
        throw new Error('Active membership target is missing after validation.');
      }

      return { organizationId, role: owner.role, userId };
    }

    return { organizationId, role: owner.role, teamId: owner.teamId };
  });
}

function sameOwners(
  current: readonly {
    userId: string | null;
    teamId: string | null;
    role: AssetOwnerAssignment['role'];
    membership: { id: string } | null;
  }[],
  next: readonly AssetOwnerAssignment[],
): boolean {
  if (current.length !== next.length) {
    return false;
  }

  const currentKeys = new Set(
    current.map((row) => {
      if (row.teamId !== null) {
        return `team:${row.teamId}:${row.role}`;
      }

      return `membership:${row.membership?.id ?? ''}:${row.role}`;
    }),
  );
  return next.every((owner) => currentKeys.has(ownerKey(owner)));
}

function rejectDuplicateCollections(input: {
  owners?: readonly AssetOwnerAssignment[];
  tags?: readonly string[];
  identifiers?: readonly NormalizedExternalIdentifier[];
}): Result<void> {
  if (input.owners !== undefined) {
    const owners = rejectDuplicateOwners(input.owners);
    if (!owners.ok) {
      return owners;
    }
  }

  if (input.tags !== undefined) {
    const tags = rejectDuplicateTags(input.tags);
    if (!tags.ok) {
      return tags;
    }
  }

  if (input.identifiers !== undefined) {
    return rejectDuplicateIdentifiers(input.identifiers);
  }

  return ok(undefined);
}

function rejectDuplicateOwners(owners: readonly AssetOwnerAssignment[]): Result<void> {
  const seen = new Set<string>();
  for (const owner of owners) {
    const key = ownerKey(owner);
    if (seen.has(key)) {
      return err(DUPLICATE_OWNERS);
    }
    seen.add(key);
  }

  return ok(undefined);
}

function rejectDuplicateTags(tags: readonly string[]): Result<void> {
  if (new Set(tags).size !== tags.length) {
    return err(DUPLICATE_TAGS);
  }

  return ok(undefined);
}

function rejectDuplicateIdentifiers(
  identifiers: readonly NormalizedExternalIdentifier[],
): Result<void> {
  const namespaces = new Set<string>();
  for (const identifier of identifiers) {
    if (namespaces.has(identifier.namespace)) {
      return err(DUPLICATE_IDENTIFIERS);
    }
    namespaces.add(identifier.namespace);
  }

  return ok(undefined);
}

function ownerKey(owner: AssetOwnerAssignment): string {
  if (owner.kind === 'membership') {
    return `membership:${owner.membershipId}:${owner.role}`;
  }

  return `team:${owner.teamId}:${owner.role}`;
}

function uniqueIds(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

function isRootPrismaClient(client: PrismaClientLike): client is PrismaClient {
  return client instanceof PrismaClient;
}
