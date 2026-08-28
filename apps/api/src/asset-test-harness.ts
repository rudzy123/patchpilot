import { randomUUID } from 'node:crypto';

import {
  ASSET_NAME_CONFLICT,
  boundPageSize,
  createSystemClock,
  err,
  JSON_SCHEMA_VERSION_V1,
  ok,
  type AppendAuditEventInput,
  type AssetDetailRecord,
  type AssetListQuery,
  type AssetOwnerAssignment,
  type AssetRepository,
  type AssetSummaryRecord,
  type AuditEventRecord,
  type Clock,
  type EnvironmentRecord,
  type EnvironmentRepository,
  type MembershipRecord,
  type MembershipRepository,
  type NormalizedCreateAssetCommand,
  type NormalizedUpdateAssetCommand,
  type PageRequest,
  type PersistenceUnitOfWork,
  type RepositoryBundle,
  type TeamRecord,
  type TeamRepository,
} from '@patchpilot/domain';

import { createAssetRuntime, type AssetRuntime } from './asset-runtime.js';

const NOW = new Date('2026-08-28T14:00:00.000Z');

export type MemoryAssetInventory = {
  assets: Map<string, AssetDetailRecord>;
  environments: Map<string, EnvironmentRecord>;
  teams: Map<string, TeamRecord>;
  memberships: Map<string, MembershipRecord & { displayName: string }>;
  auditEvents: AuditEventRecord[];
  runtime: AssetRuntime;
  seedEnvironment(input: {
    organizationId: string;
    name: string;
    slug: string;
    status?: EnvironmentRecord['status'];
    sensitivityClass?: EnvironmentRecord['sensitivityClass'];
  }): EnvironmentRecord;
  seedTeam(input: {
    organizationId: string;
    name: string;
    slug: string;
    status?: TeamRecord['status'];
  }): TeamRecord;
  seedMembership(input: {
    organizationId: string;
    userId: string;
    displayName: string;
    role?: MembershipRecord['role'];
    status?: MembershipRecord['status'];
  }): MembershipRecord & { displayName: string };
  seedAsset(
    organizationId: string,
    command: NormalizedCreateAssetCommand,
  ): Promise<AssetDetailRecord>;
};

export function createMemoryAssetInventory(
  clock: Clock = createSystemClock(),
): MemoryAssetInventory {
  const assetRows = new Map<string, AssetDetailRecord>();
  const environmentRows = new Map<string, EnvironmentRecord>();
  const teamRows = new Map<string, TeamRecord>();
  const membershipRows = new Map<string, MembershipRecord & { displayName: string }>();
  const auditEvents: AuditEventRecord[] = [];

  const environments = createMemoryEnvironments(environmentRows);
  const teams = createMemoryTeams(teamRows);
  const memberships = createMemoryMemberships(membershipRows);
  const assets = createMemoryAssets({
    assetRows,
    environmentRows,
    teamRows,
    membershipRows,
  });
  const audit = {
    async append(input: AppendAuditEventInput) {
      const record: AuditEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        actorUserId: input.actorUserId ?? null,
        actorMembershipId: input.actorMembershipId ?? null,
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? clock.now(),
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        sourceIp: input.sourceIp ?? null,
        userAgent: input.userAgent ?? null,
        payload: input.payload,
        schemaVersion: input.schemaVersion ?? JSON_SCHEMA_VERSION_V1,
        retentionCategory: input.retentionCategory ?? 'security',
      };
      auditEvents.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };

  const bundle = {
    environments,
    teams,
    memberships,
    assets,
    auditEvents: audit,
  };

  const unitOfWork: PersistenceUnitOfWork = {
    async runInTransaction(work) {
      const snapshot = {
        assets: [...assetRows.entries()].map(([id, asset]) => [id, cloneAsset(asset)] as const),
        audits: [...auditEvents],
      };
      try {
        return await work(bundle as unknown as RepositoryBundle);
      } catch (error) {
        assetRows.clear();
        for (const [id, asset] of snapshot.assets) {
          assetRows.set(id, cloneAsset(asset));
        }
        auditEvents.splice(0, auditEvents.length, ...snapshot.audits);
        throw error;
      }
    },
  };

  const inventory: MemoryAssetInventory = {
    assets: assetRows,
    environments: environmentRows,
    teams: teamRows,
    memberships: membershipRows,
    auditEvents,
    runtime: createAssetRuntime({
      assets,
      environments,
      teams,
      memberships,
      unitOfWork,
      clock,
    }),
    seedEnvironment(input) {
      const record: EnvironmentRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        name: input.name,
        slug: input.slug,
        sensitivityClass: input.sensitivityClass ?? 'production',
        status: input.status ?? 'active',
        version: 1,
        createdAt: NOW,
        updatedAt: NOW,
      };
      environmentRows.set(record.id, record);
      return record;
    },
    seedTeam(input) {
      const record: TeamRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        name: input.name,
        slug: input.slug,
        status: input.status ?? 'active',
        version: 1,
        createdAt: NOW,
        updatedAt: NOW,
      };
      teamRows.set(record.id, record);
      return record;
    },
    seedMembership(input) {
      const record: MembershipRecord & { displayName: string } = {
        id: randomUUID(),
        organizationId: input.organizationId,
        userId: input.userId,
        role: input.role ?? 'member',
        status: input.status ?? 'active',
        invitedAt: null,
        joinedAt: NOW,
        revokedAt: input.status === 'revoked' ? NOW : null,
        version: 1,
        createdAt: NOW,
        updatedAt: NOW,
        displayName: input.displayName,
      };
      membershipRows.set(record.id, record);
      return record;
    },
    async seedAsset(organizationId, command) {
      const created = await assets.createAggregate(organizationId, command);
      if (!created.ok) {
        throw new Error(created.error.message);
      }
      return created.value;
    },
  };

  return inventory;
}

function createMemoryEnvironments(
  rows: Map<string, EnvironmentRecord>,
): Pick<EnvironmentRepository, 'findById' | 'listActiveOptions'> {
  return {
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return { ...found };
    },
    async listActiveOptions(organizationId, page) {
      return paginate(
        [...rows.values()].filter(
          (row) => row.organizationId === organizationId && row.status === 'active',
        ),
        (row) => row.id,
        page,
        (row) => ({
          id: row.id,
          name: row.name,
          slug: row.slug,
          sensitivityClass: row.sensitivityClass,
        }),
      );
    },
  };
}

function createMemoryTeams(
  rows: Map<string, TeamRecord>,
): Pick<TeamRepository, 'findById' | 'listActiveOptions'> {
  return {
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return { ...found };
    },
    async listActiveOptions(organizationId, page) {
      return paginate(
        [...rows.values()].filter(
          (row) => row.organizationId === organizationId && row.status === 'active',
        ),
        (row) => row.id,
        page,
        (row) => ({ id: row.id, name: row.name, slug: row.slug }),
      );
    },
  };
}

function createMemoryMemberships(
  rows: Map<string, MembershipRecord & { displayName: string }>,
): Pick<MembershipRepository, 'findById' | 'listActiveOptions'> {
  return {
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      const { displayName: _displayName, ...record } = found;
      return { ...record };
    },
    async listActiveOptions(organizationId, page) {
      return paginate(
        [...rows.values()].filter(
          (row) => row.organizationId === organizationId && row.status === 'active',
        ),
        (row) => row.id,
        page,
        (row) => ({
          membershipId: row.id,
          displayName: row.displayName,
          role: row.role,
        }),
      );
    },
  };
}

function createMemoryAssets(state: {
  assetRows: Map<string, AssetDetailRecord>;
  environmentRows: Map<string, EnvironmentRecord>;
  teamRows: Map<string, TeamRecord>;
  membershipRows: Map<string, MembershipRecord & { displayName: string }>;
}): Pick<
  AssetRepository,
  | 'createAggregate'
  | 'findDetailById'
  | 'listForOrganization'
  | 'compareAndSetUpdate'
  | 'compareAndSetArchive'
> {
  return {
    async createAggregate(organizationId, command) {
      if (hasActiveNameConflict(state.assetRows, organizationId, command.name)) {
        return err(ASSET_NAME_CONFLICT);
      }
      const detail = materializeCreatedAsset(state, organizationId, command);
      state.assetRows.set(detail.id, detail);
      return ok(cloneAsset(detail));
    },
    async findDetailById(organizationId, id) {
      const found = state.assetRows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return cloneAsset(found);
    },
    async listForOrganization(organizationId, query) {
      return listAssets(state.assetRows, organizationId, query);
    },
    async compareAndSetUpdate(organizationId, assetId, command) {
      const current = state.assetRows.get(assetId);
      if (current === undefined || current.organizationId !== organizationId) {
        return ok({ kind: 'not_found' as const });
      }
      if (current.lifecycleStatus === 'archived') {
        return ok({ kind: 'archived' as const, asset: cloneAsset(current) });
      }
      if (current.version !== command.expectedVersion) {
        return ok({ kind: 'version_conflict' as const, asset: cloneAsset(current) });
      }
      if (
        command.name !== undefined &&
        hasActiveNameConflict(state.assetRows, organizationId, command.name, assetId)
      ) {
        return err(ASSET_NAME_CONFLICT);
      }

      applyScalarUpdate(state, current, command);
      current.version += 1;
      current.updatedAt = NOW;
      if (command.owners !== undefined) {
        current.owners = command.owners.map((owner) => toOwnerView(state, owner));
      }
      if (command.tags !== undefined) {
        current.tags = [...command.tags];
      }
      if (command.externalIdentifiers !== undefined) {
        current.identifiers = command.externalIdentifiers.map((identifier) => ({
          id: randomUUID(),
          organizationId,
          assetId,
          namespace: identifier.namespace,
          identifier: identifier.identifier,
          createdAt: NOW,
        }));
      }
      return ok({ kind: 'updated' as const, asset: cloneAsset(current) });
    },
    async compareAndSetArchive(organizationId, assetId, expectedVersion, archivedAt) {
      const current = state.assetRows.get(assetId);
      if (current === undefined || current.organizationId !== organizationId) {
        return { kind: 'not_found' as const };
      }
      if (current.lifecycleStatus === 'archived') {
        return { kind: 'archived' as const, asset: cloneAsset(current) };
      }
      if (current.version !== expectedVersion) {
        return { kind: 'version_conflict' as const, asset: cloneAsset(current) };
      }
      current.lifecycleStatus = 'archived';
      current.archivedAt = archivedAt ?? NOW;
      current.version += 1;
      current.updatedAt = NOW;
      return { kind: 'updated' as const, asset: cloneAsset(current) };
    },
  };
}

function listAssets(
  rows: Map<string, AssetDetailRecord>,
  organizationId: string,
  query: AssetListQuery | undefined,
) {
  const lifecycle = query?.lifecycleStatus ?? 'active';
  let items = [...rows.values()]
    .filter((asset) => asset.organizationId === organizationId)
    .filter((asset) => lifecycle === 'all' || asset.lifecycleStatus === lifecycle);

  if (query?.environmentId !== undefined) {
    items = items.filter((asset) => asset.environment?.id === query.environmentId);
  }
  if (query?.assetType !== undefined) {
    items = items.filter((asset) => asset.assetType === query.assetType);
  }
  if (query?.businessCriticality !== undefined) {
    items = items.filter((asset) => asset.businessCriticality === query.businessCriticality);
  }
  if (query?.internetExposure !== undefined) {
    items = items.filter((asset) => asset.internetExposure === query.internetExposure);
  }
  if (query?.owningTeamId !== undefined) {
    items = items.filter((asset) => asset.owningTeam?.id === query.owningTeamId);
  }
  if (query?.tag !== undefined) {
    items = items.filter((asset) => asset.tags.includes(query.tag ?? ''));
  }
  if (query?.namePrefix !== undefined) {
    const prefix = query.namePrefix.toLowerCase();
    items = items.filter((asset) => asset.name.toLowerCase().startsWith(prefix));
  }

  items.sort((left, right) => {
    const name = left.name.toLowerCase().localeCompare(right.name.toLowerCase());
    return name === 0 ? left.id.localeCompare(right.id) : name;
  });

  if (query?.cursor !== undefined) {
    items = items.filter((asset) => {
      const name = asset.name.toLowerCase();
      const cursorName = query.cursor?.n.toLowerCase() ?? '';
      return name > cursorName || (name === cursorName && asset.id > (query.cursor?.i ?? ''));
    });
  }

  const limit = query?.limit ?? 20;
  const pageItems = items.slice(0, limit);
  const last = pageItems[pageItems.length - 1];
  return {
    items: pageItems.map(toSummary),
    nextCursor:
      items.length > limit && last !== undefined
        ? { v: 1 as const, n: last.name, i: last.id }
        : undefined,
  };
}

function hasActiveNameConflict(
  rows: Map<string, AssetDetailRecord>,
  organizationId: string,
  name: string,
  exceptId?: string,
): boolean {
  const normalized = name.toLowerCase();
  return [...rows.values()].some(
    (asset) =>
      asset.organizationId === organizationId &&
      asset.lifecycleStatus === 'active' &&
      asset.id !== exceptId &&
      asset.name.toLowerCase() === normalized,
  );
}

function materializeCreatedAsset(
  state: {
    environmentRows: Map<string, EnvironmentRecord>;
    teamRows: Map<string, TeamRecord>;
    membershipRows: Map<string, MembershipRecord & { displayName: string }>;
  },
  organizationId: string,
  command: NormalizedCreateAssetCommand,
): AssetDetailRecord {
  const id = randomUUID();
  const environment =
    command.environmentId === undefined
      ? null
      : (state.environmentRows.get(command.environmentId) ?? null);
  const owningTeam =
    command.owningTeamId === undefined ? null : (state.teamRows.get(command.owningTeamId) ?? null);

  return {
    id,
    organizationId,
    name: command.name,
    assetType: command.assetType,
    lifecycleStatus: 'active',
    environment:
      environment === null
        ? null
        : {
            id: environment.id,
            name: environment.name,
            sensitivityClass: environment.sensitivityClass,
          },
    owningTeam: owningTeam === null ? null : { id: owningTeam.id, name: owningTeam.name },
    businessCriticality: command.businessCriticality,
    internetExposure: command.internetExposure,
    dataClassification: command.dataClassification,
    tags: [...command.tags],
    lastObservedAt: null,
    version: 1,
    updatedAt: NOW,
    description: command.description ?? null,
    repositoryUrl: command.repositoryUrl ?? null,
    deploymentContext: command.deploymentContext ?? null,
    lastSuccessfulSbomIngestionId: null,
    lastSuccessfulSbomIngestionAt: null,
    archivedAt: null,
    owners: command.owners.map((owner) => toOwnerView(state, owner)),
    identifiers: command.externalIdentifiers.map((identifier) => ({
      id: randomUUID(),
      organizationId,
      assetId: id,
      namespace: identifier.namespace,
      identifier: identifier.identifier,
      createdAt: NOW,
    })),
    createdAt: NOW,
  };
}

function applyScalarUpdate(
  state: {
    environmentRows: Map<string, EnvironmentRecord>;
    teamRows: Map<string, TeamRecord>;
  },
  current: AssetDetailRecord,
  command: NormalizedUpdateAssetCommand,
): void {
  if (command.name !== undefined) {
    current.name = command.name;
  }
  if (command.assetType !== undefined) {
    current.assetType = command.assetType;
  }
  if (command.businessCriticality !== undefined) {
    current.businessCriticality = command.businessCriticality;
  }
  if (command.internetExposure !== undefined) {
    current.internetExposure = command.internetExposure;
  }
  if (command.dataClassification !== undefined) {
    current.dataClassification = command.dataClassification;
  }
  if (command.environmentId !== undefined) {
    if (command.environmentId === null) {
      current.environment = null;
    } else {
      const environment = state.environmentRows.get(command.environmentId);
      current.environment =
        environment === undefined
          ? null
          : {
              id: environment.id,
              name: environment.name,
              sensitivityClass: environment.sensitivityClass,
            };
    }
  }
  if (command.owningTeamId !== undefined) {
    if (command.owningTeamId === null) {
      current.owningTeam = null;
    } else {
      const team = state.teamRows.get(command.owningTeamId);
      current.owningTeam = team === undefined ? null : { id: team.id, name: team.name };
    }
  }
  if (command.description !== undefined) {
    current.description = command.description;
  }
  if (command.repositoryUrl !== undefined) {
    current.repositoryUrl = command.repositoryUrl;
  }
  if (command.deploymentContext !== undefined) {
    current.deploymentContext = command.deploymentContext;
  }
}

function toOwnerView(
  state: {
    teamRows: Map<string, TeamRecord>;
    membershipRows: Map<string, MembershipRecord & { displayName: string }>;
  },
  owner: AssetOwnerAssignment,
) {
  if (owner.kind === 'membership') {
    const membership = state.membershipRows.get(owner.membershipId);
    return {
      kind: 'membership' as const,
      id: randomUUID(),
      membershipId: owner.membershipId,
      userId: membership?.userId ?? randomUUID(),
      displayName: membership?.displayName ?? 'Unknown',
      role: owner.role,
    };
  }

  const team = state.teamRows.get(owner.teamId);
  return {
    kind: 'team' as const,
    id: randomUUID(),
    teamId: owner.teamId,
    name: team?.name ?? 'Unknown',
    role: owner.role,
  };
}

function toSummary(asset: AssetDetailRecord): AssetSummaryRecord {
  return {
    id: asset.id,
    organizationId: asset.organizationId,
    name: asset.name,
    assetType: asset.assetType,
    lifecycleStatus: asset.lifecycleStatus,
    environment: asset.environment,
    owningTeam: asset.owningTeam,
    businessCriticality: asset.businessCriticality,
    internetExposure: asset.internetExposure,
    dataClassification: asset.dataClassification,
    tags: [...asset.tags],
    lastObservedAt: asset.lastObservedAt,
    version: asset.version,
    updatedAt: asset.updatedAt,
  };
}

function cloneAsset(asset: AssetDetailRecord): AssetDetailRecord {
  return {
    ...asset,
    tags: [...asset.tags],
    owners: asset.owners.map((owner) => ({ ...owner })),
    identifiers: asset.identifiers.map((identifier) => ({ ...identifier })),
    environment: asset.environment === null ? null : { ...asset.environment },
    owningTeam: asset.owningTeam === null ? null : { ...asset.owningTeam },
  };
}

function paginate<T, U extends { id?: string; membershipId?: string }>(
  items: T[],
  key: (item: T) => string,
  page: PageRequest | undefined,
  map: (item: T) => U,
) {
  const limit = boundPageSize(page?.limit);
  const sorted = [...items].sort((left, right) => key(left).localeCompare(key(right)));
  const after = page?.afterId;
  const filtered =
    after === undefined ? sorted : sorted.filter((item) => key(item).localeCompare(after) > 0);
  const mapped = filtered.map(map);
  if (mapped.length > limit) {
    const pageItems = mapped.slice(0, limit);
    const last = pageItems[pageItems.length - 1];
    const cursorId = last?.id ?? last?.membershipId;
    return {
      items: pageItems,
      nextCursor: cursorId === undefined ? undefined : { id: cursorId },
    };
  }

  return { items: mapped, nextCursor: undefined };
}
