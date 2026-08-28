import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { Clock } from '../clock.js';
import type {
  AppendAuditEventInput,
  AssetRepository,
  AuditAppendRepository,
  CreateOutboxEventInput,
  EnvironmentRepository,
  MembershipRepository,
  OutboxRepository,
  PersistenceUnitOfWork,
  RepositoryBundle,
  TeamRepository,
} from '../ports.js';
import type {
  AuditEventRecord,
  EnvironmentRecord,
  MembershipRecord,
  OutboxEventRecord,
  TeamRecord,
} from '../records.js';
import {
  ASSET_ARCHIVED,
  ASSET_NOT_FOUND,
  ASSET_VERSION_CONFLICT,
  ENVIRONMENT_NOT_ASSIGNABLE,
  MEMBERSHIP_NOT_ASSIGNABLE,
  ORGANIZATION_CONTEXT_REQUIRED,
  PERMISSION_DENIED,
  TEAM_NOT_ASSIGNABLE,
  assetAuditActions,
  createArchiveAssetUseCase,
  createCreateAssetUseCase,
  createGetAssetUseCase,
  createListAssetEnvironmentsUseCase,
  createListAssetMembershipsUseCase,
  createListAssetTeamsUseCase,
  createListAssetsUseCase,
  createUpdateAssetUseCase,
  type AssetActor,
  type AssetDetailRecord,
  type AssetOwnerAssignment,
  type AssetSummaryRecord,
  type NormalizedCreateAssetCommand,
  type NormalizedUpdateAssetCommand,
} from './index.js';

const NOW = new Date('2026-08-28T13:00:00.000Z');
const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const USER_A = '11111111-1111-4111-8111-111111111111';
const SESSION_A = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP_A = '33333333-3333-4333-8333-333333333333';
const MEMBERSHIP_B = '44444444-4444-4444-8444-444444444444';
const REVOKED_MEMBERSHIP = '55555555-5555-4555-8555-555555555555';
const TEAM_A = '66666666-6666-4666-8666-666666666666';
const ARCHIVED_TEAM = '77777777-7777-4777-8777-777777777777';
const ENV_A = '88888888-8888-4888-8888-888888888888';
const ARCHIVED_ENV = '99999999-9999-4999-8999-999999999999';
const CORRELATION = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const SECRET_DESCRIPTION = 'SECRET_DESCRIPTION_TEXT';
const SECRET_REPO = 'https://secret.example.invalid/repo';
const SECRET_CONTEXT = 'SECRET_DEPLOYMENT_CONTEXT';
const SECRET_IDENTIFIER = 'SECRET_IDENTIFIER_VALUE';

describe('asset application use cases', () => {
  it('requires organization context before checking permissions', async () => {
    const inventory = createInventory();
    const actor = actorWithoutOrganization();
    const listed = await inventory.list.execute({ actor });
    const created = await inventory.create.execute({
      actor,
      correlationId: CORRELATION,
      fields: { name: 'Payments', assetType: 'application' },
    });

    expect(listed).toEqual({ ok: false, error: ORGANIZATION_CONTEXT_REQUIRED });
    expect(created).toEqual({ ok: false, error: ORGANIZATION_CONTEXT_REQUIRED });
  });

  it('allows viewer and member read access and denies their mutations', async () => {
    const inventory = createInventory();
    inventory.seedAsset(ORG_A, { name: 'Readable' });
    const viewer = actorWithPermissions(ORG_A, ['asset:read']);
    const member = actorWithPermissions(ORG_A, ['asset:read']);

    expect((await inventory.list.execute({ actor: viewer })).ok).toBe(true);
    expect(
      (await inventory.get.execute({ actor: member, assetId: inventory.assetId('Readable') })).ok,
    ).toBe(true);
    expect((await inventory.listEnvironments.execute({ actor: viewer })).ok).toBe(true);
    expect((await inventory.listTeams.execute({ actor: member })).ok).toBe(true);
    expect((await inventory.listMemberships.execute({ actor: viewer })).ok).toBe(true);

    const viewerCreate = await inventory.create.execute({
      actor: viewer,
      correlationId: CORRELATION,
      fields: { name: 'Denied', assetType: 'service' },
    });
    const memberUpdate = await inventory.update.execute({
      actor: member,
      assetId: inventory.assetId('Readable'),
      correlationId: CORRELATION,
      fields: { expectedVersion: 1, name: 'Nope' },
    });
    expect(viewerCreate).toEqual({ ok: false, error: PERMISSION_DENIED });
    expect(memberUpdate).toEqual({ ok: false, error: PERMISSION_DENIED });
  });

  it('allows admin and owner mutations', async () => {
    const inventory = createInventory();
    const admin = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);
    const owner = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);

    const created = await inventory.create.execute({
      actor: admin,
      correlationId: randomUUID(),
      fields: { name: 'Admin App', assetType: 'application' },
    });
    expect(created.ok).toBe(true);

    const archived = await inventory.archive.execute({
      actor: owner,
      assetId: created.ok ? created.value.id : '',
      correlationId: randomUUID(),
      expectedVersion: 1,
    });
    expect(archived.ok).toBe(true);
    if (archived.ok) {
      expect(archived.value.lifecycleStatus).toBe('archived');
      expect(archived.value.archivedAt).toEqual(NOW);
      expect(archived.value.version).toBe(2);
    }
  });

  it('hides cross-tenant assets behind not-found', async () => {
    const inventory = createInventory();
    const foreign = inventory.seedAsset(ORG_B, { name: 'Foreign' });
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);

    const listed = await inventory.list.execute({ actor });
    const got = await inventory.get.execute({ actor, assetId: foreign.id });
    const updated = await inventory.update.execute({
      actor,
      assetId: foreign.id,
      correlationId: CORRELATION,
      fields: { expectedVersion: 1, name: 'Stolen' },
    });

    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.value.items.map((item) => item.id)).not.toContain(foreign.id);
    }
    expect(got).toEqual({ ok: false, error: ASSET_NOT_FOUND });
    expect(updated).toEqual({ ok: false, error: ASSET_NOT_FOUND });
  });

  it('rejects revoked membership, archived team, and archived environment assignments', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);

    const revoked = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      fields: {
        name: 'Bad Membership',
        assetType: 'application',
        owners: [{ kind: 'membership', membershipId: REVOKED_MEMBERSHIP, role: 'technical' }],
      },
    });
    const archivedTeam = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      fields: {
        name: 'Bad Team',
        assetType: 'application',
        owningTeamId: ARCHIVED_TEAM,
      },
    });
    const archivedEnvironment = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      fields: {
        name: 'Bad Environment',
        assetType: 'application',
        environmentId: ARCHIVED_ENV,
      },
    });

    expect(revoked).toEqual({ ok: false, error: MEMBERSHIP_NOT_ASSIGNABLE });
    expect(archivedTeam).toEqual({ ok: false, error: TEAM_NOT_ASSIGNABLE });
    expect(archivedEnvironment).toEqual({ ok: false, error: ENVIRONMENT_NOT_ASSIGNABLE });
  });

  it('validates active assignment targets on create and update', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);
    const created = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      fields: {
        name: 'Valid Targets',
        assetType: 'application',
        environmentId: ENV_A,
        owningTeamId: TEAM_A,
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' }],
      },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const updated = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: {
        expectedVersion: 1,
        environmentId: ARCHIVED_ENV,
      },
    });
    expect(updated).toEqual({ ok: false, error: ENVIRONMENT_NOT_ASSIGNABLE });
    expect(created.value.environment?.id).toBe(ENV_A);
  });

  it('rolls back create, update, and archive when audit append fails', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);

    inventory.failNextAudit();
    await expect(
      inventory.create.execute({
        actor,
        correlationId: randomUUID(),
        fields: { name: 'Rollback Create', assetType: 'application' },
      }),
    ).rejects.toThrow('audit append failed');
    expect(inventory.assets()).toEqual([]);

    const seeded = inventory.seedAsset(ORG_A, { name: 'Rollback Target' });
    inventory.failNextAudit();
    await expect(
      inventory.update.execute({
        actor,
        assetId: seeded.id,
        correlationId: randomUUID(),
        fields: { expectedVersion: 1, name: 'Should Roll Back' },
      }),
    ).rejects.toThrow('audit append failed');
    expect(inventory.assetById(seeded.id)?.name).toBe('Rollback Target');
    expect(inventory.assetById(seeded.id)?.version).toBe(1);

    inventory.failNextAudit();
    await expect(
      inventory.archive.execute({
        actor,
        assetId: seeded.id,
        correlationId: randomUUID(),
        expectedVersion: 1,
      }),
    ).rejects.toThrow('audit append failed');
    expect(inventory.assetById(seeded.id)?.lifecycleStatus).toBe('active');
    expect(inventory.auditEvents()).toEqual([]);
  });

  it('applies scalar, collection, compound, and no-op updates', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);
    const created = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      requestId: 'req-create',
      fields: {
        name: 'Mutable',
        assetType: 'application',
        description: SECRET_DESCRIPTION,
        repositoryUrl: SECRET_REPO,
        deploymentContext: SECRET_CONTEXT,
        tags: ['alpha'],
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' }],
        externalIdentifiers: [{ namespace: 'cmdb', identifier: SECRET_IDENTIFIER }],
      },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const scalar = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: { expectedVersion: 1, name: 'Mutable Scalar' },
    });
    expect(scalar.ok).toBe(true);
    if (scalar.ok) {
      expect(scalar.value.name).toBe('Mutable Scalar');
      expect(scalar.value.version).toBe(2);
      expect(scalar.value.tags).toEqual(['alpha']);
    }

    const ownersOnly = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: {
        expectedVersion: 2,
        owners: [{ kind: 'team', teamId: TEAM_A, role: 'business' }],
      },
    });
    expect(ownersOnly.ok).toBe(true);
    if (ownersOnly.ok) {
      expect(ownersOnly.value.version).toBe(3);
      expect(ownersOnly.value.name).toBe('Mutable Scalar');
      expect(ownersOnly.value.owners).toEqual([
        expect.objectContaining({ kind: 'team', teamId: TEAM_A, role: 'business' }),
      ]);
    }

    const tagsOnly = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: { expectedVersion: 3, tags: ['alpha', 'beta'] },
    });
    expect(tagsOnly.ok).toBe(true);
    if (tagsOnly.ok) {
      expect(tagsOnly.value.version).toBe(4);
      expect(tagsOnly.value.tags).toEqual(['alpha', 'beta']);
    }

    const identifiersOnly = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: {
        expectedVersion: 4,
        externalIdentifiers: [{ namespace: 'servicenow', identifier: 'sn-1' }],
      },
    });
    expect(identifiersOnly.ok).toBe(true);
    if (identifiersOnly.ok) {
      expect(identifiersOnly.value.version).toBe(5);
      expect(identifiersOnly.value.identifiers).toEqual([
        expect.objectContaining({ namespace: 'servicenow', identifier: 'sn-1' }),
      ]);
    }

    const compound = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: {
        expectedVersion: 5,
        businessCriticality: 'high',
        tags: ['gamma'],
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'security' }],
      },
    });
    expect(compound.ok).toBe(true);
    if (compound.ok) {
      expect(compound.value.version).toBe(6);
      expect(compound.value.businessCriticality).toBe('high');
      expect(compound.value.tags).toEqual(['gamma']);
    }

    const noop = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: {
        expectedVersion: 6,
        name: 'Mutable Scalar',
        tags: ['gamma'],
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'security' }],
        externalIdentifiers: [{ namespace: 'servicenow', identifier: 'sn-1' }],
      },
    });
    expect(noop.ok).toBe(true);
    if (noop.ok) {
      expect(noop.value.version).toBe(6);
      expect(noop.value.updatedAt).toEqual(compound.ok ? compound.value.updatedAt : NOW);
    }
  });

  it('rejects stale versions, archived updates, and repeat archives', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);
    const created = await inventory.create.execute({
      actor,
      correlationId: randomUUID(),
      fields: { name: 'Lifecycle', assetType: 'service' },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const stale = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: { expectedVersion: 99, name: 'Stale' },
    });
    expect(stale).toEqual({ ok: false, error: ASSET_VERSION_CONFLICT });

    const archived = await inventory.archive.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      expectedVersion: 1,
    });
    expect(archived.ok).toBe(true);

    const updateArchived = await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      fields: { expectedVersion: 2, name: 'Still Archived' },
    });
    expect(updateArchived).toEqual({ ok: false, error: ASSET_ARCHIVED });

    const repeat = await inventory.archive.execute({
      actor,
      assetId: created.value.id,
      correlationId: randomUUID(),
      expectedVersion: 2,
    });
    expect(repeat).toEqual({ ok: false, error: ASSET_ARCHIVED });
  });

  it('writes redacted audit metadata and never writes OutboxEvent', async () => {
    const inventory = createInventory();
    const actor = actorWithPermissions(ORG_A, ['asset:read', 'asset:manage']);
    const created = await inventory.create.execute({
      actor,
      correlationId: 'create-correlation',
      fields: {
        name: 'Audited',
        assetType: 'application',
        description: SECRET_DESCRIPTION,
        repositoryUrl: SECRET_REPO,
        deploymentContext: SECRET_CONTEXT,
        environmentId: ENV_A,
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' }],
        tags: ['alpha'],
        externalIdentifiers: [{ namespace: 'cmdb', identifier: SECRET_IDENTIFIER }],
      },
    });
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'scalar-correlation',
      fields: { expectedVersion: 1, name: 'Audited Scalar' },
    });
    await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'owners-correlation',
      fields: {
        expectedVersion: 2,
        owners: [{ kind: 'team', teamId: TEAM_A, role: 'business' }],
      },
    });
    await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'tags-correlation',
      fields: { expectedVersion: 3, tags: ['beta'] },
    });
    await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'identifiers-correlation',
      fields: {
        expectedVersion: 4,
        externalIdentifiers: [{ namespace: 'cmdb', identifier: 'other' }],
      },
    });
    await inventory.update.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'compound-correlation',
      fields: {
        expectedVersion: 5,
        internetExposure: 'internal',
        tags: ['gamma'],
        owners: [{ kind: 'membership', membershipId: MEMBERSHIP_A, role: 'security' }],
      },
    });
    await inventory.archive.execute({
      actor,
      assetId: created.value.id,
      correlationId: 'archive-correlation',
      expectedVersion: 6,
    });

    const actions = inventory.auditEvents().map((event) => event.action);
    expect(actions).toEqual([
      assetAuditActions.created,
      assetAuditActions.updated,
      assetAuditActions.ownersUpdated,
      assetAuditActions.tagsUpdated,
      assetAuditActions.identifiersUpdated,
      assetAuditActions.updated,
      assetAuditActions.ownersUpdated,
      assetAuditActions.tagsUpdated,
      assetAuditActions.archived,
    ]);

    const createdAudit = inventory.auditEvents()[0];
    expect(createdAudit?.payload.metadata).toEqual({
      assetType: 'application',
      hasEnvironment: true,
      hasOwningTeam: false,
      hasDescription: true,
      hasRepositoryUrl: true,
      hasDeploymentContext: true,
      ownerCount: 1,
      tagCount: 1,
      identifierCount: 1,
    });

    const serialized = JSON.stringify(inventory.auditEvents().map((event) => event.payload));
    expect(serialized).not.toContain(SECRET_DESCRIPTION);
    expect(serialized).not.toContain(SECRET_REPO);
    expect(serialized).not.toContain(SECRET_CONTEXT);
    expect(serialized).not.toContain(SECRET_IDENTIFIER);
    expect(serialized).not.toContain('Audited Scalar');
    expect(inventory.outboxEvents()).toEqual([]);
    expect(createdAudit?.actorUserId).toBe(USER_A);
    expect(createdAudit?.actorMembershipId).toBe(MEMBERSHIP_A);
    expect(createdAudit?.organizationId).toBe(ORG_A);
    expect(createdAudit?.subjectType).toBe('asset');
  });
});

function actorWithoutOrganization(): AssetActor {
  return {
    userId: USER_A,
    sessionId: SESSION_A,
    organizationId: null,
    membershipId: null,
    permissions: [],
  };
}

function actorWithPermissions(organizationId: string, permissions: readonly string[]): AssetActor {
  return {
    userId: USER_A,
    sessionId: SESSION_A,
    organizationId,
    membershipId: MEMBERSHIP_A,
    permissions,
  };
}

function createInventory() {
  const state = createFakeState();
  const clock: Clock = { now: () => new Date(NOW.getTime()) };
  const unitOfWork = createFakeUnitOfWork(state);
  const create = createCreateAssetUseCase({ unitOfWork, clock });
  const update = createUpdateAssetUseCase({ unitOfWork, clock });
  const archive = createArchiveAssetUseCase({ unitOfWork, clock });
  const list = createListAssetsUseCase({ assets: state.assets });
  const get = createGetAssetUseCase({ assets: state.assets });
  const listEnvironments = createListAssetEnvironmentsUseCase({
    environments: state.environments,
  });
  const listTeams = createListAssetTeamsUseCase({ teams: state.teams });
  const listMemberships = createListAssetMembershipsUseCase({ memberships: state.memberships });

  return {
    list,
    get,
    create,
    update,
    archive,
    listEnvironments,
    listTeams,
    listMemberships,
    failNextAudit() {
      state.audit.failNextAppend = true;
    },
    seedAsset(organizationId: string, fields: { name: string }): AssetDetailRecord {
      const detail = baseAsset(organizationId, fields.name);
      state.assetRows.set(detail.id, detail);
      return cloneAsset(detail);
    },
    assetId(name: string): string {
      const found = [...state.assetRows.values()].find((asset) => asset.name === name);
      if (found === undefined) {
        throw new Error(`Missing seeded asset ${name}`);
      }
      return found.id;
    },
    assetById(id: string): AssetDetailRecord | undefined {
      const found = state.assetRows.get(id);
      return found === undefined ? undefined : cloneAsset(found);
    },
    assets(): AssetDetailRecord[] {
      return [...state.assetRows.values()].map(cloneAsset);
    },
    auditEvents(): AuditEventRecord[] {
      return state.audit.events.map((event) => ({ ...event, payload: { ...event.payload } }));
    },
    outboxEvents(): OutboxEventRecord[] {
      return [...state.outbox.events];
    },
  };
}

type InventoryState = {
  assetRows: Map<string, AssetDetailRecord>;
  environmentRows: Map<string, EnvironmentRecord>;
  teamRows: Map<string, TeamRecord>;
  membershipRows: Map<string, MembershipRecord & { displayName: string }>;
  assets: AssetRepository;
  environments: EnvironmentRepository;
  teams: TeamRepository;
  memberships: MembershipRepository;
  audit: AuditAppendRepository & { events: AuditEventRecord[]; failNextAppend: boolean };
  outbox: OutboxRepository & { events: OutboxEventRecord[] };
};

function createFakeState(): InventoryState {
  const assetRows = new Map<string, AssetDetailRecord>();
  const environmentRows = new Map<string, EnvironmentRecord>([
    [ENV_A, environmentRecord(ORG_A, ENV_A, 'production', 'active')],
    [ARCHIVED_ENV, environmentRecord(ORG_A, ARCHIVED_ENV, 'legacy', 'archived')],
  ]);
  const teamRows = new Map<string, TeamRecord>([
    [TEAM_A, teamRecord(ORG_A, TEAM_A, 'Platform', 'active')],
    [ARCHIVED_TEAM, teamRecord(ORG_A, ARCHIVED_TEAM, 'Old', 'archived')],
  ]);
  const membershipRows = new Map<string, MembershipRecord & { displayName: string }>([
    [MEMBERSHIP_A, membershipRecord(ORG_A, MEMBERSHIP_A, USER_A, 'active', 'Ada')],
    [MEMBERSHIP_B, membershipRecord(ORG_B, MEMBERSHIP_B, USER_A, 'active', 'Other')],
    [REVOKED_MEMBERSHIP, membershipRecord(ORG_A, REVOKED_MEMBERSHIP, USER_A, 'revoked', 'Revoked')],
  ]);

  const audit: InventoryState['audit'] = {
    events: [],
    failNextAppend: false,
    async append(input: AppendAuditEventInput) {
      if (audit.failNextAppend) {
        audit.failNextAppend = false;
        throw new Error('audit append failed');
      }
      const record: AuditEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        actorUserId: input.actorUserId ?? null,
        actorMembershipId: input.actorMembershipId ?? null,
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? NOW,
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        sourceIp: input.sourceIp ?? null,
        userAgent: input.userAgent ?? null,
        payload: input.payload,
        schemaVersion: input.schemaVersion ?? 1,
        retentionCategory: input.retentionCategory ?? 'security',
      };
      audit.events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };

  const outbox: InventoryState['outbox'] = {
    events: [],
    async create(input: CreateOutboxEventInput) {
      const record: OutboxEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        aggregateType: input.aggregateType,
        aggregateId: input.aggregateId,
        eventType: input.eventType,
        eventSchemaVersion: input.eventSchemaVersion ?? 1,
        payload: input.payload,
        dedupeKey: input.dedupeKey,
        occurredAt: input.occurredAt ?? NOW,
        availableAt: input.availableAt ?? NOW,
        claimedAt: null,
        leaseExpiresAt: null,
        processedAt: null,
        attemptCount: 0,
        lastFailureCategory: null,
        lastFailureCode: null,
        status: input.status ?? 'pending',
        createdAt: NOW,
      };
      outbox.events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };

  const state = {
    assetRows,
    environmentRows,
    teamRows,
    membershipRows,
    audit,
    outbox,
  };

  const assets = createFakeAssetRepository(state);
  const environments = createFakeEnvironmentRepository(environmentRows);
  const teams = createFakeTeamRepository(teamRows);
  const memberships = createFakeMembershipRepository(membershipRows);

  return {
    assetRows,
    environmentRows,
    teamRows,
    membershipRows,
    assets,
    environments,
    teams,
    memberships,
    audit,
    outbox,
  };
}

function createFakeUnitOfWork(state: InventoryState): PersistenceUnitOfWork {
  const bundle = {
    organizations: throwingRepo('organizations'),
    users: throwingRepo('users'),
    memberships: state.memberships,
    localCredentials: throwingRepo('localCredentials'),
    sessions: throwingRepo('sessions'),
    teams: state.teams,
    environments: state.environments,
    assets: state.assets,
    sboms: throwingRepo('sboms'),
    findings: throwingRepo('findings'),
    riskPolicies: throwingRepo('riskPolicies'),
    remediationTasks: throwingRepo('remediationTasks'),
    auditEvents: state.audit,
    outboxEvents: state.outbox,
    idempotencyRecords: throwingRepo('idempotencyRecords'),
  } as RepositoryBundle;

  return {
    async runInTransaction(work) {
      const snapshot = snapshotAssets(state);
      try {
        return await work(bundle);
      } catch (error) {
        restoreAssets(state, snapshot);
        throw error;
      }
    },
  };
}

function snapshotAssets(state: InventoryState) {
  return {
    assets: [...state.assetRows.entries()].map(([id, asset]) => [id, cloneAsset(asset)] as const),
    audit: [...state.audit.events],
    outbox: [...state.outbox.events],
  };
}

function restoreAssets(state: InventoryState, snapshot: ReturnType<typeof snapshotAssets>): void {
  state.assetRows.clear();
  for (const [id, asset] of snapshot.assets) {
    state.assetRows.set(id, cloneAsset(asset));
  }
  state.audit.events.splice(0, state.audit.events.length, ...snapshot.audit);
  state.outbox.events.splice(0, state.outbox.events.length, ...snapshot.outbox);
}

function createFakeAssetRepository(state: {
  assetRows: Map<string, AssetDetailRecord>;
  environmentRows: Map<string, EnvironmentRecord>;
  teamRows: Map<string, TeamRecord>;
  membershipRows: Map<string, MembershipRecord & { displayName: string }>;
}): AssetRepository {
  return {
    async create() {
      throw new Error('create is not used by asset use cases');
    },
    async createAggregate(organizationId, command: NormalizedCreateAssetCommand) {
      const detail = materializeCreatedAsset(state, organizationId, command);
      state.assetRows.set(detail.id, detail);
      return { ok: true, value: cloneAsset(detail) };
    },
    async findById(organizationId, id) {
      const detail = await this.findDetailById(organizationId, id);
      if (detail === undefined) {
        return undefined;
      }
      return {
        id: detail.id,
        organizationId: detail.organizationId,
        name: detail.name,
        description: detail.description,
        assetType: detail.assetType,
        lifecycleStatus: detail.lifecycleStatus,
        environmentId: detail.environment?.id ?? null,
        owningTeamId: detail.owningTeam?.id ?? null,
        businessCriticality: detail.businessCriticality,
        internetExposure: detail.internetExposure,
        dataClassification: detail.dataClassification,
        repositoryUrl: detail.repositoryUrl,
        deploymentContext: detail.deploymentContext,
        lastObservedAt: detail.lastObservedAt,
        lastSuccessfulSbomIngestionId: detail.lastSuccessfulSbomIngestionId,
        lastSuccessfulSbomIngestionAt: detail.lastSuccessfulSbomIngestionAt,
        archivedAt: detail.archivedAt,
        version: detail.version,
        createdAt: detail.createdAt,
        updatedAt: detail.updatedAt,
      };
    },
    async findDetailById(organizationId, id) {
      const found = state.assetRows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return cloneAsset(found);
    },
    async listForOrganization(organizationId, query) {
      const lifecycle = query?.lifecycleStatus ?? 'active';
      const items = [...state.assetRows.values()]
        .filter((asset) => asset.organizationId === organizationId)
        .filter((asset) => lifecycle === 'all' || asset.lifecycleStatus === lifecycle)
        .map(toSummary);
      return { items, nextCursor: undefined };
    },
    async compareAndSetUpdate(organizationId, assetId, command: NormalizedUpdateAssetCommand) {
      const current = state.assetRows.get(assetId);
      if (current === undefined || current.organizationId !== organizationId) {
        return { ok: true, value: { kind: 'not_found' as const } };
      }
      if (current.lifecycleStatus === 'archived') {
        return { ok: true, value: { kind: 'archived' as const, asset: cloneAsset(current) } };
      }
      if (current.version !== command.expectedVersion) {
        return {
          ok: true,
          value: { kind: 'version_conflict' as const, asset: cloneAsset(current) },
        };
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
      return { ok: true, value: { kind: 'updated' as const, asset: cloneAsset(current) } };
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
    async replaceOwners() {
      return { ok: true, value: undefined };
    },
    async replaceTags() {
      return { ok: true, value: undefined };
    },
    async replaceExternalIdentifiers() {
      return { ok: true, value: undefined };
    },
    async addOwner() {
      throw new Error('addOwner is not used by asset use cases');
    },
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
  if ('environmentId' in command) {
    current.environment =
      command.environmentId === null || command.environmentId === undefined
        ? null
        : environmentSummary(state.environmentRows.get(command.environmentId));
  }
  if ('owningTeamId' in command) {
    current.owningTeam =
      command.owningTeamId === null || command.owningTeamId === undefined
        ? null
        : teamSummary(state.teamRows.get(command.owningTeamId));
  }
  if ('description' in command) {
    current.description = command.description ?? null;
  }
  if ('repositoryUrl' in command) {
    current.repositoryUrl = command.repositoryUrl ?? null;
  }
  if ('deploymentContext' in command) {
    current.deploymentContext = command.deploymentContext ?? null;
  }
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
  return {
    id,
    organizationId,
    name: command.name,
    assetType: command.assetType,
    lifecycleStatus: 'active',
    environment:
      command.environmentId === undefined
        ? null
        : environmentSummary(state.environmentRows.get(command.environmentId)),
    owningTeam:
      command.owningTeamId === undefined
        ? null
        : teamSummary(state.teamRows.get(command.owningTeamId)),
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
      userId: membership?.userId ?? USER_A,
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

function createFakeEnvironmentRepository(
  rows: Map<string, EnvironmentRecord>,
): EnvironmentRepository {
  return {
    async create() {
      throw new Error('environment create is not used');
    },
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return { ...found };
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
    async listActiveOptions(organizationId) {
      const items = [...rows.values()]
        .filter((row) => row.organizationId === organizationId && row.status === 'active')
        .map((row) => ({
          id: row.id,
          name: row.name,
          slug: row.slug,
          sensitivityClass: row.sensitivityClass,
        }));
      return { items, nextCursor: undefined };
    },
  };
}

function createFakeTeamRepository(rows: Map<string, TeamRecord>): TeamRepository {
  return {
    async create() {
      throw new Error('team create is not used');
    },
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      return { ...found };
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
    async listActiveOptions(organizationId) {
      const items = [...rows.values()]
        .filter((row) => row.organizationId === organizationId && row.status === 'active')
        .map((row) => ({ id: row.id, name: row.name, slug: row.slug }));
      return { items, nextCursor: undefined };
    },
    async addMember() {
      throw new Error('addMember is not used');
    },
  };
}

function createFakeMembershipRepository(
  rows: Map<string, MembershipRecord & { displayName: string }>,
): MembershipRepository {
  return {
    async create() {
      throw new Error('membership create is not used');
    },
    async findById(organizationId, id) {
      const found = rows.get(id);
      if (found === undefined || found.organizationId !== organizationId) {
        return undefined;
      }
      const { displayName: _displayName, ...record } = found;
      return { ...record };
    },
    async findByUser() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
    async listActiveOptions(organizationId) {
      const items = [...rows.values()]
        .filter((row) => row.organizationId === organizationId && row.status === 'active')
        .map((row) => ({
          membershipId: row.id,
          displayName: row.displayName,
          role: row.role,
        }));
      return { items, nextCursor: undefined };
    },
    async listActiveInActiveOrganizationsForUser() {
      return [];
    },
    async findActiveInActiveOrganization() {
      return undefined;
    },
  };
}

function throwingRepo<T extends object>(name: string): T {
  return new Proxy(
    {},
    {
      get(_target, prop) {
        return () => {
          throw new Error(`${name}.${String(prop)} is not used by asset use cases`);
        };
      },
    },
  ) as T;
}

function baseAsset(organizationId: string, name: string): AssetDetailRecord {
  return {
    id: randomUUID(),
    organizationId,
    name,
    assetType: 'application',
    lifecycleStatus: 'active',
    environment: null,
    owningTeam: null,
    businessCriticality: 'unspecified',
    internetExposure: 'unknown',
    dataClassification: 'unspecified',
    tags: [],
    lastObservedAt: null,
    version: 1,
    updatedAt: NOW,
    description: null,
    repositoryUrl: null,
    deploymentContext: null,
    lastSuccessfulSbomIngestionId: null,
    lastSuccessfulSbomIngestionAt: null,
    archivedAt: null,
    owners: [],
    identifiers: [],
    createdAt: NOW,
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

function environmentRecord(
  organizationId: string,
  id: string,
  name: string,
  status: EnvironmentRecord['status'],
): EnvironmentRecord {
  return {
    id,
    organizationId,
    name,
    slug: name.toLowerCase(),
    sensitivityClass: 'production',
    status,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function teamRecord(
  organizationId: string,
  id: string,
  name: string,
  status: TeamRecord['status'],
): TeamRecord {
  return {
    id,
    organizationId,
    name,
    slug: name.toLowerCase().replaceAll(' ', '-'),
    status,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function membershipRecord(
  organizationId: string,
  id: string,
  userId: string,
  status: MembershipRecord['status'],
  displayName: string,
): MembershipRecord & { displayName: string } {
  return {
    id,
    organizationId,
    userId,
    role: 'admin',
    status,
    invitedAt: null,
    joinedAt: NOW,
    revokedAt: status === 'revoked' ? NOW : null,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
    displayName,
  };
}

function environmentSummary(row: EnvironmentRecord | undefined) {
  if (row === undefined) {
    return null;
  }
  return { id: row.id, name: row.name, sensitivityClass: row.sensitivityClass };
}

function teamSummary(row: TeamRecord | undefined) {
  if (row === undefined) {
    return null;
  }
  return { id: row.id, name: row.name };
}
