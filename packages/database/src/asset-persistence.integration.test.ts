import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  ASSET_NAME_CONFLICT,
  DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
  type AssetListQuery,
  type NormalizedCreateAssetCommand,
  type NormalizedUpdateAssetCommand,
} from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createPrismaUnitOfWork, createRepositories } from './repositories.js';

describe('asset repository persistence', () => {
  let databaseUrl: string;
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function createOrg(label: string) {
    return prisma.organization.create({
      data: { slug: `${label}-${randomUUID().slice(0, 8)}`, name: `Org ${label}` },
    });
  }

  async function createUser(label: string, displayName = label) {
    return prisma.user.create({
      data: {
        email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
        displayName,
      },
    });
  }

  async function createMembership(
    organizationId: string,
    userId: string,
    role: 'owner' | 'admin' | 'member' | 'viewer' = 'member',
  ) {
    return prisma.membership.create({
      data: { organizationId, userId, role },
    });
  }

  async function createTeam(organizationId: string, name: string) {
    return prisma.team.create({
      data: {
        organizationId,
        name,
        slug: `${name.toLowerCase().replaceAll(' ', '-')}-${randomUUID().slice(0, 8)}`,
      },
    });
  }

  async function createEnvironment(
    organizationId: string,
    name: string,
    sensitivityClass: 'production' | 'non_production' = 'production',
  ) {
    return prisma.environment.create({
      data: {
        organizationId,
        name,
        slug: `${name.toLowerCase().replaceAll(' ', '-')}-${randomUUID().slice(0, 8)}`,
        sensitivityClass,
      },
    });
  }

  function createCommand(
    name: string,
    overrides: Partial<NormalizedCreateAssetCommand> = {},
  ): NormalizedCreateAssetCommand {
    const command: NormalizedCreateAssetCommand = {
      name,
      assetType: overrides.assetType ?? 'application',
      businessCriticality: overrides.businessCriticality ?? 'unspecified',
      internetExposure: overrides.internetExposure ?? 'unknown',
      dataClassification: overrides.dataClassification ?? 'unspecified',
      owners: overrides.owners ?? [],
      tags: overrides.tags ?? [],
      externalIdentifiers: overrides.externalIdentifiers ?? [],
    };
    if (overrides.environmentId !== undefined) {
      command.environmentId = overrides.environmentId;
    }
    if (overrides.owningTeamId !== undefined) {
      command.owningTeamId = overrides.owningTeamId;
    }
    if (overrides.description !== undefined) {
      command.description = overrides.description;
    }
    if (overrides.repositoryUrl !== undefined) {
      command.repositoryUrl = overrides.repositoryUrl;
    }
    if (overrides.deploymentContext !== undefined) {
      command.deploymentContext = overrides.deploymentContext;
    }
    return command;
  }

  it('isolates two organizations on list, detail, and compare-and-set', async () => {
    const repos = createRepositories(prisma);
    const orgA = await createOrg('iso-a');
    const orgB = await createOrg('iso-b');
    const created = await repos.assets.createAggregate(orgA.id, createCommand('Isolated A'));
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const listedA = await repos.assets.listForOrganization(orgA.id, {
      limit: 20,
      lifecycleStatus: DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
    });
    const listedB = await repos.assets.listForOrganization(orgB.id, {
      limit: 20,
      lifecycleStatus: 'active',
    });
    expect(listedA.items.map((item) => item.id)).toEqual([created.value.id]);
    expect(listedB.items).toEqual([]);
    expect(await repos.assets.findDetailById(orgB.id, created.value.id)).toBeUndefined();

    const stolen = await repos.assets.compareAndSetUpdate(orgB.id, created.value.id, {
      expectedVersion: created.value.version,
      name: 'Stolen',
    });
    expect(stolen.ok).toBe(true);
    if (stolen.ok) {
      expect(stolen.value).toEqual({ kind: 'not_found' });
    }

    const stillA = await repos.assets.findDetailById(orgA.id, created.value.id);
    expect(stillA?.name).toBe('Isolated A');
  });

  it('defaults the list to active assets and returns archived only when requested', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('lifecycle');
    const active = await repos.assets.createAggregate(org.id, createCommand('Active App'));
    const archived = await repos.assets.createAggregate(org.id, createCommand('Archived App'));
    expect(active.ok && archived.ok).toBe(true);
    if (!active.ok || !archived.ok) {
      return;
    }

    const archivedResult = await repos.assets.compareAndSetArchive(
      org.id,
      archived.value.id,
      archived.value.version,
    );
    expect(archivedResult.kind).toBe('updated');

    const defaultList = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
    });
    expect(defaultList.items.map((item) => item.name)).toEqual(['Active App']);

    const archivedList = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'archived',
    });
    expect(archivedList.items.map((item) => item.name)).toEqual(['Archived App']);

    const allList = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'all',
    });
    expect(allList.items.map((item) => item.name)).toEqual(['Active App', 'Archived App']);
  });

  it('paginates with a stable lower(name), id keyset and bounded pages', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('page');
    await repos.assets.createAggregate(org.id, createCommand('Zebra'));
    const bravo = await repos.assets.createAggregate(org.id, createCommand('Bravo'));
    await repos.assets.createAggregate(org.id, createCommand('alpha'));
    expect(bravo.ok).toBe(true);
    if (!bravo.ok) {
      return;
    }

    const first = await repos.assets.listForOrganization(org.id, {
      limit: 2,
      lifecycleStatus: 'active',
    });
    expect(first.items.map((item) => item.name)).toEqual(['alpha', 'Bravo']);
    expect(first.nextCursor).toEqual({ v: 1, n: 'Bravo', i: bravo.value.id });

    const secondQuery: AssetListQuery = {
      limit: 2,
      lifecycleStatus: 'active',
    };
    if (first.nextCursor !== undefined) {
      secondQuery.cursor = first.nextCursor;
    }
    const second = await repos.assets.listForOrganization(org.id, secondQuery);
    expect(second.items.map((item) => item.name)).toEqual(['Zebra']);
    expect(second.nextCursor).toBeUndefined();

    const afterLast = await repos.assets.listForOrganization(org.id, {
      limit: 2,
      lifecycleStatus: 'active',
      cursor: { v: 1, n: 'Zebra', i: second.items[0]?.id ?? bravo.value.id },
    });
    expect(afterLast.items).toEqual([]);
    expect(afterLast.nextCursor).toBeUndefined();

    const oversized = await repos.assets.listForOrganization(org.id, {
      limit: 1000,
      lifecycleStatus: 'active',
    });
    expect(oversized.items.length).toBeLessThanOrEqual(100);
  });

  it('treats an invalid cursor as an empty page', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('cursor');
    await repos.assets.createAggregate(org.id, createCommand('Cursor Asset'));

    const page = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      cursor: { v: 1, n: 'Cursor Asset', i: 'not-a-uuid' },
    });
    expect(page.items).toEqual([]);
  });

  it('applies each approved list filter', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('filters');
    const environment = await createEnvironment(org.id, 'production');
    const otherEnvironment = await createEnvironment(org.id, 'staging', 'non_production');
    const team = await createTeam(org.id, 'Platform');
    const otherTeam = await createTeam(org.id, 'Security');

    await repos.assets.createAggregate(
      org.id,
      createCommand('Filter Target', {
        assetType: 'service',
        businessCriticality: 'high',
        internetExposure: 'internet_facing',
        environmentId: environment.id,
        owningTeamId: team.id,
        tags: ['payments', 'core'],
      }),
    );
    await repos.assets.createAggregate(
      org.id,
      createCommand('Filter Other', {
        assetType: 'application',
        businessCriticality: 'low',
        internetExposure: 'internal',
        environmentId: otherEnvironment.id,
        owningTeamId: otherTeam.id,
        tags: ['other'],
      }),
    );

    const byEnvironment = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      environmentId: environment.id,
    });
    const byType = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      assetType: 'service',
    });
    const byCriticality = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      businessCriticality: 'high',
    });
    const byExposure = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      internetExposure: 'internet_facing',
    });
    const byTeam = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      owningTeamId: team.id,
    });
    const byTag = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      tag: 'payments',
    });
    const byPrefix = await repos.assets.listForOrganization(org.id, {
      limit: 20,
      lifecycleStatus: 'active',
      namePrefix: 'Filter T',
    });

    expect(byEnvironment.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byType.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byCriticality.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byExposure.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byTeam.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byTag.items.map((item) => item.name)).toEqual(['Filter Target']);
    expect(byPrefix.items.map((item) => item.name)).toEqual(['Filter Target']);
  });

  it('rejects an active duplicate name and allows archived-name reuse', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('names');
    const other = await createOrg('names-b');
    const first = await repos.assets.createAggregate(org.id, createCommand('Payments API'));
    expect(first.ok).toBe(true);
    if (!first.ok) {
      return;
    }

    const duplicate = await repos.assets.createAggregate(org.id, createCommand('payments api'));
    expect(duplicate).toEqual({ ok: false, error: ASSET_NAME_CONFLICT });

    const otherOrg = await repos.assets.createAggregate(other.id, createCommand('Payments API'));
    expect(otherOrg.ok).toBe(true);

    const archived = await repos.assets.compareAndSetArchive(
      org.id,
      first.value.id,
      first.value.version,
    );
    expect(archived.kind).toBe('updated');

    const reused = await repos.assets.createAggregate(org.id, createCommand('Payments API'));
    expect(reused.ok).toBe(true);
    if (reused.ok) {
      expect(reused.value.lifecycleStatus).toBe('active');
      expect(reused.value.name).toBe('Payments API');
    }
  });

  it('maps detail relations and keeps archived environment and team readable', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('detail');
    const user = await createUser('owner', 'Ada Owner');
    const membership = await createMembership(org.id, user.id);
    const team = await createTeam(org.id, 'Platform');
    const environment = await createEnvironment(org.id, 'production');

    const created = await repos.assets.createAggregate(
      org.id,
      createCommand('Detail Asset', {
        description: 'Tracked service',
        repositoryUrl: 'https://example.test/app.git',
        deploymentContext: 'k8s',
        environmentId: environment.id,
        owningTeamId: team.id,
        owners: [
          { kind: 'membership', membershipId: membership.id, role: 'technical' },
          { kind: 'team', teamId: team.id, role: 'business' },
        ],
        tags: ['zeta', 'alpha'],
        externalIdentifiers: [{ namespace: 'cmdb', identifier: 'CMDB-1' }],
      }),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    await prisma.environment.update({
      where: { id: environment.id },
      data: { status: 'archived' },
    });
    await prisma.team.update({
      where: { id: team.id },
      data: { status: 'archived' },
    });

    const detail = await repos.assets.findDetailById(org.id, created.value.id);
    expect(detail).toMatchObject({
      id: created.value.id,
      organizationId: org.id,
      name: 'Detail Asset',
      description: 'Tracked service',
      repositoryUrl: 'https://example.test/app.git',
      deploymentContext: 'k8s',
      version: 1,
      tags: ['alpha', 'zeta'],
      environment: {
        id: environment.id,
        name: 'production',
        sensitivityClass: 'production',
      },
      owningTeam: { id: team.id, name: 'Platform' },
    });
    expect(detail?.createdAt).toBeInstanceOf(Date);
    expect(detail?.updatedAt).toBeInstanceOf(Date);
    expect(detail?.identifiers).toEqual([
      expect.objectContaining({ namespace: 'cmdb', identifier: 'CMDB-1' }),
    ]);
    expect(detail?.owners).toEqual([
      expect.objectContaining({
        kind: 'membership',
        membershipId: membership.id,
        userId: user.id,
        displayName: 'Ada Owner',
        role: 'technical',
      }),
      expect.objectContaining({
        kind: 'team',
        teamId: team.id,
        name: 'Platform',
        role: 'business',
      }),
    ]);
  });

  it('returns not_found for compare-and-set against a missing or cross-tenant asset', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('missing');
    const outcome = await repos.assets.compareAndSetArchive(org.id, randomUUID(), 1);
    expect(outcome).toEqual({ kind: 'not_found' });
  });

  it('compare-and-sets an update, then reports stale version, archived, and a single increment', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('cas');
    const user = await createUser('cas');
    const membership = await createMembership(org.id, user.id);
    const created = await repos.assets.createAggregate(
      org.id,
      createCommand('CAS Asset', {
        tags: ['one'],
        owners: [{ kind: 'membership', membershipId: membership.id, role: 'technical' }],
        externalIdentifiers: [{ namespace: 'cmdb', identifier: '1' }],
      }),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const update: NormalizedUpdateAssetCommand = {
      expectedVersion: created.value.version,
      name: 'CAS Asset Updated',
      tags: ['one', 'two'],
      owners: [{ kind: 'membership', membershipId: membership.id, role: 'security' }],
      externalIdentifiers: [{ namespace: 'cmdb', identifier: '2' }],
    };
    const updated = await repos.assets.compareAndSetUpdate(org.id, created.value.id, update);
    expect(updated.ok).toBe(true);
    if (!updated.ok || updated.value.kind !== 'updated') {
      throw new Error('expected compare-and-set success');
    }
    expect(updated.value.asset.version).toBe(created.value.version + 1);
    expect(updated.value.asset.name).toBe('CAS Asset Updated');
    expect(updated.value.asset.tags).toEqual(['one', 'two']);

    const stale = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version,
      name: 'Stale',
    });
    expect(stale.ok).toBe(true);
    if (stale.ok && stale.value.kind === 'version_conflict') {
      expect(stale.value.asset.version).toBe(created.value.version + 1);
      expect(stale.value.asset.name).toBe('CAS Asset Updated');
    } else {
      throw new Error('expected version conflict');
    }

    const archived = await repos.assets.compareAndSetArchive(
      org.id,
      created.value.id,
      created.value.version + 1,
    );
    expect(archived.kind).toBe('updated');
    if (archived.kind === 'updated') {
      expect(archived.asset.lifecycleStatus).toBe('archived');
      expect(archived.asset.archivedAt).toBeInstanceOf(Date);
      expect(archived.asset.version).toBe(created.value.version + 2);
    }

    const updateArchived = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version + 2,
      name: 'Should Fail',
    });
    expect(updateArchived.ok).toBe(true);
    if (updateArchived.ok) {
      expect(updateArchived.value.kind).toBe('archived');
    }
  });

  it('replaces owners, tags, and identifiers and skips unchanged collections', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('replace');
    const user = await createUser('replace', 'Owner One');
    const membership = await createMembership(org.id, user.id);
    const team = await createTeam(org.id, 'Platform');
    const created = await repos.assets.createAggregate(
      org.id,
      createCommand('Replace Asset', {
        owners: [{ kind: 'membership', membershipId: membership.id, role: 'technical' }],
        tags: ['alpha'],
        externalIdentifiers: [{ namespace: 'cmdb', identifier: 'A' }],
      }),
    );
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const originalOwnerId = created.value.owners[0]?.id;
    const originalTagCreatedAt = await prisma.assetTag.findFirst({
      where: { organizationId: org.id, assetId: created.value.id, tag: 'alpha' },
    });
    const originalIdentifier = await prisma.assetExternalIdentifier.findFirst({
      where: { organizationId: org.id, assetId: created.value.id, namespace: 'cmdb' },
    });

    const sameCollections = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version,
      name: 'Replace Asset Same',
      owners: [{ kind: 'membership', membershipId: membership.id, role: 'technical' }],
      tags: ['alpha'],
      externalIdentifiers: [{ namespace: 'cmdb', identifier: 'A' }],
    });
    expect(sameCollections.ok).toBe(true);
    if (!sameCollections.ok || sameCollections.value.kind !== 'updated') {
      throw new Error('expected unchanged collection update');
    }
    expect(sameCollections.value.asset.version).toBe(created.value.version + 1);
    expect(sameCollections.value.asset.owners[0]?.id).toBe(originalOwnerId);
    const unchangedTag = await prisma.assetTag.findFirst({
      where: { organizationId: org.id, assetId: created.value.id, tag: 'alpha' },
    });
    expect(unchangedTag?.createdAt).toEqual(originalTagCreatedAt?.createdAt);
    const unchangedIdentifier = await prisma.assetExternalIdentifier.findFirst({
      where: { organizationId: org.id, assetId: created.value.id, namespace: 'cmdb' },
    });
    expect(unchangedIdentifier?.id).toBe(originalIdentifier?.id);

    const replaced = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version + 1,
      owners: [{ kind: 'team', teamId: team.id, role: 'business' }],
      tags: ['beta'],
      externalIdentifiers: [{ namespace: 'servicenow', identifier: 'SN-1' }],
    });
    expect(replaced.ok).toBe(true);
    if (!replaced.ok || replaced.value.kind !== 'updated') {
      throw new Error('expected collection replacement');
    }
    expect(replaced.value.asset.version).toBe(created.value.version + 2);
    expect(replaced.value.asset.owners).toEqual([
      expect.objectContaining({
        kind: 'team',
        teamId: team.id,
        name: 'Platform',
        role: 'business',
      }),
    ]);
    expect(replaced.value.asset.tags).toEqual(['beta']);
    expect(replaced.value.asset.identifiers).toEqual([
      expect.objectContaining({ namespace: 'servicenow', identifier: 'SN-1' }),
    ]);
    expect(replaced.value.asset.owners[0]?.id).not.toBe(originalOwnerId);
  });

  it('rejects revoked memberships and archived teams or environments as new assignment targets', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('targets');
    const user = await createUser('targets');
    const membership = await createMembership(org.id, user.id);
    const team = await createTeam(org.id, 'Platform');
    const environment = await createEnvironment(org.id, 'production');
    const created = await repos.assets.createAggregate(org.id, createCommand('Target Asset'));
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    await prisma.membership.update({
      where: { id: membership.id },
      data: { status: 'revoked', revokedAt: new Date() },
    });
    await prisma.team.update({
      where: { id: team.id },
      data: { status: 'archived' },
    });
    await prisma.environment.update({
      where: { id: environment.id },
      data: { status: 'archived' },
    });

    const revokedOwner = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version,
      owners: [{ kind: 'membership', membershipId: membership.id, role: 'technical' }],
    });
    expect(revokedOwner.ok).toBe(false);
    if (!revokedOwner.ok) {
      expect(revokedOwner.error.message).toContain('Membership');
    }

    const archivedTeam = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version,
      owningTeamId: team.id,
    });
    expect(archivedTeam.ok).toBe(false);
    if (!archivedTeam.ok) {
      expect(archivedTeam.error.message).toContain('Team');
    }

    const archivedEnvironment = await repos.assets.compareAndSetUpdate(org.id, created.value.id, {
      expectedVersion: created.value.version,
      environmentId: environment.id,
    });
    expect(archivedEnvironment.ok).toBe(false);
    if (!archivedEnvironment.ok) {
      expect(archivedEnvironment.error.message).toContain('Environment');
    }

    const unchanged = await repos.assets.findDetailById(org.id, created.value.id);
    expect(unchanged?.version).toBe(1);
    expect(unchanged?.name).toBe('Target Asset');
  });

  it('rolls back compare-and-set changes when the surrounding transaction fails', async () => {
    const org = await createOrg('rollback');
    const repos = createRepositories(prisma);
    const created = await repos.assets.createAggregate(org.id, createCommand('Rollback Asset'));
    expect(created.ok).toBe(true);
    if (!created.ok) {
      return;
    }

    const unitOfWork = createPrismaUnitOfWork({ client: prisma });
    await expect(
      unitOfWork.runInTransaction(async (txRepos) => {
        const updated = await txRepos.assets.compareAndSetUpdate(org.id, created.value.id, {
          expectedVersion: created.value.version,
          name: 'Should Roll Back',
          tags: ['rolled-back'],
        });
        expect(updated.ok).toBe(true);
        throw new Error('force rollback');
      }),
    ).rejects.toThrow('force rollback');

    const detail = await repos.assets.findDetailById(org.id, created.value.id);
    expect(detail?.name).toBe('Rollback Asset');
    expect(detail?.version).toBe(1);
    expect(detail?.tags).toEqual([]);
  });

  it('lists only active environment, team, and membership options', async () => {
    const repos = createRepositories(prisma);
    const org = await createOrg('options');
    const other = await createOrg('options-b');
    const activeUser = await createUser('opt-active', 'Active Member');
    const revokedUser = await createUser('opt-revoked', 'Revoked Member');
    const otherUser = await createUser('opt-other', 'Other Org');
    const activeMembership = await createMembership(org.id, activeUser.id, 'admin');
    const revokedMembership = await createMembership(org.id, revokedUser.id);
    await createMembership(other.id, otherUser.id);
    await prisma.membership.update({
      where: { id: revokedMembership.id },
      data: { status: 'revoked', revokedAt: new Date() },
    });

    const activeEnv = await createEnvironment(org.id, 'production');
    const archivedEnv = await createEnvironment(org.id, 'legacy');
    await prisma.environment.update({
      where: { id: archivedEnv.id },
      data: { status: 'archived' },
    });
    await createEnvironment(other.id, 'foreign');

    const activeTeam = await createTeam(org.id, 'Platform');
    const archivedTeam = await createTeam(org.id, 'Old Team');
    await prisma.team.update({
      where: { id: archivedTeam.id },
      data: { status: 'archived' },
    });
    await createTeam(other.id, 'Foreign Team');

    const environments = await repos.environments.listActiveOptions(org.id, { limit: 100 });
    const teams = await repos.teams.listActiveOptions(org.id, { limit: 100 });
    const memberships = await repos.memberships.listActiveOptions(org.id, { limit: 100 });

    expect(environments.items.map((item) => item.id)).toEqual([activeEnv.id]);
    expect(environments.items[0]).toMatchObject({
      name: 'production',
      sensitivityClass: 'production',
    });
    expect(teams.items.map((item) => item.id)).toEqual([activeTeam.id]);
    expect(memberships.items.map((item) => item.membershipId)).toEqual([activeMembership.id]);
    expect(memberships.items[0]).toMatchObject({
      displayName: 'Active Member',
      role: 'admin',
    });
    expect(environments.items.length).toBeLessThanOrEqual(100);
  });

  it('loads a tagged list without N+1 queries', async () => {
    const org = await createOrg('nplusone');
    const seedRepos = createRepositories(prisma);
    for (const name of ['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8']) {
      const created = await seedRepos.assets.createAggregate(
        org.id,
        createCommand(name, { tags: ['shared', name.toLowerCase()] }),
      );
      expect(created.ok).toBe(true);
    }

    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });

    try {
      const repos = createRepositories(logging);
      queries.length = 0;
      const page = await repos.assets.listForOrganization(org.id, {
        limit: 20,
        lifecycleStatus: 'active',
        tag: 'shared',
      });
      expect(page.items).toHaveLength(8);
      expect(page.items.every((item) => item.tags.includes('shared'))).toBe(true);
      const selectQueries = queries.filter((query) => /\bselect\b/i.test(query));
      expect(selectQueries.length).toBe(1);
    } finally {
      await logging.$disconnect();
    }
  });
});
