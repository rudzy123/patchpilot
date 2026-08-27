import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import { JSON_SCHEMA_VERSION_V1, type RiskPolicyDefinitionJson } from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createRepositories } from './repositories.js';

const SHA_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SHA_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const SHA_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const SHA_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';

describe('session 5 review corrections', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
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

  async function createOrg(slug: string) {
    return prisma.organization.create({ data: { slug, name: `Org ${slug}` } });
  }

  async function createUser(email: string) {
    return prisma.user.create({ data: { email, displayName: email } });
  }

  async function createMembership(organizationId: string, userId: string) {
    return prisma.membership.create({
      data: { organizationId, userId, role: 'member' },
    });
  }

  it('separates builtin and tenant risk policies and blocks published deletes', async () => {
    const orgA = await createOrg(`pol-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`pol-b-${randomUUID().slice(0, 8)}`);
    const repos = createRepositories(prisma);
    const definition = {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      policyKey: 'patchpilot.builtin.v0',
      factorCatalog: [],
      weights: {},
    } satisfies RiskPolicyDefinitionJson;

    const builtin = await repos.riskPolicies.createBuiltin({
      policyKey: 'patchpilot.builtin.v0',
      name: 'Builtin',
      version: 1,
      status: 'published',
      policySchemaVersion: 1,
      publishedAt: new Date('2026-01-01T00:00:00.000Z'),
      definition,
    });
    expect(builtin.organizationId).toBeNull();
    expect(builtin.scope).toBe('builtin');

    const orgPolicy = await repos.riskPolicies.createForOrganization({
      organizationId: orgA.id,
      policyKey: 'org.override',
      name: 'Org A override',
      version: 1,
      status: 'published',
      policySchemaVersion: 1,
      publishedAt: new Date('2026-01-01T00:00:00.000Z'),
      definition: { ...definition, policyKey: 'org.override' },
    });

    expect(await repos.riskPolicies.findById(orgA.id, builtin.id)).toBeUndefined();
    expect(await repos.riskPolicies.findById(orgB.id, orgPolicy.id)).toBeUndefined();
    expect((await repos.riskPolicies.findById(orgA.id, orgPolicy.id))?.id).toBe(orgPolicy.id);
    expect((await repos.riskPolicies.findBuiltinById(builtin.id))?.id).toBe(builtin.id);
    expect(
      (await repos.riskPolicies.findBuiltinByKeyVersion('patchpilot.builtin.v0', 1))?.id,
    ).toBe(builtin.id);
    expect((await repos.riskPolicies.listBuiltins()).items.some((row) => row.id === builtin.id)).toBe(
      true,
    );
    expect(
      (await repos.riskPolicies.listForOrganization(orgA.id)).items.some(
        (row) => row.id === builtin.id,
      ),
    ).toBe(false);

    await expect(
      prisma.riskPolicy.create({
        data: {
          organizationId: orgA.id,
          scope: 'builtin',
          policyKey: 'invalid.mix',
          name: 'Invalid',
          version: 1,
          status: 'draft',
          policySchemaVersion: 1,
          definition,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.riskPolicy.create({
        data: {
          scope: 'organization',
          policyKey: 'invalid.mix',
          name: 'Invalid',
          version: 1,
          status: 'draft',
          policySchemaVersion: 1,
          definition,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.riskPolicy.create({
        data: {
          organizationId: orgA.id,
          scope: 'organization',
          policyKey: 'draft.bad-ts',
          name: 'Invalid timestamps',
          version: 1,
          status: 'published',
          policySchemaVersion: 1,
          definition,
        },
      }),
    ).rejects.toThrow();

    await expect(prisma.riskPolicy.delete({ where: { id: orgPolicy.id } })).rejects.toThrow();
    await expect(
      prisma.riskPolicy.update({
        where: { id: orgPolicy.id },
        data: { policyKey: 'mutated.after.publish' },
      }),
    ).rejects.toThrow();
    await prisma.riskPolicy.update({
      where: { id: orgPolicy.id },
      data: { status: 'retired', retiredAt: new Date('2026-02-01T00:00:00.000Z') },
    });
    await expect(
      prisma.riskPolicy.update({
        where: { id: orgPolicy.id },
        data: { definition: { schemaVersion: 2 } },
      }),
    ).rejects.toThrow();

    const draft = await prisma.riskPolicy.create({
      data: {
        organizationId: orgA.id,
        scope: 'organization',
        policyKey: 'org.draft',
        name: 'Draft',
        version: 1,
        status: 'draft',
        policySchemaVersion: 1,
        definition: { ...definition, policyKey: 'org.draft' },
      },
    });
    await prisma.riskPolicy.delete({ where: { id: draft.id } });
  });

  it('rejects cross-organization and builtin membership creators for risk policies', async () => {
    const orgA = await createOrg(`creator-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`creator-b-${randomUUID().slice(0, 8)}`);
    const userA = await createUser(`creator-a-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const userB = await createUser(`creator-b-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const membershipA = await createMembership(orgA.id, userA.id);
    const membershipB = await createMembership(orgB.id, userB.id);
    const definition = {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      policyKey: 'org.creator',
      factorCatalog: [],
      weights: {},
    } satisfies RiskPolicyDefinitionJson;

    await expect(
      prisma.riskPolicy.create({
        data: {
          scope: 'builtin',
          policyKey: 'builtin.with-membership',
          name: 'Invalid builtin creator',
          version: 1,
          status: 'draft',
          policySchemaVersion: 1,
          definition: { ...definition, policyKey: 'builtin.with-membership' },
          createdByMembershipId: membershipA.id,
        },
      }),
    ).rejects.toThrow();

    await expect(
      prisma.riskPolicy.create({
        data: {
          organizationId: orgA.id,
          scope: 'organization',
          policyKey: 'org.cross-creator',
          name: 'Cross-org creator',
          version: 1,
          status: 'draft',
          policySchemaVersion: 1,
          definition: { ...definition, policyKey: 'org.cross-creator' },
          createdByMembershipId: membershipB.id,
        },
      }),
    ).rejects.toThrow();

    await prisma.membership.update({
      where: { id: membershipA.id },
      data: { status: 'revoked', revokedAt: new Date('2026-03-01T00:00:00.000Z') },
    });
    const created = await prisma.riskPolicy.create({
      data: {
        organizationId: orgA.id,
        scope: 'organization',
        policyKey: 'org.revoked-creator',
        name: 'Revoked membership still attributes',
        version: 1,
        status: 'draft',
        policySchemaVersion: 1,
        definition: { ...definition, policyKey: 'org.revoked-creator' },
        createdByMembershipId: membershipA.id,
      },
    });
    expect(created.createdByMembershipId).toBe(membershipA.id);
  });

  it('allows the same SBOM SHA-256 on different assets in one organization', async () => {
    const org = await createOrg(`hash-${randomUUID().slice(0, 8)}`);
    const assetA = await prisma.asset.create({
      data: { organizationId: org.id, name: 'hash-a', assetType: 'application' },
    });
    const assetB = await prisma.asset.create({
      data: { organizationId: org.id, name: 'hash-b', assetType: 'application' },
    });
    await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: assetA.id,
        objectKey: `org/${org.id}/hash-a`,
        sha256: SHA_A,
        byteLength: 16,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const second = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: assetB.id,
        objectKey: `org/${org.id}/hash-b`,
        sha256: SHA_A,
        byteLength: 16,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    expect(second.sha256).toBe(SHA_A);
    expect(second.assetId).toBe(assetB.id);
  });

  it('keeps system intelligence sources distinct from tenant integrations', async () => {
    const org = await createOrg(`int-${randomUUID().slice(0, 8)}`);
    const osv = await prisma.intelligenceSource.findUniqueOrThrow({ where: { providerKey: 'osv' } });
    expect(osv).toMatchObject({ providerKey: 'osv' });
    await expect(
      prisma.intelligenceSource.create({
        data: {
          providerKey: 'reserved',
          config: { schemaVersion: JSON_SCHEMA_VERSION_V1, refreshIntervalSeconds: null, endpointAllowlist: [] },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.integration.create({
        data: {
          providerId: (await prisma.integrationProvider.findUniqueOrThrow({
            where: { providerKey: 'osv' },
          })).id,
          displayName: 'Null org install',
          config: { schemaVersion: JSON_SCHEMA_VERSION_V1, refreshIntervalSeconds: null, endpointAllowlist: [] },
        } as never,
      }),
    ).rejects.toThrow();

    const reserved = await prisma.integrationProvider.findUniqueOrThrow({
      where: { providerKey: 'reserved' },
    });
    const install = await prisma.integration.create({
      data: {
        organizationId: org.id,
        providerId: reserved.id,
        displayName: 'Tenant reserved',
        config: { schemaVersion: JSON_SCHEMA_VERSION_V1, refreshIntervalSeconds: null, endpointAllowlist: [] },
      },
    });
    expect(install.organizationId).toBe(org.id);
    await prisma.externalCredential.create({
      data: {
        organizationId: org.id,
        integrationId: install.id,
        storageProvider: 'encrypted_local',
        secretReference: 'vault://org/test',
        keyVersion: '1',
      },
    });
  });

  it('rejects evidence-graph mismatches across SBOM, ingestion, occurrence, and asset', async () => {
    const org = await createOrg(`graph-${randomUUID().slice(0, 8)}`);
    const assetA = await prisma.asset.create({
      data: { organizationId: org.id, name: 'graph-a', assetType: 'application' },
    });
    const assetB = await prisma.asset.create({
      data: { organizationId: org.id, name: 'graph-b', assetType: 'application' },
    });
    const sbomA = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: assetA.id,
        objectKey: `org/${org.id}/graph-a`,
        sha256: SHA_A,
        byteLength: 12,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const sbomB = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: assetB.id,
        objectKey: `org/${org.id}/graph-b`,
        sha256: SHA_B,
        byteLength: 12,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const ingestionA = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbomA.id,
        assetId: assetA.id,
        parserVersion: '0.0.0-test',
      },
    });
    const ingestionB = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbomB.id,
        assetId: assetB.id,
        parserVersion: '0.0.0-test',
      },
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbomA.id,
          assetId: assetB.id,
          parserVersion: '0.0.0-test',
        },
      }),
    ).rejects.toThrow();

    const componentA = await prisma.component.create({
      data: { organizationId: org.id, identityKey: 'npm|graph-a', ecosystem: 'npm', name: 'graph-a' },
    });
    const componentB = await prisma.component.create({
      data: { organizationId: org.id, identityKey: 'npm|graph-b', ecosystem: 'npm', name: 'graph-b' },
    });
    const occA = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: assetA.id,
        sbomId: sbomA.id,
        sbomIngestionId: ingestionA.id,
        componentId: componentA.id,
        version: '1.0.0',
      },
    });
    const occB = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: assetB.id,
        sbomId: sbomB.id,
        sbomIngestionId: ingestionB.id,
        componentId: componentB.id,
        version: '1.0.0',
      },
    });
    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: org.id,
          assetId: assetA.id,
          sbomId: sbomB.id,
          sbomIngestionId: ingestionA.id,
          componentId: componentA.id,
          version: '2.0.0',
        },
      }),
    ).rejects.toThrow();
    const sbomA2 = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: assetA.id,
        objectKey: `org/${org.id}/graph-a2`,
        sha256: SHA_D,
        byteLength: 12,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const ingestionA2 = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbomA2.id,
        assetId: assetA.id,
        parserVersion: '0.0.0-test',
      },
    });
    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: org.id,
          assetId: assetA.id,
          sbomId: sbomA.id,
          sbomIngestionId: ingestionA2.id,
          componentId: componentA.id,
          version: '2.0.0',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.dependencyRelationship.create({
        data: {
          organizationId: org.id,
          sbomId: sbomA.id,
          sbomIngestionId: ingestionA.id,
          fromOccurrenceId: occA.id,
          toOccurrenceId: occB.id,
        },
      }),
    ).rejects.toThrow();

    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-GRAPH-${randomUUID().slice(0, 8)}` },
    });
    await expect(
      prisma.finding.create({
        data: {
          organizationId: org.id,
          assetId: assetA.id,
          vulnerabilityId: vulnerability.id,
          componentId: componentA.id,
          componentOccurrenceId: occB.id,
          firstObservedAt: new Date(),
          lastObservedAt: new Date(),
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.finding.create({
        data: {
          organizationId: org.id,
          assetId: assetA.id,
          vulnerabilityId: vulnerability.id,
          componentId: componentB.id,
          componentOccurrenceId: occA.id,
          firstObservedAt: new Date(),
          lastObservedAt: new Date(),
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.asset.update({
        where: { id: assetA.id },
        data: { lastSuccessfulSbomIngestionId: ingestionB.id },
      }),
    ).rejects.toThrow();
  });

  it('requires membership-scoped actors for tenant-sensitive user references', async () => {
    const orgA = await createOrg(`act-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`act-b-${randomUUID().slice(0, 8)}`);
    const userA = await createUser(`act-a-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const userB = await createUser(`act-b-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const membershipA = await createMembership(orgA.id, userA.id);
    const membershipB = await createMembership(orgB.id, userB.id);
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'act-asset', assetType: 'application' },
    });
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-ACT-${randomUUID().slice(0, 8)}` },
    });
    const component = await prisma.component.create({
      data: { organizationId: orgA.id, identityKey: 'npm|act', ecosystem: 'npm', name: 'act' },
    });
    const finding = await prisma.finding.create({
      data: {
        organizationId: orgA.id,
        assetId: assetA.id,
        vulnerabilityId: vulnerability.id,
        componentId: component.id,
        firstObservedAt: new Date(),
        lastObservedAt: new Date(),
      },
    });
    await expect(
      prisma.finding.update({
        where: { id: finding.id },
        data: { assignedMembershipId: membershipB.id },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.remediationTask.create({
        data: {
          organizationId: orgA.id,
          findingId: finding.id,
          title: 'cross',
          assignedMembershipId: membershipB.id,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.sbom.create({
        data: {
          organizationId: orgA.id,
          assetId: assetA.id,
          objectKey: `org/${orgA.id}/act`,
          sha256: SHA_C,
          byteLength: 8,
          declaredContentType: 'application/json',
          receivedAt: new Date(),
          uploadedByMembershipId: membershipB.id,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.riskAcceptance.create({
        data: {
          organizationId: orgA.id,
          findingId: finding.id,
          status: 'active',
          reason: 'cross-org requester',
          startsAt: new Date('2026-01-01T00:00:00.000Z'),
          expiresAt: new Date('2026-02-01T00:00:00.000Z'),
          reviewAt: new Date('2026-01-24T00:00:00.000Z'),
          requestedByMembershipId: membershipB.id,
          approvedByMembershipId: membershipA.id,
          approvedAt: new Date('2026-01-01T00:00:00.000Z'),
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.riskAcceptance.create({
        data: {
          organizationId: orgA.id,
          findingId: finding.id,
          status: 'active',
          reason: 'cross-org approver',
          startsAt: new Date('2026-01-01T00:00:00.000Z'),
          expiresAt: new Date('2026-02-01T00:00:00.000Z'),
          reviewAt: new Date('2026-01-24T00:00:00.000Z'),
          requestedByMembershipId: membershipA.id,
          approvedByMembershipId: membershipB.id,
          approvedAt: new Date('2026-01-01T00:00:00.000Z'),
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.evidence.create({
        data: {
          organizationId: orgA.id,
          kind: 'export_snapshot',
          assetId: assetA.id,
          submittedByMembershipId: membershipB.id,
          metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.auditEvent.create({
        data: {
          organizationId: orgA.id,
          actorType: 'user',
          action: 'test.actor',
          subjectType: 'finding',
          subjectId: finding.id,
          correlationId: randomUUID(),
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
          schemaVersion: JSON_SCHEMA_VERSION_V1,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.auditEvent.create({
        data: {
          organizationId: orgA.id,
          actorMembershipId: membershipB.id,
          actorType: 'user',
          action: 'test.actor.cross',
          subjectType: 'finding',
          subjectId: finding.id,
          correlationId: randomUUID(),
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
          schemaVersion: JSON_SCHEMA_VERSION_V1,
        },
      }),
    ).rejects.toThrow();
    await prisma.auditEvent.create({
      data: {
        actorType: 'system',
        action: 'intelligence.imported',
        subjectType: 'vulnerability',
        subjectId: vulnerability.id,
        correlationId: randomUUID(),
        payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        schemaVersion: JSON_SCHEMA_VERSION_V1,
      },
    });
  });

  it('treats vulnerability source records as immutable normalized revisions', async () => {
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-REV-${randomUUID().slice(0, 8)}` },
    });
    const first = await prisma.vulnerabilitySourceRecord.create({
      data: {
        vulnerabilityId: vulnerability.id,
        source: 'osv',
        sourceIdentity: vulnerability.osvId,
        retrievedAt: new Date(),
        payloadSha256: SHA_A,
        normalizationVersion: 'norm-1',
        normalized: { schemaVersion: JSON_SCHEMA_VERSION_V1, summary: 'one', severity: null, affectedPackages: [] },
      },
    });
    const renormalized = await prisma.vulnerabilitySourceRecord.create({
      data: {
        vulnerabilityId: vulnerability.id,
        source: 'osv',
        sourceIdentity: vulnerability.osvId,
        retrievedAt: new Date(),
        payloadSha256: SHA_A,
        normalizationVersion: 'norm-2',
        supersedesRecordId: first.id,
        normalized: { schemaVersion: JSON_SCHEMA_VERSION_V1, summary: 'two', severity: null, affectedPackages: [] },
      },
    });
    expect(renormalized.supersedesRecordId).toBe(first.id);
    await expect(
      prisma.vulnerabilitySourceRecord.create({
        data: {
          vulnerabilityId: vulnerability.id,
          source: 'osv',
          sourceIdentity: vulnerability.osvId,
          retrievedAt: new Date(),
          payloadSha256: SHA_A,
          normalizationVersion: 'norm-1',
          normalized: { schemaVersion: JSON_SCHEMA_VERSION_V1, summary: 'dup', severity: null, affectedPackages: [] },
        },
      }),
    ).rejects.toThrow();

    const other = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-REV-OTHER-${randomUUID().slice(0, 8)}` },
    });
    await expect(
      prisma.vulnerabilitySourceRecord.create({
        data: {
          vulnerabilityId: other.id,
          source: 'osv',
          sourceIdentity: other.osvId,
          retrievedAt: new Date(),
          payloadSha256: SHA_B,
          normalizationVersion: 'norm-1',
          supersedesRecordId: first.id,
          normalized: { schemaVersion: JSON_SCHEMA_VERSION_V1, summary: 'cross', severity: null, affectedPackages: [] },
        },
      }),
    ).rejects.toThrow();
  });

  it('allows export_snapshot evidence on assets and keeps exactly one target', async () => {
    const org = await createOrg(`ev-${randomUUID().slice(0, 8)}`);
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'ev-asset', assetType: 'application' },
    });
    await prisma.evidence.create({
      data: {
        organizationId: org.id,
        kind: 'export_snapshot',
        assetId: asset.id,
        metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
      },
    });
    await expect(
      prisma.evidence.create({
        data: {
          organizationId: org.id,
          kind: 'export_snapshot',
          findingId: randomUUID(),
          metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.evidence.create({
        data: {
          organizationId: org.id,
          kind: 'export_snapshot',
          assetId: asset.id,
          findingId: randomUUID(),
          metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.evidence.create({
        data: {
          organizationId: org.id,
          kind: 'sbom_object',
          assetId: asset.id,
          metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces NULL-safe asset-owner uniqueness and ingestion idempotency keys', async () => {
    const org = await createOrg(`own-${randomUUID().slice(0, 8)}`);
    const user = await createUser(`own-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    await createMembership(org.id, user.id);
    const team = await prisma.team.create({
      data: { organizationId: org.id, name: 'Owners', slug: 'owners' },
    });
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'owned', assetType: 'application' },
    });
    await prisma.assetOwner.create({
      data: { organizationId: org.id, assetId: asset.id, teamId: team.id, role: 'technical' },
    });
    await expect(
      prisma.assetOwner.create({
        data: { organizationId: org.id, assetId: asset.id, teamId: team.id, role: 'technical' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.assetOwner.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          userId: user.id,
          teamId: team.id,
          role: 'business',
        },
      }),
    ).rejects.toThrow();
    await prisma.assetOwner.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        userId: user.id,
        role: 'business',
      },
    });
    await expect(
      prisma.assetOwner.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          userId: user.id,
          role: 'business',
        },
      }),
    ).rejects.toThrow();

    const sbom = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        objectKey: `org/${org.id}/idem`,
        sha256: SHA_A,
        byteLength: 4,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '0.0.0-test',
        idempotencyKey: 'upload-1',
      },
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '0.0.1-test',
          idempotencyKey: 'upload-1',
        },
      }),
    ).rejects.toThrow();
    await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '0.0.1-test',
        attemptNumber: 2,
      },
    });
    await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '0.0.2-test',
        attemptNumber: 3,
      },
    });
  });

  it('pins security-sensitive trigger functions to a controlled search_path', async () => {
    const functions = await prisma.$queryRaw<Array<{ proname: string; proconfig: string[] | null }>>`
      SELECT proname, proconfig
      FROM pg_proc
      WHERE proname LIKE 'patchpilot_%'
    `;
    expect(functions.length).toBeGreaterThan(0);
    for (const fn of functions) {
      expect(fn.proconfig?.some((entry) => entry.includes('search_path=pg_catalog'))).toBe(true);
    }
  });
});
