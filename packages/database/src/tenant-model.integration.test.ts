import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Prisma, PrismaClient } from '@prisma/client';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { persistTenantChangeWithAuditAndOutbox } from './persistence-fixture.js';
import { createPrismaUnitOfWork, createRepositories } from './repositories.js';
import { seedDevelopmentData } from './seed/development.js';

const SHA_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SHA_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

describe('tenant model persistence', () => {
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

  async function createOrg(slug: string) {
    return prisma.organization.create({
      data: { slug, name: `Org ${slug}` },
    });
  }

  async function createUser(email: string) {
    return prisma.user.create({
      data: { email, displayName: email },
    });
  }

  it('enforces organization slug uniqueness and shape', async () => {
    await createOrg('acme-synthetic');
    await expect(createOrg('acme-synthetic')).rejects.toThrow();
    await expect(
      prisma.organization.create({ data: { slug: 'No_Caps', name: 'Bad' } }),
    ).rejects.toThrow();
  });

  it('enforces membership uniqueness per organization and user', async () => {
    const org = await createOrg(`mem-${randomUUID().slice(0, 8)}`);
    const user = await createUser(`mem-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    await prisma.membership.create({
      data: { organizationId: org.id, userId: user.id, role: 'owner' },
    });
    await expect(
      prisma.membership.create({
        data: { organizationId: org.id, userId: user.id, role: 'member' },
      }),
    ).rejects.toThrow();
  });

  it('prevents cross-organization team membership', async () => {
    const orgA = await createOrg(`team-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`team-b-${randomUUID().slice(0, 8)}`);
    const user = await createUser(`team-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    await prisma.membership.create({
      data: { organizationId: orgA.id, userId: user.id, role: 'member' },
    });
    const teamB = await prisma.team.create({
      data: { organizationId: orgB.id, name: 'Team B', slug: 'team-b' },
    });
    await expect(
      prisma.teamMembership.create({
        data: { organizationId: orgB.id, teamId: teamB.id, userId: user.id },
      }),
    ).rejects.toThrow();
  });

  it('scopes environments to their organization', async () => {
    const orgA = await createOrg(`env-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`env-b-${randomUUID().slice(0, 8)}`);
    const envA = await prisma.environment.create({
      data: {
        organizationId: orgA.id,
        name: 'production',
        slug: 'production',
        sensitivityClass: 'production',
      },
    });
    await expect(
      prisma.asset.create({
        data: {
          organizationId: orgB.id,
          name: 'cross-env',
          assetType: 'application',
          environmentId: envA.id,
        },
      }),
    ).rejects.toThrow();
  });

  it('prevents cross-organization asset ownership', async () => {
    const orgA = await createOrg(`own-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`own-b-${randomUUID().slice(0, 8)}`);
    const userB = await createUser(`own-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    await prisma.membership.create({
      data: { organizationId: orgB.id, userId: userB.id, role: 'member' },
    });
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'asset-a', assetType: 'application' },
    });
    await expect(
      prisma.assetOwner.create({
        data: {
          organizationId: orgA.id,
          assetId: assetA.id,
          userId: userB.id,
          role: 'technical',
        },
      }),
    ).rejects.toThrow();
  });

  it('prevents cross-organization repository connections', async () => {
    const orgA = await createOrg(`repo-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`repo-b-${randomUUID().slice(0, 8)}`);
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'repo-asset-a', assetType: 'application' },
    });
    const assetB = await prisma.asset.create({
      data: { organizationId: orgB.id, name: 'repo-asset-b', assetType: 'application' },
    });
    const integrationB = await prisma.integration.create({
      data: {
        organizationId: orgB.id,
        providerKey: 'reserved',
        displayName: 'Synthetic B',
        config: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          refreshIntervalSeconds: null,
          endpointAllowlist: [],
        },
      },
    });
    await expect(
      prisma.repositoryConnection.create({
        data: {
          organizationId: orgA.id,
          assetId: assetB.id,
          provider: 'reserved',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.repositoryConnection.create({
        data: {
          organizationId: orgA.id,
          assetId: assetA.id,
          provider: 'reserved',
          integrationId: integrationB.id,
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces SBOM SHA-256 format, positive size, object-key uniqueness, and org/asset/hash dedupe', async () => {
    const org = await createOrg(`sbom-${randomUUID().slice(0, 8)}`);
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'sbom-asset', assetType: 'application' },
    });
    await expect(
      prisma.sbom.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          objectKey: `org/${org.id}/bad`,
          sha256: 'not-a-hash',
          byteLength: 12,
          declaredContentType: 'application/json',
          receivedAt: new Date(),
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.sbom.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          objectKey: `org/${org.id}/zero`,
          sha256: SHA_A,
          byteLength: 0,
          declaredContentType: 'application/json',
          receivedAt: new Date(),
        },
      }),
    ).rejects.toThrow();

    const created = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        objectKey: `org/${org.id}/assets/${asset.id}/sboms/sha256/${SHA_A}`,
        sha256: SHA_A,
        byteLength: 128,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    expect(created.id).toBeTruthy();

    await expect(
      prisma.sbom.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          objectKey: `org/${org.id}/assets/${asset.id}/sboms/sha256/${SHA_A}-dup`,
          sha256: SHA_A,
          byteLength: 128,
          declaredContentType: 'application/json',
          receivedAt: new Date(),
        },
      }),
    ).rejects.toThrow();

    await expect(
      prisma.sbom.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          objectKey: `org/${org.id}/assets/${asset.id}/sboms/sha256/${SHA_A}`,
          sha256: SHA_B,
          byteLength: 64,
          declaredContentType: 'application/json',
          receivedAt: new Date(),
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces component occurrence and dependency tenant/SBOM consistency', async () => {
    const orgA = await createOrg(`comp-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`comp-b-${randomUUID().slice(0, 8)}`);
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'comp-asset', assetType: 'application' },
    });
    const sbomA = await prisma.sbom.create({
      data: {
        organizationId: orgA.id,
        assetId: assetA.id,
        objectKey: `org/${orgA.id}/sbom-${SHA_B.slice(0, 8)}`,
        sha256: SHA_B,
        byteLength: 32,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const ingestionA = await prisma.sbomIngestion.create({
      data: {
        organizationId: orgA.id,
        sbomId: sbomA.id,
        assetId: assetA.id,
        parserVersion: '0.0.0-test',
      },
    });
    const componentA = await prisma.component.create({
      data: {
        organizationId: orgA.id,
        identityKey: 'npm|left-pad',
        ecosystem: 'npm',
        name: 'left-pad',
      },
    });
    const occA1 = await prisma.componentOccurrence.create({
      data: {
        organizationId: orgA.id,
        sbomId: sbomA.id,
        sbomIngestionId: ingestionA.id,
        componentId: componentA.id,
        version: '1.0.0',
      },
    });
    const occA2 = await prisma.componentOccurrence.create({
      data: {
        organizationId: orgA.id,
        sbomId: sbomA.id,
        sbomIngestionId: ingestionA.id,
        componentId: componentA.id,
        version: '1.0.1',
      },
    });
    await prisma.dependencyRelationship.create({
      data: {
        organizationId: orgA.id,
        sbomId: sbomA.id,
        sbomIngestionId: ingestionA.id,
        fromOccurrenceId: occA1.id,
        toOccurrenceId: occA2.id,
      },
    });
    await expect(
      prisma.dependencyRelationship.create({
        data: {
          organizationId: orgA.id,
          sbomId: sbomA.id,
          sbomIngestionId: ingestionA.id,
          fromOccurrenceId: occA1.id,
          toOccurrenceId: occA1.id,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.component
        .create({
          data: {
            organizationId: orgB.id,
            identityKey: 'npm|left-pad',
            ecosystem: 'npm',
            name: 'left-pad',
          },
        })
        .then((componentB) =>
          prisma.componentOccurrence.create({
            data: {
              organizationId: orgA.id,
              sbomId: sbomA.id,
              sbomIngestionId: ingestionA.id,
              componentId: componentB.id,
              version: '9.9.9',
            },
          }),
        ),
    ).rejects.toThrow();
  });

  it('preserves vulnerability source provenance uniqueness and finding isolation', async () => {
    const orgA = await createOrg(`find-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`find-b-${randomUUID().slice(0, 8)}`);
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'find-a', assetType: 'application' },
    });
    const assetB = await prisma.asset.create({
      data: { organizationId: orgB.id, name: 'find-b', assetType: 'application' },
    });
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-SYNTH-${randomUUID().slice(0, 8)}` },
    });
    await prisma.vulnerabilitySourceRecord.create({
      data: {
        vulnerabilityId: vulnerability.id,
        source: 'osv',
        sourceIdentity: vulnerability.osvId,
        retrievedAt: new Date(),
        payloadSha256: SHA_A,
        normalizationVersion: 'test-1',
        normalized: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          summary: 'synthetic',
          severity: null,
          affectedPackages: [],
        },
      },
    });
    await expect(
      prisma.vulnerabilitySourceRecord.create({
        data: {
          vulnerabilityId: vulnerability.id,
          source: 'osv',
          sourceIdentity: vulnerability.osvId,
          retrievedAt: new Date(),
          payloadSha256: SHA_A,
          normalizationVersion: 'test-1',
          normalized: {
            schemaVersion: JSON_SCHEMA_VERSION_V1,
            summary: 'synthetic',
            severity: null,
            affectedPackages: [],
          },
        },
      }),
    ).rejects.toThrow();

    const componentA = await prisma.component.create({
      data: {
        organizationId: orgA.id,
        identityKey: 'npm|demo',
        ecosystem: 'npm',
        name: 'demo',
      },
    });
    const componentB = await prisma.component.create({
      data: {
        organizationId: orgB.id,
        identityKey: 'npm|demo',
        ecosystem: 'npm',
        name: 'demo',
      },
    });
    const findingA = await prisma.finding.create({
      data: {
        organizationId: orgA.id,
        assetId: assetA.id,
        vulnerabilityId: vulnerability.id,
        componentId: componentA.id,
        firstObservedAt: new Date(),
        lastObservedAt: new Date(),
      },
    });
    const findingB = await prisma.finding.create({
      data: {
        organizationId: orgB.id,
        assetId: assetB.id,
        vulnerabilityId: vulnerability.id,
        componentId: componentB.id,
        firstObservedAt: new Date(),
        lastObservedAt: new Date(),
      },
    });
    expect(findingA.vulnerabilityId).toBe(findingB.vulnerabilityId);
    await expect(
      prisma.finding.create({
        data: {
          organizationId: orgA.id,
          assetId: assetB.id,
          vulnerabilityId: vulnerability.id,
          componentId: componentA.id,
          firstObservedAt: new Date(),
          lastObservedAt: new Date(),
        },
      }),
    ).rejects.toThrow();

    const repos = createRepositories(prisma);
    expect(await repos.findings.findById(orgA.id, findingB.id)).toBeUndefined();
    expect(await repos.findings.findById(orgB.id, findingA.id)).toBeUndefined();
    expect((await repos.findings.findById(orgA.id, findingA.id))?.id).toBe(findingA.id);
  });

  it('makes finding observations, calculations, and audit events append-only', async () => {
    const org = await createOrg(`imm-${randomUUID().slice(0, 8)}`);
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'imm-asset', assetType: 'application' },
    });
    const sbom = await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        objectKey: `org/${org.id}/imm`,
        sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        byteLength: 16,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    const ingestion = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '0.0.0-test',
      },
    });
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-IMM-${randomUUID().slice(0, 8)}` },
    });
    const component = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: 'npm|imm',
        ecosystem: 'npm',
        name: 'imm',
      },
    });
    const finding = await prisma.finding.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        vulnerabilityId: vulnerability.id,
        componentId: component.id,
        firstObservedAt: new Date(),
        lastObservedAt: new Date(),
      },
    });
    const observation = await prisma.findingObservation.create({
      data: {
        organizationId: org.id,
        findingId: finding.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        result: 'present',
        method: 'exact_purl',
        observedAt: new Date(),
        evidence: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
      },
    });
    await expect(
      prisma.findingObservation.update({
        where: { id: observation.id },
        data: { result: 'absent' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.findingObservation.delete({ where: { id: observation.id } }),
    ).rejects.toThrow();

    const policy = await prisma.riskPolicy.create({
      data: {
        organizationId: org.id,
        policyKey: 'org.override',
        name: 'Org override',
        version: 1,
        status: 'published',
        policySchemaVersion: 1,
        publishedAt: new Date(),
        definition: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          policyKey: 'org.override',
          factorCatalog: [],
          weights: {},
        },
      },
    });
    await expect(
      prisma.riskPolicy.update({
        where: { id: policy.id },
        data: { definition: { schemaVersion: 2 } },
      }),
    ).rejects.toThrow();

    const calculation = await prisma.riskCalculation.create({
      data: {
        organizationId: org.id,
        findingId: finding.id,
        riskPolicyId: policy.id,
        policyVersion: 1,
        policyDefinitionSha256: SHA_A,
        calculatedAt: new Date(),
        factors: { schemaVersion: JSON_SCHEMA_VERSION_V1, factors: [] },
        result: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          priority: 10,
          priorityBand: 'P4',
          dueDateRecommendationDays: 180,
          escalationRecommendation: false,
        },
        calculationEngineVersion: 'test-1',
        calculationReason: 'initial',
        inputFingerprint: SHA_B,
      },
    });
    await expect(
      prisma.riskCalculation.update({
        where: { id: calculation.id },
        data: { policyVersion: 2 },
      }),
    ).rejects.toThrow();

    const audit = await prisma.auditEvent.create({
      data: {
        organizationId: org.id,
        actorType: 'system',
        action: 'test.append',
        subjectType: 'finding',
        subjectId: finding.id,
        correlationId: randomUUID(),
        payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        schemaVersion: JSON_SCHEMA_VERSION_V1,
      },
    });
    await expect(
      prisma.auditEvent.update({
        where: { id: audit.id },
        data: { action: 'test.mutated' },
      }),
    ).rejects.toThrow();
    await expect(prisma.auditEvent.delete({ where: { id: audit.id } })).rejects.toThrow();
  });

  it('enforces risk acceptance expiration, approval, and revocation consistency', async () => {
    const org = await createOrg(`ra-${randomUUID().slice(0, 8)}`);
    const requester = await createUser(
      `ra-r-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
    );
    const approver = await createUser(`ra-a-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    await prisma.membership.create({
      data: { organizationId: org.id, userId: requester.id, role: 'member' },
    });
    await prisma.membership.create({
      data: { organizationId: org.id, userId: approver.id, role: 'admin' },
    });
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'ra-asset', assetType: 'application' },
    });
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-RA-${randomUUID().slice(0, 8)}` },
    });
    const component = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: 'npm|ra',
        ecosystem: 'npm',
        name: 'ra',
      },
    });
    const finding = await prisma.finding.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        vulnerabilityId: vulnerability.id,
        componentId: component.id,
        firstObservedAt: new Date(),
        lastObservedAt: new Date(),
      },
    });
    const startsAt = new Date('2026-01-01T00:00:00.000Z');
    const expiresAt = new Date('2026-01-31T00:00:00.000Z');
    const reviewAt = new Date('2026-01-24T00:00:00.000Z');
    await expect(
      prisma.riskAcceptance.create({
        data: {
          organizationId: org.id,
          findingId: finding.id,
          requestedByUserId: requester.id,
          reason: 'synthetic',
          startsAt,
          expiresAt: startsAt,
          reviewAt,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.riskAcceptance.create({
        data: {
          organizationId: org.id,
          findingId: finding.id,
          status: 'active',
          requestedByUserId: requester.id,
          reason: 'synthetic',
          startsAt,
          expiresAt,
          reviewAt,
        },
      }),
    ).rejects.toThrow();
    const accepted = await prisma.riskAcceptance.create({
      data: {
        organizationId: org.id,
        findingId: finding.id,
        status: 'active',
        requestedByUserId: requester.id,
        approvedByUserId: approver.id,
        approvedAt: new Date('2026-01-01T01:00:00.000Z'),
        reason: 'synthetic',
        startsAt,
        expiresAt,
        reviewAt,
      },
    });
    await expect(
      prisma.riskAcceptance.update({
        where: { id: accepted.id },
        data: { status: 'revoked', revokedAt: new Date() },
      }),
    ).rejects.toThrow();
  });

  it('rejects cross-tenant remediation assignment and evidence target mismatches', async () => {
    const orgA = await createOrg(`rem-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(`rem-b-${randomUUID().slice(0, 8)}`);
    const userB = await createUser(`rem-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const teamB = await prisma.team.create({
      data: { organizationId: orgB.id, name: 'B', slug: 'team-b' },
    });
    const assetA = await prisma.asset.create({
      data: { organizationId: orgA.id, name: 'rem-asset', assetType: 'application' },
    });
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `PATCHPILOT-REM-${randomUUID().slice(0, 8)}` },
    });
    const component = await prisma.component.create({
      data: {
        organizationId: orgA.id,
        identityKey: 'npm|rem',
        ecosystem: 'npm',
        name: 'rem',
      },
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
      prisma.remediationTask.create({
        data: {
          organizationId: orgA.id,
          findingId: finding.id,
          title: 'fix',
          assignedTeamId: teamB.id,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.evidence.create({
        data: {
          organizationId: orgA.id,
          kind: 'sbom_object',
          findingId: finding.id,
          metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        },
      }),
    ).rejects.toThrow();
    await prisma.evidence.create({
      data: {
        organizationId: orgA.id,
        kind: 'compensating_control',
        findingId: finding.id,
        metadata: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
      },
    });
    void userB;
  });

  it('enforces outbox attempt, lease, processed timestamp, and idempotency uniqueness', async () => {
    const org = await createOrg(`out-${randomUUID().slice(0, 8)}`);
    await expect(
      prisma.outboxEvent.create({
        data: {
          organizationId: org.id,
          aggregateType: 'asset',
          aggregateId: randomUUID(),
          eventType: 'asset.created',
          eventSchemaVersion: 1,
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, ids: {}, metadata: {} },
          dedupeKey: 'k1',
          attemptCount: -1,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.outboxEvent.create({
        data: {
          organizationId: org.id,
          aggregateType: 'asset',
          aggregateId: randomUUID(),
          eventType: 'asset.created',
          eventSchemaVersion: 1,
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, ids: {}, metadata: {} },
          dedupeKey: 'k2',
          status: 'claimed',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.outboxEvent.create({
        data: {
          organizationId: org.id,
          aggregateType: 'asset',
          aggregateId: randomUUID(),
          eventType: 'asset.created',
          eventSchemaVersion: 1,
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, ids: {}, metadata: {} },
          dedupeKey: 'k3',
          status: 'processed',
        },
      }),
    ).rejects.toThrow();
    await prisma.idempotencyRecord.create({
      data: {
        organizationId: org.id,
        scope: 'sbom.upload',
        keyHash: SHA_A,
        requestFingerprint: SHA_B,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'sbom.upload',
          keyHash: SHA_A,
          requestFingerprint: SHA_A,
          expiresAt: new Date(Date.now() + 60_000),
        },
      }),
    ).rejects.toThrow();
  });

  it('requires organizationId on tenant repositories, bounds pagination, and isolates tenants', async () => {
    const repos = createRepositories(prisma);
    const orgA = await repos.organizations.create({
      slug: `repo-a-${randomUUID().slice(0, 8)}`,
      name: 'Repo A',
    });
    const orgB = await repos.organizations.create({
      slug: `repo-b-${randomUUID().slice(0, 8)}`,
      name: 'Repo B',
    });
    const assetA = await repos.assets.create({
      organizationId: orgA.id,
      name: 'listed',
      assetType: 'application',
    });
    expect(await repos.assets.findById(orgB.id, assetA.id)).toBeUndefined();
    expect(repos.assets.findById.length).toBe(2);
    const page = await repos.assets.listForOrganization(orgA.id, { limit: 1000 });
    expect(page.items.length).toBeLessThanOrEqual(100);
  });

  it('commits tenant state, audit, and outbox atomically and rolls all three back together', async () => {
    const org = await prisma.organization.create({
      data: { slug: `tx-${randomUUID().slice(0, 8)}`, name: 'Tx Org' },
    });
    const user = await createUser(`tx-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`);
    const unitOfWork = createPrismaUnitOfWork({ client: prisma });

    const committed = await unitOfWork.runInTransaction(async (repos) =>
      persistTenantChangeWithAuditAndOutbox(repos, {
        organizationId: org.id,
        assetName: 'atomic-asset',
        assetType: 'application',
        actorUserId: user.id,
        correlationId: randomUUID(),
      }),
    );
    expect(
      await prisma.asset.findFirst({ where: { id: committed.assetId, organizationId: org.id } }),
    ).toBeTruthy();
    expect(
      await prisma.auditEvent.findFirst({ where: { id: committed.auditEventId } }),
    ).toBeTruthy();
    expect(
      await prisma.outboxEvent.findFirst({ where: { id: committed.outboxEventId } }),
    ).toBeTruthy();

    const beforeAssets = await prisma.asset.count({ where: { organizationId: org.id } });
    const beforeAudit = await prisma.auditEvent.count({ where: { organizationId: org.id } });
    const beforeOutbox = await prisma.outboxEvent.count({ where: { organizationId: org.id } });

    await expect(
      unitOfWork.runInTransaction(async (repos) => {
        await persistTenantChangeWithAuditAndOutbox(repos, {
          organizationId: org.id,
          assetName: 'rollback-asset',
          assetType: 'application',
          actorUserId: user.id,
          correlationId: randomUUID(),
        });
        throw new Error('force rollback');
      }),
    ).rejects.toThrow(/force rollback/);

    expect(await prisma.asset.count({ where: { organizationId: org.id } })).toBe(beforeAssets);
    expect(await prisma.auditEvent.count({ where: { organizationId: org.id } })).toBe(beforeAudit);
    expect(await prisma.outboxEvent.count({ where: { organizationId: org.id } })).toBe(
      beforeOutbox,
    );
  });

  it('restricts deleting evidentiary parents while referenced', async () => {
    const org = await createOrg(`del-${randomUUID().slice(0, 8)}`);
    const asset = await prisma.asset.create({
      data: { organizationId: org.id, name: 'del-asset', assetType: 'application' },
    });
    await prisma.sbom.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        objectKey: `org/${org.id}/del`,
        sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        byteLength: 8,
        declaredContentType: 'application/json',
        receivedAt: new Date(),
      },
    });
    await expect(prisma.asset.delete({ where: { id: asset.id } })).rejects.toThrow(
      Prisma.PrismaClientKnownRequestError,
    );
    await expect(prisma.organization.delete({ where: { id: org.id } })).rejects.toThrow();
  });

  it('runs the development seed twice without duplicating synthetic tenants', async () => {
    const env = createFoundationTestEnv();
    await seedDevelopmentData({ env, client: prisma });
    await seedDevelopmentData({ env, client: prisma });
    expect(await prisma.organization.count({ where: { slug: 'synthetic-org-a' } })).toBe(1);
    expect(await prisma.organization.count({ where: { slug: 'synthetic-org-b' } })).toBe(1);
    expect(await prisma.user.count({ where: { email: 'owner-a@synthetic.patchpilot.test' } })).toBe(
      1,
    );
  });
});
