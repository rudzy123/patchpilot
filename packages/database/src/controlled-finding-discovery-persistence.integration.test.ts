/**
 * Disposable PostgreSQL proof for asset-scoped controlled Finding discovery.
 * The read calls the creation eligibility predicate and writes nothing.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import { createControlledFindingCreationApplication } from '@patchpilot/domain/controlled-finding-operator';
import {
  createControlledFindingDiscoveryApplication,
  encodeFindingDiscoveryCursor,
} from '@patchpilot/domain/controlled-finding-discovery';
import {
  PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATOR_ID,
  PRODUCT_MATCH_EVALUATOR_VERSION,
  PRODUCT_MATCH_MATCHING_POLICY_ID,
  PRODUCT_MATCH_MATCHING_POLICY_VERSION,
  componentEvidenceFingerprint,
  createProductMatchEvaluationComposition,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import { createControlledFindingDiscoveryPersistence } from './controlled-finding-discovery-persistence.js';
import { seedControlledFindingEvidence } from './controlled-finding-operator-seed-fixture.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import { createOrg } from './sbom-test-fixture.js';

let prisma: PrismaClient;
let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;

beforeAll(async () => {
  database = await createEphemeralDatabase('it');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

describe('controlled finding target discovery persistence', () => {
  it('returns the authoritative set, one candidate for several versions, and writes nothing', async () => {
    const world = await createWorld('eligible');
    const seeded = await seedControlledFindingEvidence(prisma, {
      label: `eligible-${world.organizationId.slice(0, 8)}`,
      organizationId: world.organizationId,
      versions: [
        { version: '1.1.0', bomRef: 'affected-a' },
        { version: '1.2.0', bomRef: 'affected-b' },
        { version: '3.0.0', bomRef: 'unaffected' },
      ],
    });
    const before = await snapshot(world.organizationId);
    const originalFetch = globalThis.fetch;
    let providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      throw new Error('provider contact');
    };
    let result;
    try {
      result = await discover(world, seeded.assetId, 10, null);
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(providerCalls).toBe(0);
    expect(await snapshot(world.organizationId)).toEqual(before);
    expect(result.status).toBe('page');
    if (result.status !== 'page') {
      return;
    }
    expect(result.page.candidates).toHaveLength(1);
    const candidate = result.page.candidates[0];
    expect(candidate?.classification).toBe('eligible_for_creation');
    if (candidate?.classification !== 'eligible_for_creation') {
      return;
    }
    const qualifying = await qualifyingIds(world.organizationId, seeded);
    expect([...candidate.acknowledgement.expectedProductMatchEvidenceIds]).toEqual(qualifying);
    expect(qualifying).toHaveLength(2);
    expect(candidate.affectedOccurrenceCount).toBe(2);
    expect(candidate.affectedVersions.values).toEqual(['1.1.0', '1.2.0']);
    expect(candidate.otherOccurrenceCount).toBe(1);
    expect(candidate.vulnerabilityPublicId).toContain('REVIEWED-');
    const foreign = await discover(await createWorld('foreign'), seeded.assetId, 10, null);
    const absent = await discover(world, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 10, null);
    expect(foreign.status).toBe('not_found');
    expect(absent.status).toBe('not_found');
    expect(JSON.stringify(foreign)).toBe(JSON.stringify(absent));
    const acknowledgement = candidate.acknowledgement;
    await addVersion(seeded, '1.4.0', 'stale-ack');
    const beforeStale = await snapshot(world.organizationId);
    const stale = await createControlledFindingCreationApplication({
      persistence: createControlledFindingCreationPersistence(prisma),
    }).execute({
      actor: actor(world, 'owner'),
      request: acknowledgement,
    });
    expect(stale.status).toBe('evidence_set_mismatch');
    expect(JSON.stringify(stale)).not.toContain(acknowledgement.expectedProductMatchEvidenceIds[0]);
    expect(await snapshot(world.organizationId)).toEqual(beforeStale);
  }, 120_000);

  it('classifies exact replay, then a changed set, and fails closed on malformed lineage', async () => {
    const world = await createWorld('replay');
    const seeded = await seedControlledFindingEvidence(prisma, {
      label: `replay-${world.organizationId.slice(0, 8)}`,
      organizationId: world.organizationId,
      versions: [{ version: '1.1.0', bomRef: 'only' }],
    });
    const first = await discover(world, seeded.assetId, 10, null);
    expect(first.status).toBe('page');
    if (
      first.status !== 'page' ||
      first.page.candidates[0]?.classification !== 'eligible_for_creation'
    ) {
      throw new Error('expected an eligible candidate');
    }
    const created = await createControlledFindingCreationApplication({
      persistence: createControlledFindingCreationPersistence(prisma),
    }).execute({
      actor: actor(world, 'owner'),
      request: first.page.candidates[0].acknowledgement,
    });
    expect(created.status).toBe('created');
    if (created.status !== 'created') {
      return;
    }
    const beforeReplay = await lineageStamp(created.findingId);
    const replay = await discover(world, seeded.assetId, 10, null);
    expect(replay.status).toBe('page');
    if (replay.status !== 'page') {
      return;
    }
    expect(replay.page.candidates[0]?.classification).toBe('exact_replay_available');
    expect(JSON.stringify(replay.page)).not.toContain(created.findingId);
    expect(await lineageStamp(created.findingId)).toEqual(beforeReplay);
    if (replay.page.candidates[0]?.classification !== 'exact_replay_available') {
      return;
    }
    const replayed = await createControlledFindingCreationApplication({
      persistence: createControlledFindingCreationPersistence(prisma),
    }).execute({
      actor: actor(world, 'owner'),
      request: replay.page.candidates[0].acknowledgement,
    });
    expect(replayed).toEqual({ status: 'already_applied', findingId: created.findingId });
    expect(await lineageStamp(created.findingId)).toEqual(beforeReplay);
    const originalAcknowledgement = first.page.candidates[0].acknowledgement;
    await addVersion(seeded, '1.3.0', 'later');
    const changed = await discover(world, seeded.assetId, 10, null);
    expect(changed.status).toBe('page');
    if (
      changed.status !== 'page' ||
      changed.page.candidates[0]?.classification !== 'existing_finding'
    ) {
      throw new Error('expected an existing finding without an acknowledgement');
    }
    expect('acknowledgement' in changed.page.candidates[0]).toBe(false);
    expect(changed.page.candidates[0].lifecycleUpdate).toBe('unavailable');
    const beforeStale = await lineageStamp(created.findingId);
    const stale = await createControlledFindingCreationApplication({
      persistence: createControlledFindingCreationPersistence(prisma),
    }).execute({
      actor: actor(world, 'owner'),
      request: originalAcknowledgement,
    });
    expect(stale).toEqual({ status: 'already_applied', findingId: created.findingId });
    expect(await lineageStamp(created.findingId)).toEqual(beforeStale);
    const corruptFingerprint = 'a'.repeat(64);
    await prisma.$executeRaw`ALTER TABLE "finding_observation" DISABLE TRIGGER "finding_observation_append_only"`;
    await prisma.$executeRaw`
      UPDATE "finding_observation"
      SET "replay_fingerprint" = ${corruptFingerprint},
          "evidence" = jsonb_set(
            "evidence",
            '{evidenceSetFingerprint}',
            to_jsonb(${corruptFingerprint}::text)
          )
      WHERE "finding_id" = ${created.findingId}::uuid
    `;
    await prisma.$executeRaw`ALTER TABLE "finding_observation" ENABLE TRIGGER "finding_observation_append_only"`;
    const malformed = await discover(world, seeded.assetId, 10, null);
    expect(malformed.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(malformed)).not.toContain('candidates');
  }, 120_000);

  it('omits normalization version 1 and oversized sets, and rejects a stale cursor', async () => {
    const world = await createWorld('bounds');
    const seeded = await seedControlledFindingEvidence(prisma, {
      label: `bounds-${world.organizationId.slice(0, 8)}`,
      organizationId: world.organizationId,
      versions: [{ version: '1.1.0', bomRef: 'current' }],
    });
    await prisma.sbomIngestion.update({
      where: { id: seeded.ingestionId },
      data: { normalizationVersion: '1' },
    });
    const hidden = await discover(world, seeded.assetId, 10, null);
    expect(hidden.status).toBe('page');
    if (hidden.status !== 'page') {
      return;
    }
    expect(hidden.page.candidates).toEqual([]);
    await prisma.sbomIngestion.update({
      where: { id: seeded.ingestionId },
      data: { normalizationVersion: '2' },
    });
    const cursor = encodeFindingDiscoveryCursor({
      ingestionId: '12121212-1212-4121-8121-121212121212',
      componentId: seeded.componentId,
      vulnerabilityId: seeded.vulnerabilityId,
    });
    const stale = await discover(world, seeded.assetId, 10, cursor);
    expect(stale.status).toBe('stale_cursor');
    expect(JSON.stringify(stale)).not.toContain(seeded.ingestionId);

    const oversizedWorld = await createWorld('oversized');
    const versions = Array.from({ length: 17 }, (_value, index) => ({
      version: `1.0.${index + 1}`,
      bomRef: `wide-${index + 1}`,
    }));
    const wide = await seedControlledFindingEvidence(prisma, {
      label: `wide-${oversizedWorld.organizationId.slice(0, 8)}`,
      organizationId: oversizedWorld.organizationId,
      versions,
    });
    const omitted = await discover(oversizedWorld, wide.assetId, 10, null);
    expect(omitted.status).toBe('page');
    if (omitted.status !== 'page') {
      return;
    }
    expect(omitted.page.candidates).toEqual([]);
    expect(omitted.page.oversizedCandidateCount).toBe(1);
    expect(JSON.stringify(omitted.page)).not.toContain(wide.componentId);
    expect(JSON.stringify(omitted.page)).not.toContain(wide.vulnerabilityId);
    expect(JSON.stringify(omitted.page)).not.toContain(wide.evidence[0]?.evidenceId);
  }, 180_000);

  it('orders two components and does not repeat a candidate on the next page', async () => {
    const world = await createWorld('page');
    const first = await seedControlledFindingEvidence(prisma, {
      label: `page-a-${world.organizationId.slice(0, 8)}`,
      organizationId: world.organizationId,
      packageName: 'reviewed-npm-alpha',
      versions: [{ version: '1.1.0', bomRef: 'alpha' }],
    });
    const second = await seedControlledFindingEvidence(prisma, {
      label: `page-b-${world.organizationId.slice(0, 8)}`,
      organizationId: world.organizationId,
      packageName: 'reviewed-npm-beta',
      attach: {
        assetId: first.assetId,
        sbomId: first.sbomId,
        ingestionId: first.ingestionId,
        sbomSha256: first.sbomSha256,
      },
      versions: [{ version: '1.1.0', bomRef: 'beta' }],
    });
    const page = await discover(world, first.assetId, 1, null);
    expect(page.status).toBe('page');
    if (page.status !== 'page' || page.page.nextCursor === null) {
      throw new Error('expected a continuation cursor');
    }
    const next = await discover(world, first.assetId, 10, page.page.nextCursor);
    expect(next.status).toBe('page');
    if (next.status !== 'page') {
      return;
    }
    const ids = [...page.page.candidates, ...next.page.candidates].map(
      (candidate) => candidate.componentId,
    );
    expect(new Set(ids).size).toBe(2);
    expect(ids.sort()).toEqual([first.componentId, second.componentId].sort());
    expect(next.page.nextCursor).toBeNull();
  }, 120_000);

  it('rejects a persisted role, organization, or actor that cannot discover before asset lookup', async () => {
    const world = await createWorld('authority');
    const absent = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    await prisma.membership.update({
      where: { id: world.membershipId },
      data: { role: 'admin' },
    });
    expect((await discover(world, absent, 10, null)).status).toBe('not_found');

    await prisma.membership.update({
      where: { id: world.membershipId },
      data: { role: 'member' },
    });
    expect((await discover(world, absent, 10, null)).status).toBe('authority_required');
    await prisma.membership.update({
      where: { id: world.membershipId },
      data: { role: 'viewer' },
    });
    expect((await discover(world, absent, 10, null)).status).toBe('authority_required');

    await prisma.membership.update({
      where: { id: world.membershipId },
      data: {
        role: 'owner',
        status: 'revoked',
        revokedAt: new Date('2026-10-08T00:00:00.000Z'),
      },
    });
    expect((await discover(world, absent, 10, null)).status).toBe('authority_required');
    await prisma.membership.update({
      where: { id: world.membershipId },
      data: { status: 'active', revokedAt: null },
    });

    const mismatched = await createControlledFindingDiscoveryApplication({
      discovery: createControlledFindingDiscoveryPersistence(prisma),
    }).execute({
      actor: {
        ...actor(world, 'owner'),
        userId: '99999999-9999-4999-8999-999999999999',
      },
      assetId: absent,
      limit: 10,
      cursor: null,
    });
    expect(mismatched.status).toBe('authority_required');

    await prisma.organization.update({
      where: { id: world.organizationId },
      data: { status: 'archived', archivedAt: new Date('2026-10-08T00:00:00.000Z') },
    });
    expect((await discover(world, absent, 10, null)).status).toBe('authority_required');
  }, 60_000);
});

async function createWorld(label: string) {
  const organization = await createOrg(prisma, `${label}-${randomUUID().slice(0, 8)}`);
  const user = await prisma.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: organization.id, userId: user.id, role: 'owner', status: 'active' },
  });
  return { organizationId: organization.id, userId: user.id, membershipId: membership.id };
}

function actor(
  world: { organizationId: string; userId: string; membershipId: string },
  role: 'owner' | 'admin' | 'member' | 'viewer',
) {
  return {
    userId: world.userId,
    sessionId: 'session-discovery',
    organizationId: world.organizationId,
    membershipId: world.membershipId,
    role,
  };
}

function discover(
  world: { organizationId: string; userId: string; membershipId: string },
  assetId: string,
  limit: number,
  cursor: string | null,
) {
  return createControlledFindingDiscoveryApplication({
    discovery: createControlledFindingDiscoveryPersistence(prisma),
  }).execute({
    actor: actor(world, 'owner'),
    assetId,
    limit,
    cursor,
  });
}

async function qualifyingIds(
  organizationId: string,
  seeded: {
    assetId: string;
    componentId: string;
    vulnerabilityId: string;
    ingestionId: string;
  },
): Promise<string[]> {
  const rows = await prisma.$queryRaw<Array<{ id: string }>>`
    SELECT id::text AS id
    FROM patchpilot_finding_creation_qualifying_evidence(
      ${organizationId}::uuid,
      ${seeded.assetId}::uuid,
      ${seeded.componentId}::uuid,
      ${seeded.vulnerabilityId}::uuid,
      ${seeded.ingestionId}::uuid
    )
  `;
  return rows.map((row) => row.id);
}

async function snapshot(organizationId: string) {
  const [
    findings,
    observations,
    links,
    evidence,
    audits,
    assets,
    occurrences,
    ingestions,
    approvals,
  ] = await Promise.all([
    prisma.finding.findMany({
      where: { organizationId },
      select: { id: true, state: true, version: true, updatedAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.findingObservation.findMany({
      where: { organizationId },
      select: { id: true, createdAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.findingCreationEvidenceLink.findMany({
      where: { organizationId },
      select: { id: true, createdAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.productMatchEvaluationEvidence.findMany({
      where: { organizationId },
      select: { id: true, createdAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.auditEvent.count({ where: { organizationId } }),
    prisma.asset.findMany({
      where: { organizationId },
      select: { id: true, updatedAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.componentOccurrence.findMany({
      where: { organizationId },
      select: { id: true, createdAt: true, version: true },
      orderBy: { id: 'asc' },
    }),
    prisma.sbomIngestion.findMany({
      where: { organizationId },
      select: { id: true, state: true, normalizationVersion: true, updatedAt: true },
      orderBy: { id: 'asc' },
    }),
    prisma.maintainerReviewedAdvisoryApproval.count(),
  ]);
  return {
    findings: findings.map((row) => ({
      id: row.id,
      state: row.state,
      version: row.version,
      updatedAt: row.updatedAt.toISOString(),
    })),
    observations: observations.map((row) => ({
      id: row.id,
      createdAt: row.createdAt.toISOString(),
    })),
    links: links.map((row) => ({ id: row.id, createdAt: row.createdAt.toISOString() })),
    evidence: evidence.map((row) => ({ id: row.id, createdAt: row.createdAt.toISOString() })),
    audits,
    approvals,
    assets: assets.map((asset) => ({ id: asset.id, updatedAt: asset.updatedAt.toISOString() })),
    occurrences: occurrences.map((row) => ({
      id: row.id,
      version: row.version,
      createdAt: row.createdAt.toISOString(),
    })),
    ingestions: ingestions.map((row) => ({
      id: row.id,
      state: row.state,
      normalizationVersion: row.normalizationVersion,
      updatedAt: row.updatedAt.toISOString(),
    })),
  };
}

async function lineageStamp(findingId: string) {
  const finding = await prisma.finding.findUniqueOrThrow({
    where: { id: findingId },
    select: { state: true, version: true, updatedAt: true, organizationId: true },
  });
  const [observations, links, audits] = await Promise.all([
    prisma.findingObservation.findMany({
      where: { findingId },
      select: { id: true, createdAt: true, replayFingerprint: true },
      orderBy: { id: 'asc' },
    }),
    prisma.findingCreationEvidenceLink.findMany({
      where: { findingId },
      select: { id: true, createdAt: true, productMatchEvaluationEvidenceId: true },
      orderBy: { id: 'asc' },
    }),
    prisma.auditEvent.count({ where: { organizationId: finding.organizationId } }),
  ]);
  return {
    state: finding.state,
    version: finding.version,
    updatedAt: finding.updatedAt.toISOString(),
    audits,
    observations: observations.map((row) => ({
      id: row.id,
      createdAt: row.createdAt.toISOString(),
      replayFingerprint: row.replayFingerprint,
    })),
    links: links.map((row) => ({
      id: row.id,
      createdAt: row.createdAt.toISOString(),
      evidenceId: row.productMatchEvaluationEvidenceId,
    })),
  };
}

async function addVersion(
  seeded: {
    organizationId?: string;
    assetId: string;
    componentId: string;
    vulnerabilityId: string;
    ingestionId: string;
    sbomId: string;
    sbomSha256: string;
    evidence: readonly { evidenceId: string; version: string }[];
  },
  version: string,
  bomRef: string,
): Promise<void> {
  const existingId = seeded.evidence[0]?.evidenceId;
  if (existingId === undefined) {
    throw new Error('missing evidence');
  }
  const evidence = await prisma.productMatchEvaluationEvidence.findUniqueOrThrow({
    where: { id: existingId },
  });
  const component = await prisma.component.findUniqueOrThrow({ where: { id: seeded.componentId } });
  const occurrence = await prisma.componentOccurrence.create({
    data: {
      organizationId: evidence.organizationId,
      assetId: seeded.assetId,
      sbomId: seeded.sbomId,
      sbomIngestionId: seeded.ingestionId,
      componentId: seeded.componentId,
      bomRef,
      version,
      versionKnown: true,
      isDirect: true,
    },
  });
  const executed = await createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  }).execute({
    commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
    organizationId: evidence.organizationId,
    componentOccurrenceId: occurrence.id,
    expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
      organizationId: evidence.organizationId,
      componentOccurrenceId: occurrence.id,
      assetId: seeded.assetId,
      sbomId: seeded.sbomId,
      sbomIngestionId: seeded.ingestionId,
      componentId: seeded.componentId,
      componentIdentityKey: component.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: component.name,
      rawObservedVersion: version,
      versionKnown: true,
      sbomSha256: seeded.sbomSha256,
    }),
    expectedNpmPackageIdentity: evidence.packageIdentityKey,
    expectedRawObservedVersion: version,
    advisoryRevisionId: evidence.advisoryRevisionId,
    approvalEvidenceId: evidence.approvalId,
    expectedContentFingerprint: evidence.contentFingerprint,
    expectedRangeFingerprint: evidence.rangeFingerprint,
    expectedVulnerabilityId: seeded.vulnerabilityId,
    evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
    evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
    matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
    matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
    productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
    productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
    correlationId: randomUUID(),
  });
  if (executed.kind !== 'recorded' || executed.projection.outcome !== 'affected') {
    throw new Error(`additional version was ${executed.kind}`);
  }
}
