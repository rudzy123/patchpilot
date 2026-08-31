import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  SBOM_INVALID_TRANSITION,
  SBOM_TERMINAL_STATE,
  SBOM_UPLOAD_IDEMPOTENCY_SCOPE,
} from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { isRootPrismaClient } from './guards.js';
import { createSbomPersistence } from './sbom-persistence.js';
import {
  NORMALIZATION_VERSION,
  PARSER_VERSION,
  SHA_A,
  SHA_B,
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  graphOf,
  newCorrelationId,
  outboxPayload,
  resolvedComponent,
  unknownVersionComponent,
} from './sbom-test-fixture.js';

const packageSrc = path.resolve(path.dirname(fileURLToPath(import.meta.url)));

describe('session 8 sbom persistence adapters', () => {
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

  it('keeps repository files free of Redis, object storage, and queue SDKs', () => {
    const files = [
      'sbom-metadata-persistence.ts',
      'sbom-ingestion-persistence.ts',
      'sbom-upload-idempotency.ts',
      'outbox-relay-persistence.ts',
      'background-job-execution.ts',
      'component-graph-persistence.ts',
    ];
    const banned = /ioredis|bullmq|@aws-sdk|S3Client|MinIO|process\.env/;
    for (const file of files) {
      const source = readFileSync(path.join(packageSrc, file), 'utf8');
      expect(source, file).not.toMatch(banned);
      expect(source, file).not.toContain('Idempotency-Key');
      if (file === 'outbox-relay-persistence.ts') {
        expect(source).toContain('FOR UPDATE SKIP LOCKED');
      }
      if (file === 'component-graph-persistence.ts') {
        expect(source).toContain('pg_advisory_xact_lock');
        expect(source).toContain('SELECT "last_successful_sbom_ingestion_id" AS "current_id"');
        expect(source).toContain('ReadCommitted');
      }
    }
  });

  it('scopes SBOM and ingestion reads and mutations by organization', async () => {
    const orgA = await createOrg(prisma, `ten-a-${randomUUID().slice(0, 8)}`);
    const orgB = await createOrg(prisma, `ten-b-${randomUUID().slice(0, 8)}`);
    const assetA = await createAsset(prisma, orgA.id, 'asset-a');
    const assetB = await createAsset(prisma, orgB.id, 'asset-b');
    const adapters = createSbomPersistence(prisma);
    const sbom = await adapters.sbomMetadata.insert({
      organizationId: orgA.id,
      assetId: assetA.id,
      objectKey: `org/${orgA.id}/assets/${assetA.id}/sboms/sha256/${SHA_A}`,
      sha256: SHA_A,
      byteLength: 12,
      declaredContentType: 'application/json',
      specificationType: 'cyclonedx',
      source: 'upload',
      uploadedByMembershipId: null,
      capturedAt: null,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    const ingestion = await adapters.ingestions.createAccepted({
      organizationId: orgA.id,
      sbomId: sbom.id,
      assetId: assetA.id,
      parserVersion: PARSER_VERSION,
      normalizationVersion: NORMALIZATION_VERSION,
    });
    expect(ingestion.ok).toBe(true);
    if (!ingestion.ok) {
      return;
    }
    expect(ingestion.value.normalizationVersion).toBe(NORMALIZATION_VERSION);

    expect(await adapters.sbomMetadata.findById(orgB.id, sbom.id)).toBeUndefined();
    expect(
      await adapters.sbomMetadata.findByAssetAndId(orgA.id, assetB.id, sbom.id),
    ).toBeUndefined();
    expect(await adapters.ingestions.findById(orgB.id, ingestion.value.id)).toBeUndefined();
    expect(
      await adapters.ingestions.findByAssetAndId(orgA.id, assetB.id, ingestion.value.id),
    ).toBeUndefined();
    const listed = await adapters.sbomMetadata.listForAsset(orgB.id, assetA.id);
    expect(listed.items).toHaveLength(0);
  });

  it('reserves, reclaims, and finalizes upload idempotency without persisting a raw key', async () => {
    const org = await createOrg(prisma, `idemp-${randomUUID().slice(0, 8)}`);
    const adapters = createSbomPersistence(prisma);
    const scope = `${SBOM_UPLOAD_IDEMPOTENCY_SCOPE}:${randomUUID()}`;
    const keyHash = '1'.repeat(64);
    const reservationFingerprint = '2'.repeat(64);
    const finalFingerprint = '3'.repeat(64);
    const input = {
      organizationId: org.id,
      scope,
      keyHash,
      reservationFingerprint,
      expiresAt: new Date(Date.now() + 60_000),
    };
    const first = adapters.uploadIdempotency.reserveStarted(input);
    const concurrent = adapters.uploadIdempotency.reserveStarted(input);
    const reserved = await Promise.all([first, concurrent]);
    const acquired = reserved.filter((result) => result.kind === 'acquired');
    expect(acquired).toHaveLength(1);
    const second = reserved.find((result) => result.kind !== 'acquired');
    expect(second?.kind).toBe('unexpired_started');
    const winner = acquired[0];
    if (winner === undefined || winner.kind !== 'acquired') {
      return;
    }
    expect(winner.record.reservationFingerprint).toBe(reservationFingerprint);

    const unexpired = await adapters.uploadIdempotency.findUnexpiredStarted(input);
    expect(unexpired?.id).toBe(winner.record.id);

    await prisma.idempotencyRecord.update({
      where: { id: winner.record.id },
      data: {
        createdAt: new Date(Date.now() - 60_000),
        expiresAt: new Date(Date.now() - 1000),
      },
    });
    const reclaimA = adapters.uploadIdempotency.reclaimExpiredStarted({
      ...input,
      reservationFingerprint: '4'.repeat(64),
      expiresAt: new Date(Date.now() + 60_000),
    });
    const reclaimB = adapters.uploadIdempotency.reclaimExpiredStarted({
      ...input,
      reservationFingerprint: '5'.repeat(64),
      expiresAt: new Date(Date.now() + 60_000),
    });
    const reclaims = await Promise.all([reclaimA, reclaimB]);
    const winners = reclaims.filter((result) => result.ok);
    expect(winners).toHaveLength(1);
    const reclaimed = winners[0];
    if (reclaimed === undefined || !reclaimed.ok) {
      return;
    }

    const finalized = await adapters.uploadIdempotency.finalizeCompleted({
      organizationId: org.id,
      scope,
      keyHash,
      reservationFingerprint: reclaimed.value.reservationFingerprint,
      finalFingerprint,
      responseStatus: 202,
      response: {
        schemaVersion: 1,
        sbomId: randomUUID(),
        ingestionId: randomUUID(),
      },
    });
    const staleFinalize = await adapters.uploadIdempotency.finalizeCompleted({
      organizationId: org.id,
      scope,
      keyHash,
      reservationFingerprint,
      finalFingerprint,
      responseStatus: 202,
      response: {
        schemaVersion: 1,
        sbomId: randomUUID(),
        ingestionId: randomUUID(),
      },
    });
    expect(finalized.ok || staleFinalize.ok).toBe(true);
    expect(finalized.ok && staleFinalize.ok).toBe(false);

    const completedReservation = finalized.ok
      ? finalized.value
      : staleFinalize.ok
        ? staleFinalize.value
        : null;
    expect(completedReservation).not.toBeNull();
    if (completedReservation === null || completedReservation.response === null) {
      return;
    }
    const replay = await adapters.uploadIdempotency.resolveCompletedReplay({
      organizationId: org.id,
      scope,
      keyHash,
      finalFingerprint: completedReservation.finalFingerprint ?? finalFingerprint,
    });
    expect(replay.ok).toBe(true);
    if (replay.ok && replay.value.kind === 'replay') {
      expect(replay.value.response.sbomId).toBe(completedReservation.response.sbomId);
    }
    const stored = await prisma.idempotencyRecord.findFirst({
      where: { organizationId: org.id, scope, keyHash },
    });
    expect(JSON.stringify(stored)).not.toContain('Idempotency-Key');
    expect(stored?.keyHash).toBe(keyHash);
  });

  it('claims disjoint outbox batches with a proven two-branch plan', async () => {
    const org = await createOrg(prisma, `out-${randomUUID().slice(0, 8)}`);
    const now = new Date('2026-08-30T15:00:00.000Z');
    const payload = outboxPayload();
    const pendingIds: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const row = await prisma.outboxEvent.create({
        data: {
          organizationId: org.id,
          aggregateType: 'sbom',
          aggregateId: randomUUID(),
          eventType: 'sbom.ingest',
          eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
          payload,
          dedupeKey: `pending:${randomUUID()}`,
          availableAt: new Date(now.getTime() - (3 - index) * 1000),
          status: 'pending',
        },
      });
      pendingIds.push(row.id);
    }
    const expired = await prisma.outboxEvent.create({
      data: {
        organizationId: org.id,
        aggregateType: 'sbom',
        aggregateId: randomUUID(),
        eventType: 'sbom.ingest',
        eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
        payload,
        dedupeKey: `expired:${randomUUID()}`,
        availableAt: new Date(now.getTime() - 10_000),
        status: 'claimed',
        claimedAt: new Date(now.getTime() - 9_000),
        leaseExpiresAt: new Date(now.getTime() - 1000),
      },
    });
    const active = await prisma.outboxEvent.create({
      data: {
        organizationId: org.id,
        aggregateType: 'sbom',
        aggregateId: randomUUID(),
        eventType: 'sbom.ingest',
        eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
        payload,
        dedupeKey: `active:${randomUUID()}`,
        availableAt: new Date(now.getTime() - 5000),
        status: 'claimed',
        claimedAt: now,
        leaseExpiresAt: new Date(now.getTime() + 60_000),
      },
    });
    const processed = await prisma.outboxEvent.create({
      data: {
        organizationId: org.id,
        aggregateType: 'sbom',
        aggregateId: randomUUID(),
        eventType: 'sbom.ingest',
        eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
        payload,
        dedupeKey: `processed:${randomUUID()}`,
        availableAt: new Date(now.getTime() - 20_000),
        status: 'processed',
        processedAt: now,
      },
    });

    const adapters = createSbomPersistence(prisma);
    const leaseExpiresAt = new Date(now.getTime() + 30_000);
    const [batchA, batchB] = await Promise.all([
      adapters.outboxRelay.claimDueBatch({ limit: 2, now, leaseExpiresAt }),
      adapters.outboxRelay.claimDueBatch({ limit: 2, now, leaseExpiresAt }),
    ]);
    const claimedIds = [...batchA, ...batchB].map((event) => event.id);
    expect(new Set(claimedIds).size).toBe(claimedIds.length);
    expect(claimedIds).toHaveLength(4);
    expect(claimedIds).toEqual(expect.arrayContaining([...pendingIds, expired.id]));
    expect(claimedIds).not.toContain(active.id);
    expect(claimedIds).not.toContain(processed.id);
    expect(batchA.length + batchB.length).toBeLessThanOrEqual(4);

    const wrongOrg = await adapters.outboxRelay.markProcessedAfterQueueAcceptance({
      organizationId: randomUUID(),
      eventId: claimedIds[0] ?? expired.id,
      acceptedAt: now,
      queueJobId: 'sbom.ingest:x',
    });
    expect(wrongOrg.ok).toBe(false);

    const pendingPlan = await explain(
      prisma,
      `SELECT id FROM outbox_event WHERE status = 'pending' AND available_at <= $1 ORDER BY available_at ASC, id ASC LIMIT 10`,
      [now],
    );
    const claimedPlan = await explain(
      prisma,
      `SELECT id FROM outbox_event WHERE status = 'claimed' AND lease_expires_at < $1 ORDER BY available_at ASC, id ASC LIMIT 10`,
      [now],
    );
    expect(usesIndex(pendingPlan, 'outbox_event_available_work_idx')).toBe(true);
    expect(usesIndex(claimedPlan, 'outbox_event_claimed_lease_idx')).toBe(true);
  });

  it('enqueues one background job and claims with a single winner', async () => {
    const org = await createOrg(prisma, `job-${randomUUID().slice(0, 8)}`);
    const adapters = createSbomPersistence(prisma);
    const outbox = await prisma.outboxEvent.create({
      data: {
        organizationId: org.id,
        aggregateType: 'sbom',
        aggregateId: randomUUID(),
        eventType: 'sbom.ingest',
        eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
        payload: outboxPayload(),
        dedupeKey: `job:${randomUUID()}`,
      },
    });
    const first = await adapters.backgroundJobs.enqueueQueued({
      organizationId: org.id,
      outboxEventId: outbox.id,
      jobType: 'sbom.ingest',
      dedupeKey: outbox.dedupeKey,
    });
    const duplicate = await adapters.backgroundJobs.enqueueQueued({
      organizationId: org.id,
      outboxEventId: outbox.id,
      jobType: 'sbom.ingest',
      dedupeKey: outbox.dedupeKey,
    });
    expect(duplicate.id).toBe(first.id);
    expect(await prisma.backgroundJob.count({ where: { outboxEventId: outbox.id } })).toBe(1);

    const now = new Date('2026-08-30T16:00:00.000Z');
    const lease = new Date(now.getTime() + 60_000);
    const [claimA, claimB] = await Promise.all([
      adapters.backgroundJobs.claimExecution({
        organizationId: org.id,
        jobId: first.id,
        workerIdentifier: 'worker-a',
        now,
        leaseExpiresAt: lease,
      }),
      adapters.backgroundJobs.claimExecution({
        organizationId: org.id,
        jobId: first.id,
        workerIdentifier: 'worker-b',
        now,
        leaseExpiresAt: lease,
      }),
    ]);
    const winners = [claimA, claimB].filter((result) => result.ok);
    expect(winners).toHaveLength(1);

    const foreign = await adapters.backgroundJobs.claimExecution({
      organizationId: randomUUID(),
      jobId: first.id,
      workerIdentifier: 'worker-c',
      now,
      leaseExpiresAt: lease,
    });
    expect(foreign.ok).toBe(false);

    const otherWorkerRenew = await adapters.backgroundJobs.renewLease({
      organizationId: org.id,
      jobId: first.id,
      workerIdentifier: 'not-owner',
      now,
      leaseExpiresAt: new Date(lease.getTime() + 1000),
    });
    expect(otherWorkerRenew.ok).toBe(false);

    await prisma.backgroundJob.update({
      where: { id: first.id },
      data: { leaseExpiresAt: new Date(now.getTime() - 1000) },
    });
    const reclaim = await adapters.backgroundJobs.claimExecution({
      organizationId: org.id,
      jobId: first.id,
      workerIdentifier: 'worker-d',
      now,
      leaseExpiresAt: new Date(now.getTime() + 60_000),
    });
    expect(reclaim.ok).toBe(true);
    if (!reclaim.ok) {
      return;
    }
    const succeeded = await adapters.backgroundJobs.markSucceeded({
      organizationId: org.id,
      jobId: first.id,
      workerIdentifier: 'worker-d',
      completedAt: now,
    });
    expect(succeeded.ok).toBe(true);
    const replay = await adapters.backgroundJobs.markSucceeded({
      organizationId: org.id,
      jobId: first.id,
      workerIdentifier: 'worker-d',
      completedAt: now,
    });
    expect(replay.ok).toBe(true);
    const terminal = await adapters.backgroundJobs.findIdempotentTerminal({
      organizationId: org.id,
      jobType: 'sbom.ingest',
      dedupeKey: outbox.dedupeKey,
    });
    expect(terminal?.status).toBe('succeeded');
  });

  it('persists a graph once, no-ops completed replay, and rolls back partial failure', async () => {
    const org = await createOrg(prisma, `graph-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'graph-asset');
    const sbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
    });
    const parent = resolvedComponent({
      name: 'parent',
      bomRef: 'pkg:npm/parent',
      version: '1.0.0',
    });
    const child = resolvedComponent({ name: 'child', bomRef: 'pkg:npm/child', version: '2.0.0' });
    const cycleMate = resolvedComponent({
      name: 'cycle',
      bomRef: 'pkg:npm/cycle',
      version: '3.0.0',
    });
    const unknown = unknownVersionComponent('blob', 'blob-ref');
    const adapters = createSbomPersistence(prisma);
    const graph = graphOf(
      [parent, child, cycleMate, unknown],
      [
        { fromBomRef: 'pkg:npm/parent', toBomRef: 'pkg:npm/child', relationshipType: 'depends_on' },
        { fromBomRef: 'pkg:npm/child', toBomRef: 'pkg:npm/cycle', relationshipType: 'depends_on' },
        { fromBomRef: 'pkg:npm/cycle', toBomRef: 'pkg:npm/child', relationshipType: 'depends_on' },
      ],
      'complete',
    );
    const persisted = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      graph,
      correlationId: newCorrelationId(),
    });
    expect(persisted.ok).toBe(true);

    const replay = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      graph,
      correlationId: newCorrelationId(),
    });
    expect(replay.ok).toBe(true);
    expect(
      await prisma.componentOccurrence.count({
        where: { organizationId: org.id, sbomIngestionId: ingestion.id },
      }),
    ).toBe(4);
    const unknownRow = await prisma.componentOccurrence.findFirst({
      where: { organizationId: org.id, sbomIngestionId: ingestion.id, bomRef: 'blob-ref' },
    });
    expect(unknownRow?.versionKnown).toBe(false);
    expect(unknownRow?.version).toBe('');
    const unresolved = await prisma.component.findFirst({
      where: { organizationId: org.id, identityKey: unknown.identityKey },
    });
    expect(unresolved?.ecosystem).toBeNull();
    const edges = await prisma.dependencyRelationship.findMany({
      where: { organizationId: org.id, sbomIngestionId: ingestion.id },
    });
    expect(edges).toHaveLength(3);
    expect(edges.some((edge) => edge.fromOccurrenceId === edge.toOccurrenceId)).toBe(false);
    const completed = await prisma.sbomIngestion.findUniqueOrThrow({ where: { id: ingestion.id } });
    expect(completed.state).toBe('completed');
    expect(completed.graphCompleteness).toBe('complete');
    expect(completed.componentCount).toBe(4);
    expect(completed.dependencyEdgeCount).toBe(3);
    expect(completed.leaseExpiresAt).toBeNull();
    const evidence = await prisma.sbom.findUniqueOrThrow({ where: { id: sbom.id } });
    expect(evidence.parserVersionLastSucceeded).toBe(PARSER_VERSION);
    const audit = await prisma.auditEvent.findFirst({
      where: { organizationId: org.id, action: 'sbom.ingestion.completed' },
    });
    expect(audit?.actorType).toBe('system');
    expect(audit).not.toBeNull();

    const rejected = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
      parserVersion: '0.1.1',
    });
    await prisma.sbomIngestion.update({
      where: { id: rejected.id },
      data: {
        state: 'rejected',
        completedAt: new Date(),
        failureCategory: 'validation',
        failureCode: 'schema_invalid',
      },
    });
    const incompatible = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: rejected.id,
      graph: graphOf([parent], [], 'no_dependencies'),
      correlationId: newCorrelationId(),
    });
    expect(incompatible.ok).toBe(false);
    if (!incompatible.ok) {
      expect(incompatible.error).toEqual(SBOM_TERMINAL_STATE);
    }

    const rolling = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
      parserVersion: '0.1.2',
    });
    const conflictComponent = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: parent.identityKey + '-conflict',
        ecosystem: 'npm',
        name: 'conflict',
      },
    });
    await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: rolling.id,
        componentId: conflictComponent.id,
        bomRef: parent.bomRef,
        version: '9.9.9',
        versionKnown: true,
      },
    });
    await expect(
      adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: rolling.id,
        graph: graphOf([parent], [], 'no_dependencies'),
        correlationId: newCorrelationId(),
      }),
    ).rejects.toThrow();
    expect(
      await prisma.componentOccurrence.count({
        where: { organizationId: org.id, sbomIngestionId: rolling.id },
      }),
    ).toBe(1);
    expect(
      await prisma.sbomIngestion.findUniqueOrThrow({ where: { id: rolling.id } }),
    ).toMatchObject({ state: 'processing' });
  });

  it('rolls back graph rows when audit insert fails', async () => {
    const org = await createOrg(prisma, `aud-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'audit-asset');
    const sbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_B,
      receivedAt: new Date('2026-08-30T11:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
    });
    await prisma.$executeRaw`
      CREATE OR REPLACE FUNCTION patchpilot_test_fail_graph_audit()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $$
      BEGIN
        IF NEW.correlation_id = 'fail-graph-audit' THEN
          RAISE EXCEPTION 'forced audit failure';
        END IF;
        RETURN NEW;
      END;
      $$
    `;
    await prisma.$executeRaw`
      CREATE TRIGGER patchpilot_test_fail_graph_audit
      BEFORE INSERT ON audit_event
      FOR EACH ROW
      EXECUTE FUNCTION patchpilot_test_fail_graph_audit()
    `;
    const adapters = createSbomPersistence(prisma);
    expect(isRootPrismaClient(prisma)).toBe(true);
    const parent = resolvedComponent({
      name: 'audited',
      bomRef: 'pkg:npm/audited',
      version: '1.0.0',
    });
    try {
      await expect(
        adapters.componentGraph.persistOnceForIngestion({
          organizationId: org.id,
          assetId: asset.id,
          sbomId: sbom.id,
          sbomIngestionId: ingestion.id,
          graph: graphOf([parent], [], 'no_dependencies'),
          correlationId: 'fail-graph-audit',
        }),
      ).rejects.toThrow(/forced audit failure/);
      expect(
        await prisma.componentOccurrence.count({
          where: { organizationId: org.id, sbomIngestionId: ingestion.id },
        }),
      ).toBe(0);
    } finally {
      await prisma.$executeRaw`DROP TRIGGER IF EXISTS patchpilot_test_fail_graph_audit ON audit_event`;
      await prisma.$executeRaw`DROP FUNCTION IF EXISTS patchpilot_test_fail_graph_audit()`;
    }
  });

  it('updates the asset pointer for a null or newer completed ingestion without bumping version', async () => {
    const org = await createOrg(prisma, `ptr-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'pointer-asset');
    expect(asset.version).toBe(1);
    const adapters = createSbomPersistence(prisma);
    const olderSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-08-30T09:00:00.000Z'),
    });
    const newerSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_B,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    const older = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: olderSbom.id,
      assetId: asset.id,
      createdAt: new Date('2026-08-30T11:00:00.000Z'),
    });
    const newer = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: newerSbom.id,
      assetId: asset.id,
      createdAt: new Date('2026-08-30T17:00:00.000Z'),
    });
    const graph = graphOf(
      [resolvedComponent({ name: 'only', bomRef: 'pkg:npm/only', version: '1.0.0' })],
      [],
      'no_dependencies',
    );
    await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: olderSbom.id,
      sbomIngestionId: older.id,
      graph,
      correlationId: newCorrelationId(),
    });
    const afterNull = await prisma.asset.findUniqueOrThrow({ where: { id: asset.id } });
    expect(afterNull.lastSuccessfulSbomIngestionId).toBe(older.id);
    expect(afterNull.version).toBe(1);

    await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: newerSbom.id,
      sbomIngestionId: newer.id,
      graph,
      correlationId: newCorrelationId(),
    });
    const afterNewer = await prisma.asset.findUniqueOrThrow({ where: { id: asset.id } });
    expect(afterNewer.lastSuccessfulSbomIngestionId).toBe(newer.id);
    expect(afterNewer.version).toBe(1);

    const olderAgain = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: olderSbom.id,
      assetId: asset.id,
      parserVersion: '0.1.3',
    });
    await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: olderSbom.id,
      sbomIngestionId: olderAgain.id,
      graph,
      correlationId: newCorrelationId(),
    });
    const afterOlder = await prisma.asset.findUniqueOrThrow({ where: { id: asset.id } });
    expect(afterOlder.lastSuccessfulSbomIngestionId).toBe(newer.id);
    expect(afterOlder.version).toBe(1);

    const firstRace = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: newerSbom.id,
      assetId: asset.id,
      parserVersion: '0.2.0',
      createdAt: new Date('2026-08-30T18:00:00.000Z'),
    });
    const secondRace = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: newerSbom.id,
      assetId: asset.id,
      parserVersion: '0.2.1',
      createdAt: new Date('2026-08-30T18:00:01.000Z'),
    });
    const [left, right] = await Promise.all([
      adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: newerSbom.id,
        sbomIngestionId: firstRace.id,
        graph,
        correlationId: newCorrelationId(),
      }),
      adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: newerSbom.id,
        sbomIngestionId: secondRace.id,
        graph,
        correlationId: newCorrelationId(),
      }),
    ]);
    expect(left.ok).toBe(true);
    expect(right.ok).toBe(true);
    const afterRace = await prisma.asset.findUniqueOrThrow({ where: { id: asset.id } });
    expect(afterRace.lastSuccessfulSbomIngestionId).toBe(secondRace.id);
    expect(afterRace.version).toBe(1);
  });

  it('uses createdAt then id to break pointer ties and rejects non-completed candidates', async () => {
    const org = await createOrg(prisma, `tie-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'tie-asset');
    const receivedAt = new Date('2026-08-30T10:00:00.000Z');
    const sbomA = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt,
    });
    const sbomB = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_B,
      receivedAt,
      objectKey: `org/${org.id}/assets/${asset.id}/sboms/sha256/${SHA_B}`,
    });
    const earlier = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbomA.id,
      assetId: asset.id,
      createdAt: new Date('2026-08-30T10:00:01.000Z'),
    });
    const later = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbomB.id,
      assetId: asset.id,
      createdAt: new Date('2026-08-30T10:00:02.000Z'),
    });
    const adapters = createSbomPersistence(prisma);
    const graph = graphOf(
      [resolvedComponent({ name: 'tie', bomRef: 'pkg:npm/tie', version: '1.0.0' })],
      [],
      'no_dependencies',
    );
    await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbomA.id,
      sbomIngestionId: earlier.id,
      graph,
      correlationId: newCorrelationId(),
    });
    await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: sbomB.id,
      sbomIngestionId: later.id,
      graph,
      correlationId: newCorrelationId(),
    });
    const afterCreatedAt = await prisma.asset.findUniqueOrThrow({ where: { id: asset.id } });
    expect(afterCreatedAt.lastSuccessfulSbomIngestionId).toBe(later.id);
    expect(afterCreatedAt.version).toBe(1);
  });

  it('does not update the asset pointer for a non-completed persistOnceForIngestion candidate', async () => {
    const org = await createOrg(prisma, `elig-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'eligibility-asset');
    expect(asset.version).toBe(1);
    const adapters = createSbomPersistence(prisma);
    const baselineSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-08-30T09:00:00.000Z'),
    });
    const newerSbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_B,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    const baseline = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: baselineSbom.id,
      assetId: asset.id,
    });
    const graph = graphOf(
      [resolvedComponent({ name: 'elig', bomRef: 'pkg:npm/elig', version: '1.0.0' })],
      [],
      'no_dependencies',
    );
    const completed = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: baselineSbom.id,
      sbomIngestionId: baseline.id,
      graph,
      correlationId: newCorrelationId(),
    });
    expect(completed.ok).toBe(true);
    await expectPointer(prisma, asset.id, baseline.id, 1);

    const accepted = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: newerSbom.id,
        assetId: asset.id,
        parserVersion: '0.2.0',
        normalizationVersion: NORMALIZATION_VERSION,
        state: 'accepted',
      },
    });
    const queued = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: newerSbom.id,
        assetId: asset.id,
        parserVersion: '0.2.1',
        normalizationVersion: NORMALIZATION_VERSION,
        state: 'queued',
      },
    });
    const processing = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: newerSbom.id,
      assetId: asset.id,
      parserVersion: '0.2.2',
    });
    const rejected = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: newerSbom.id,
        assetId: asset.id,
        parserVersion: '0.2.3',
        normalizationVersion: NORMALIZATION_VERSION,
        state: 'rejected',
        completedAt: new Date('2026-08-30T13:00:00.000Z'),
        failureCategory: 'validation',
        failureCode: 'schema_invalid',
      },
    });
    const quarantined = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: newerSbom.id,
        assetId: asset.id,
        parserVersion: '0.2.4',
        normalizationVersion: NORMALIZATION_VERSION,
        state: 'quarantined',
        completedAt: new Date('2026-08-30T13:00:00.000Z'),
        failureCategory: 'timeout',
        failureCode: 'parser_timeout',
      },
    });
    const failed = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: newerSbom.id,
        assetId: asset.id,
        parserVersion: '0.2.5',
        normalizationVersion: NORMALIZATION_VERSION,
        state: 'failed',
        completedAt: new Date('2026-08-30T13:00:00.000Z'),
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });

    const ineligible = [
      { row: accepted, expected: SBOM_INVALID_TRANSITION },
      { row: queued, expected: SBOM_INVALID_TRANSITION },
      { row: rejected, expected: SBOM_TERMINAL_STATE },
      { row: quarantined, expected: SBOM_TERMINAL_STATE },
      { row: failed, expected: SBOM_TERMINAL_STATE },
    ];
    for (const candidate of ineligible) {
      const result = await adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: newerSbom.id,
        sbomIngestionId: candidate.row.id,
        graph,
        correlationId: newCorrelationId(),
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toEqual(candidate.expected);
      }
      await expectPointer(prisma, asset.id, baseline.id, 1);
    }

    const selfish = resolvedComponent({
      name: 'selfish',
      bomRef: 'pkg:npm/selfish',
      version: '1.0.0',
    });
    const selfEdgeGraph = graphOf(
      [selfish],
      [
        {
          fromBomRef: 'pkg:npm/selfish',
          toBomRef: 'pkg:npm/selfish',
          relationshipType: 'depends_on',
        },
      ],
      'complete',
    );
    const beforeCompletion = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: newerSbom.id,
      sbomIngestionId: processing.id,
      graph: selfEdgeGraph,
      correlationId: newCorrelationId(),
    });
    expect(beforeCompletion.ok).toBe(false);
    expect(
      await prisma.sbomIngestion.findUniqueOrThrow({ where: { id: processing.id } }),
    ).toMatchObject({ state: 'processing' });
    await expectPointer(prisma, asset.id, baseline.id, 1);

    const afterCompletion = await adapters.componentGraph.persistOnceForIngestion({
      organizationId: org.id,
      assetId: asset.id,
      sbomId: newerSbom.id,
      sbomIngestionId: processing.id,
      graph,
      correlationId: newCorrelationId(),
    });
    expect(afterCompletion.ok).toBe(true);
    expect(
      await prisma.sbomIngestion.findUniqueOrThrow({ where: { id: processing.id } }),
    ).toMatchObject({ state: 'completed' });
    await expectPointer(prisma, asset.id, processing.id, 1);
  });

  it('breaks equal receivedAt and createdAt pointer ties by the greater PostgreSQL UUID', async () => {
    const receivedAt = new Date('2026-08-30T10:00:00.000Z');
    const createdAt = new Date('2026-08-30T11:00:00.000Z');
    const adapters = createSbomPersistence(prisma);
    const graph = graphOf(
      [resolvedComponent({ name: 'uuid-tie', bomRef: 'pkg:npm/uuid-tie', version: '1.0.0' })],
      [],
      'no_dependencies',
    );
    const pairs = [
      {
        order: 'lesser-first' as const,
        lesserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        greaterId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      },
      {
        order: 'greater-first' as const,
        lesserId: '11111111-1111-4111-8111-111111111111',
        greaterId: '22222222-2222-4222-8222-222222222222',
      },
    ];

    for (const pair of pairs) {
      const uuidOrder = await prisma.$queryRaw<Array<{ winner: string }>>`
        SELECT GREATEST(${pair.lesserId}::uuid, ${pair.greaterId}::uuid)::text AS winner
      `;
      expect(uuidOrder[0]?.winner).toBe(pair.greaterId);

      const org = await createOrg(prisma, `uuid-${pair.order}-${randomUUID().slice(0, 8)}`);
      const asset = await createAsset(prisma, org.id, `uuid-${pair.order}-asset`);
      expect(asset.version).toBe(1);
      const sbom = await createSbom(prisma, {
        organizationId: org.id,
        assetId: asset.id,
        sha256: SHA_A,
        receivedAt,
      });
      const lesser = await createProcessingIngestion(prisma, {
        id: pair.lesserId,
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        createdAt,
        parserVersion: '0.3.0',
      });
      const greater = await createProcessingIngestion(prisma, {
        id: pair.greaterId,
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        createdAt,
        parserVersion: '0.3.1',
      });
      expect(lesser.createdAt.toISOString()).toBe(createdAt.toISOString());
      expect(greater.createdAt.toISOString()).toBe(createdAt.toISOString());
      expect(lesser.createdAt.getTime()).toBe(greater.createdAt.getTime());
      expect(
        (await prisma.sbom.findUniqueOrThrow({ where: { id: sbom.id } })).receivedAt.toISOString(),
      ).toBe(receivedAt.toISOString());
      expect(lesser.id < greater.id).toBe(true);

      const first = pair.order === 'lesser-first' ? lesser : greater;
      const second = pair.order === 'lesser-first' ? greater : lesser;
      const firstResult = await adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: first.id,
        graph,
        correlationId: newCorrelationId(),
      });
      const secondResult = await adapters.componentGraph.persistOnceForIngestion({
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: second.id,
        graph,
        correlationId: newCorrelationId(),
      });
      expect(firstResult.ok).toBe(true);
      expect(secondResult.ok).toBe(true);
      await expectPointer(prisma, asset.id, pair.greaterId, 1);
    }
  });
});

async function explain(prisma: PrismaClient, sql: string, params: Date[]): Promise<unknown> {
  const rows = await prisma.$queryRawUnsafe<Array<{ 'QUERY PLAN': unknown }>>(
    `EXPLAIN (FORMAT JSON) ${sql}`,
    ...params,
  );
  return rows[0]?.['QUERY PLAN'];
}

function usesIndex(plan: unknown, indexName: string): boolean {
  return JSON.stringify(plan).includes(indexName);
}

async function expectPointer(
  prisma: PrismaClient,
  assetId: string,
  ingestionId: string,
  version: number,
): Promise<void> {
  const asset = await prisma.asset.findUniqueOrThrow({ where: { id: assetId } });
  expect(asset.lastSuccessfulSbomIngestionId).toBe(ingestionId);
  expect(asset.version).toBe(version);
}
