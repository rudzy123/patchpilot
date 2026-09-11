import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Prisma, PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const FINGERPRINT = 'a'.repeat(64);
const HOLDER_DIGEST = 'b'.repeat(64);
const TARGET_DIGEST = 'c'.repeat(64);
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const PRODUCTION_SCOPE = 'osv_runtime_production_scope_six_prefix_v1';
const CANARY_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const NOW = new Date('2026-09-07T12:00:00.000Z');
const HEARTBEAT = new Date('2026-09-07T12:01:00.000Z');
const EXPIRES = new Date('2026-09-07T12:16:00.000Z');
const RETRY_AT = new Date('2026-09-07T12:00:01.000Z');
const RETRY_AFTER_TERMINAL = new Date('2026-09-07T12:01:01.000Z');
const BIGINT_BEYOND_SAFE = 9_007_199_254_740_993n;
const BIGINT_MAX = 9_223_372_036_854_775_807n;

const srcDir = path.dirname(fileURLToPath(import.meta.url));

function productionRequest(
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput {
  return {
    jobType: 'intelligence.osv.sync',
    jobSchemaVersion: 'osv_runtime_sync_job_schema_v1',
    synchronizationReason: 'scheduler',
    workScope: PRODUCTION_SCOPE,
    leaseScope: LEASE_SCOPE,
    catalogScope: 'osv_gcs_six_prefix_public_export_v1',
    versionSetFingerprint: FINGERPRINT,
    requestedAt: NOW,
    createdAt: NOW,
    correlationId: randomUUID(),
    requestKind: 'scheduler_window',
    schedulerWindowId: `window:${randomUUID()}`,
    operatorRequestId: null,
    requestState: 'accepted',
    ...overrides,
  };
}

function canaryRequest(
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput {
  return productionRequest({
    synchronizationReason: 'operator_canary',
    workScope: CANARY_SCOPE,
    requestKind: 'operator_request',
    schedulerWindowId: null,
    operatorRequestId: randomUUID(),
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    ...overrides,
  });
}

function operatorProductionRequest(
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput {
  return productionRequest({
    synchronizationReason: 'operator_production',
    requestKind: 'operator_request',
    schedulerWindowId: null,
    operatorRequestId: randomUUID(),
    ...overrides,
  });
}

function plannedRun(
  request: {
    id: string;
    workScope: string;
    synchronizationReason: string;
    versionSetFingerprint: string;
    leaseScope: string;
  },
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput {
  const canary = request.workScope === CANARY_SCOPE;
  return {
    requestId: request.id,
    workScope:
      request.workScope as Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput['workScope'],
    leaseScope: request.leaseScope,
    synchronizationReason:
      request.synchronizationReason as Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput['synchronizationReason'],
    paginationPolicyIdentifier: canary
      ? 'osv_disabled_first_provider_canary_policy_v1'
      : 'osv_listing_pagination_policy_v1',
    versionSetFingerprint: request.versionSetFingerprint,
    runtimeArchitectureIdentifier: 'osv_runtime_enablement_architecture_v1',
    synchronizationAlgorithmIdentifier: 'osv_catalog_sync_algorithm_v1',
    retryPolicyIdentifier: 'osv_runtime_retry_policy_v1',
    state: 'planned',
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function heldLease(
  runId: string,
  overrides: Partial<Prisma.OsvRuntimeLeaseProjectionUncheckedCreateInput> = {},
): Prisma.OsvRuntimeLeaseProjectionUncheckedCreateInput {
  return {
    scope: LEASE_SCOPE,
    runId,
    holderTokenDigest: HOLDER_DIGEST,
    rowRevision: 1n,
    fencingToken: 1n,
    state: 'held',
    acquiredAt: NOW,
    heartbeatAt: HEARTBEAT,
    expiresAt: EXPIRES,
    createdAt: NOW,
    updatedAt: HEARTBEAT,
    ...overrides,
  };
}

function listingAttempt(
  runId: string,
  overrides: Partial<Prisma.OsvRuntimeStageAttemptUncheckedCreateInput> = {},
): Prisma.OsvRuntimeStageAttemptUncheckedCreateInput {
  return {
    runId,
    stage: 'listing_page',
    attemptOrdinal: 1,
    retryPolicyIdentifier: 'osv_runtime_retry_policy_v1',
    state: 'planned',
    retryDisposition: 'durable_retry',
    nominalDelayMs: 0,
    selectedDelayMs: 0,
    retryExhausted: false,
    versionSetFingerprint: FINGERPRINT,
    createdAt: NOW,
    ...overrides,
  };
}

describe('session 12 Batch 6 OSV runtime coordination SQL constraints', { timeout: 90_000 }, () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
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

  async function resetLeaseProjection(): Promise<void> {
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_lease_projection"`;
  }

  it('does not seed runtime coordination, catalog, Finding, or tenant rows', async () => {
    expect(await prisma.osvRuntimeSynchronizationRequest.count()).toBe(0);
    expect(await prisma.osvRuntimeSynchronizationRun.count()).toBe(0);
    expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(0);
    expect(await prisma.osvRuntimeStageAttempt.count()).toBe(0);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
  });

  it('accepts scheduler, operator canary, and operator production requests', async () => {
    const scheduler = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const canary = await prisma.osvRuntimeSynchronizationRequest.create({
      data: canaryRequest(),
    });
    const production = await prisma.osvRuntimeSynchronizationRequest.create({
      data: operatorProductionRequest(),
    });
    expect(scheduler.jobType).toBe('intelligence.osv.sync');
    expect(canary.workScope).toBe(CANARY_SCOPE);
    expect(production.synchronizationReason).toBe('operator_production');
    expect(canary.canaryPolicyIdentifier).toBe('osv_disabled_first_provider_canary_policy_v1');
    expect(scheduler.canaryPolicyIdentifier).toBeNull();
  });

  it('rejects duplicate operator and scheduler idempotency identities', async () => {
    const operatorId = randomUUID();
    await prisma.osvRuntimeSynchronizationRequest.create({
      data: operatorProductionRequest({ operatorRequestId: operatorId }),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: operatorProductionRequest({ operatorRequestId: operatorId }),
      }),
    ).rejects.toThrow();

    const windowId = `window:${randomUUID()}`;
    await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest({ schedulerWindowId: windowId }),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: productionRequest({ schedulerWindowId: windowId }),
      }),
    ).rejects.toThrow();
    const otherFingerprint = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest({
        schedulerWindowId: windowId,
        versionSetFingerprint: 'd'.repeat(64),
      }),
    });
    expect(otherFingerprint.versionSetFingerprint).toBe('d'.repeat(64));
  });

  it('rejects invalid job type, reason, canary/production mismatches, and fingerprints', async () => {
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: productionRequest({ jobType: 'intelligence.sync' }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_synchronization_request" (
          "job_type", "job_schema_version", "synchronization_reason", "work_scope",
          "lease_scope", "catalog_scope", "version_set_fingerprint", "requested_at",
          "correlation_id", "request_kind", "scheduler_window_id", "request_state"
        ) VALUES (
          'intelligence.osv.sync', 'osv_runtime_sync_job_schema_v1', 'manual',
          'osv_runtime_production_scope_six_prefix_v1',
          ${LEASE_SCOPE}, 'osv_gcs_six_prefix_public_export_v1', ${FINGERPRINT},
          ${NOW}, ${randomUUID()}::uuid, 'scheduler_window', 'window-x', 'accepted'
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_synchronization_request" (
          "job_type", "job_schema_version", "synchronization_reason", "work_scope",
          "lease_scope", "catalog_scope", "version_set_fingerprint", "requested_at",
          "correlation_id", "request_kind", "operator_request_id", "request_state"
        ) VALUES (
          'intelligence.osv.sync', 'osv_runtime_sync_job_schema_v1', 'operator_canary',
          'osv_runtime_canary_scope_crates_io_rustsec_v1',
          ${LEASE_SCOPE}, 'osv_gcs_six_prefix_public_export_v1', ${FINGERPRINT},
          ${NOW}, ${randomUUID()}::uuid, 'operator_request', ${randomUUID()}::uuid, 'accepted'
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: operatorProductionRequest({
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: productionRequest({ versionSetFingerprint: 'A'.repeat(64) }),
      }),
    ).rejects.toThrow();
  });

  it('creates one run per request and rejects a second unrelated run', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    expect(run.requestId).toBe(request.id);
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(request),
      }),
    ).rejects.toThrow();
  });

  it('rejects canary/production and cross-scope run mismatches', async () => {
    const canary = await prisma.osvRuntimeSynchronizationRequest.create({
      data: canaryRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(canary, {
          workScope: PRODUCTION_SCOPE,
          synchronizationReason: 'operator_production',
          paginationPolicyIdentifier: 'osv_listing_pagination_policy_v1',
        }),
      }),
    ).rejects.toThrow();
    const production = await prisma.osvRuntimeSynchronizationRequest.create({
      data: operatorProductionRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(production, {
          workScope: CANARY_SCOPE,
          synchronizationReason: 'operator_canary',
          paginationPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
        }),
      }),
    ).rejects.toThrow();
  });

  it('enforces run terminal timestamp and completion/failure invariants', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(request, { state: 'completed', terminalAt: NOW }),
      }),
    ).rejects.toThrow();
    const failedRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(failedRequest, {
          state: 'failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
        }),
      }),
    ).rejects.toThrow();
    const completedRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(completedRequest, {
          state: 'completed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          terminalCode: 'failed',
        }),
      }),
    ).rejects.toThrow();
    const okFailed = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(
        await prisma.osvRuntimeSynchronizationRequest.create({ data: productionRequest() }),
        {
          state: 'failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          terminalCode: 'lost_lease',
          retryDisposition: 'no_retry',
        },
      ),
    });
    expect(okFailed.state).toBe('failed');
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_synchronization_run" (
          "request_id", "work_scope", "lease_scope", "synchronization_reason",
          "pagination_policy_identifier", "version_set_fingerprint",
          "runtime_architecture_identifier", "synchronization_algorithm_identifier",
          "retry_policy_identifier", "state", "updated_at"
        ) VALUES (
          ${request.id}::uuid, ${PRODUCTION_SCOPE}::osv_runtime_work_scope, ${LEASE_SCOPE},
          'scheduler'::osv_runtime_synchronization_reason, 'osv_listing_pagination_policy_v1',
          ${FINGERPRINT}, 'osv_runtime_enablement_architecture_v1',
          'osv_catalog_sync_algorithm_v1', 'osv_runtime_retry_policy_v1',
          'active'::osv_runtime_run_state, ${NOW}
        )
      `,
    ).rejects.toThrow();
  });

  it('pins run fingerprint to the request through the composite foreign key', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.update({
        where: { id: run.id },
        data: { versionSetFingerprint: 'e'.repeat(64) },
      }),
    ).rejects.toThrow();
  });

  it('accepts held and released lease projections and rejects a second scope row', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    const held = await prisma.osvRuntimeLeaseProjection.create({
      data: heldLease(run.id),
    });
    expect(held.state).toBe('held');
    expect(held.releasedAt).toBeNull();
    const released = await prisma.osvRuntimeLeaseProjection.update({
      where: { scope: LEASE_SCOPE },
      data: {
        state: 'released',
        releasedAt: HEARTBEAT,
        releaseReason: 'completed',
        rowRevision: 2n,
        fencingToken: 2n,
        updatedAt: HEARTBEAT,
      },
    });
    expect(released.releaseReason).toBe('completed');
    expect(released.fencingToken).toBe(2n);
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { rowRevision: 2n, fencingToken: 2n }),
      }),
    ).rejects.toThrow();
  });

  it('rejects malformed holder digests, non-positive integers, and timestamp mismatches', async () => {
    await resetLeaseProjection();
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { holderTokenDigest: 'B'.repeat(64) }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { rowRevision: 0n }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { fencingToken: 0n }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { heartbeatAt: new Date('2026-09-07T11:59:00.000Z') }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { expiresAt: HEARTBEAT }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { state: 'released', releaseReason: 'completed' }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { releasedAt: HEARTBEAT }),
      }),
    ).rejects.toThrow();
  });

  it('persists BIGINT revision and fencing values beyond JavaScript safe integers', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await resetLeaseProjection();
    const created = await prisma.osvRuntimeLeaseProjection.create({
      data: heldLease(run.id, {
        rowRevision: BIGINT_BEYOND_SAFE,
        fencingToken: BIGINT_MAX,
      }),
    });
    const reloaded = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: LEASE_SCOPE },
    });
    expect(created.rowRevision).toBe(BIGINT_BEYOND_SAFE);
    expect(reloaded.rowRevision).toBe(BIGINT_BEYOND_SAFE);
    expect(reloaded.fencingToken).toBe(BIGINT_MAX);
    expect(typeof reloaded.rowRevision).toBe('bigint');
    expect(reloaded.rowRevision > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true);
  });

  it('rejects concurrent duplicate lease-scope inserts', async () => {
    await resetLeaseProjection();
    const firstRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const secondRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const firstRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(firstRequest),
    });
    const secondRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(secondRequest),
    });
    const results = await Promise.allSettled([
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(firstRun.id, { rowRevision: 1n, fencingToken: 1n }),
      }),
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(secondRun.id, { rowRevision: 1n, fencingToken: 1n }),
      }),
    ]);
    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    const rejected = results.filter((result) => result.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(1);
  });

  it('accepts ordinals 1-3 and rejects 0, 4, and negatives', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, { attemptOrdinal: 1 }),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        attemptOrdinal: 2,
        nominalDelayMs: 1000,
        selectedDelayMs: 400,
      }),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        attemptOrdinal: 3,
        nominalDelayMs: 4000,
        selectedDelayMs: 2000,
        retryDisposition: 'no_retry',
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, { attemptOrdinal: 1, stage: 'parser_startup' }),
      }),
    ).resolves.toBeTruthy();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, { attemptOrdinal: 0 }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          attemptOrdinal: 4,
          nominalDelayMs: 4000,
          selectedDelayMs: 0,
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, { attemptOrdinal: -1 }),
      }),
    ).rejects.toThrow();
  });

  it('enforces attempt terminal, delay, exhaustion, and parser-timeout ordinals', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        state: 'succeeded',
        startedAt: NOW,
        terminalAt: HEARTBEAT,
        retryDisposition: 'no_retry',
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_startup',
          state: 'succeeded',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          retryDisposition: 'no_retry',
          failureCode: 'timeout',
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_startup',
          state: 'retryable_failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          retryDisposition: 'durable_retry',
        }),
      }),
    ).rejects.toThrow();
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'parser_startup',
        state: 'retryable_failed',
        startedAt: NOW,
        terminalAt: HEARTBEAT,
        failureCode: 'timeout',
        failureCatalog: 'parser',
        retryNotBefore: RETRY_AFTER_TERMINAL,
        retryDisposition: 'durable_retry',
      }),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'artifact_attachment',
        state: 'permanent_failed',
        startedAt: NOW,
        terminalAt: HEARTBEAT,
        failureCode: 'immutable_conflict',
        failureCatalog: 'storage',
        retryDisposition: 'no_retry',
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'database_stage',
          state: 'planned',
          terminalAt: HEARTBEAT,
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'database_stage',
          state: 'succeeded',
          startedAt: NOW,
          retryDisposition: 'no_retry',
        }),
      }),
    ).rejects.toThrow();
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'provider_body_retrieval',
        attemptOrdinal: 3,
        nominalDelayMs: 4000,
        selectedDelayMs: 0,
        state: 'exhausted',
        startedAt: NOW,
        terminalAt: HEARTBEAT,
        failureCode: 'http_429',
        failureCatalog: 'retrieval',
        retryDisposition: 'retry_exhausted',
        retryExhausted: true,
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_capacity',
          attemptOrdinal: 3,
          nominalDelayMs: 4000,
          selectedDelayMs: 0,
          state: 'retryable_failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          failureCode: 'parser_capacity_unavailable',
          failureCatalog: 'runtime_coordination',
          retryNotBefore: RETRY_AT,
          retryDisposition: 'durable_retry',
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_execution_timeout',
          attemptOrdinal: 3,
          nominalDelayMs: 4000,
          selectedDelayMs: 0,
        }),
      }),
    ).rejects.toThrow();
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'parser_execution_timeout',
        attemptOrdinal: 2,
        nominalDelayMs: 1000,
        selectedDelayMs: 10,
        state: 'exhausted',
        startedAt: NOW,
        terminalAt: HEARTBEAT,
        failureCode: 'timeout',
        failureCatalog: 'parser',
        retryDisposition: 'retry_exhausted',
        retryExhausted: true,
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_capacity',
          attemptOrdinal: 2,
          nominalDelayMs: 1000,
          selectedDelayMs: -1,
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_capacity',
          attemptOrdinal: 2,
          nominalDelayMs: 1000,
          selectedDelayMs: 30_001,
        }),
      }),
    ).rejects.toThrow();
  });

  it('rejects a duplicate natural attempt key and accepts a new ordinal or different target', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'provider_body_retrieval',
        targetIdentityDigest: TARGET_DIGEST,
        attemptOrdinal: 1,
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'provider_body_retrieval',
          targetIdentityDigest: TARGET_DIGEST,
          attemptOrdinal: 1,
        }),
      }),
    ).rejects.toThrow();
    const secondOrdinal = await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'provider_body_retrieval',
        targetIdentityDigest: TARGET_DIGEST,
        attemptOrdinal: 2,
        nominalDelayMs: 1000,
        selectedDelayMs: 500,
      }),
    });
    expect(secondOrdinal.attemptOrdinal).toBe(2);
    const otherTarget = await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'provider_body_retrieval',
        targetIdentityDigest: 'e'.repeat(64),
        attemptOrdinal: 1,
      }),
    });
    expect(otherTarget.targetIdentityDigest).toBe('e'.repeat(64));
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'listing_page',
        targetIdentityDigest: null,
        attemptOrdinal: 1,
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'listing_page',
          targetIdentityDigest: null,
          attemptOrdinal: 1,
        }),
      }),
    ).rejects.toThrow();
  });

  it('restricts deletion of request, run, and attempt evidence', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await resetLeaseProjection();
    await prisma.osvRuntimeLeaseProjection.create({ data: heldLease(run.id) });
    const attempt = await prisma.osvRuntimeStageAttempt.create({ data: listingAttempt(run.id) });
    await expect(
      prisma.osvRuntimeSynchronizationRequest.delete({ where: { id: request.id } }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeSynchronizationRun.delete({ where: { id: run.id } }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.delete({ where: { id: attempt.id } }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeSynchronizationRequest.update({
        where: { id: request.id },
        data: { requestState: 'superseded' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.delete({ where: { scope: LEASE_SCOPE } }),
    ).rejects.toThrow(/cannot be deleted|fencing token must not reset|restrict_violation/);
    expect(await prisma.osvRuntimeLeaseProjection.count({ where: { scope: LEASE_SCOPE } })).toBe(1);
    expect(await prisma.osvRuntimeSynchronizationRun.count({ where: { id: run.id } })).toBe(1);
  });

  it('keeps runtime tables free of tenant, token, body, and Finding columns', async () => {
    const forbidden = await prisma.$queryRaw<Array<{ table_name: string; column_name: string }>>`
      SELECT table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN (
          'osv_runtime_synchronization_request',
          'osv_runtime_synchronization_run',
          'osv_runtime_lease_projection',
          'osv_runtime_stage_attempt'
        )
        AND column_name IN (
          'organization_id',
          'tenant_id',
          'user_id',
          'asset_id',
          'component_id',
          'component_occurrence_id',
          'finding_id',
          'finding_observation_id',
          'evidence_id',
          'risk_calculation_id',
          'holder_token',
          'page_token',
          'token_digest',
          'body',
          'url',
          'payload'
        )
    `;
    expect(forbidden).toEqual([]);
    const jsonColumns = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name LIKE 'osv_runtime_%'
        AND data_type IN ('json', 'jsonb')
    `;
    expect(jsonColumns).toEqual([]);
    const schema = readFileSync(path.join(srcDir, '../prisma/schema.prisma'), 'utf8');
    const start = schema.indexOf('model OsvRuntimeSynchronizationRequest');
    const end = schema.indexOf('\nmodel OsvListingObservationEvidenceSet {');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const block = schema.slice(start, end);
    expect(block).not.toContain('organizationId');
    expect(block).not.toContain('findingId');
    expect(block).not.toContain('holderToken ');
    expect(block).not.toContain('pageToken');
    expect(block).toContain('holderTokenDigest');
    expect(block).toContain('rowRevision');
    expect(block).toContain('fencingToken');
    expect(block).toContain('BigInt');
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.findingObservation.count()).toBe(0);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
  });

  it('keeps schema free of acquire methods and leaves runtime composition unregistered', () => {
    expect(existsSync(path.join(srcDir, 'osv-runtime-coordination-persistence.ts'))).toBe(true);
    const schema = readFileSync(path.join(srcDir, '../prisma/schema.prisma'), 'utf8');
    expect(schema).not.toContain('acquire(');
    expect(schema).not.toContain('heartbeat(');
    expect(schema).not.toContain('takeover(');
    expect(schema).not.toContain('executeRetry');
    expect(schema).not.toContain('claimRetry');
    const adapter = readFileSync(
      path.join(srcDir, 'osv-runtime-coordination-persistence.ts'),
      'utf8',
    );
    expect(adapter).toContain('createOsvRuntimeCoordinationPersistence');
    expect(adapter).not.toContain('executeRetry');
    expect(adapter).not.toContain('setTimeout(');
  });

  it('rejects malformed fingerprints, including whitespace, prefix, JSON, and Unicode digits', async () => {
    const fingerprints = [
      '',
      'a'.repeat(63),
      'a'.repeat(65),
      ` ${'a'.repeat(64)}`,
      `${'a'.repeat(64)} `,
      `sha256:${'a'.repeat(58)}`,
      '{"k":1}',
      `\uFF11${'a'.repeat(63)}`,
      'A'.repeat(64),
    ];
    for (const versionSetFingerprint of fingerprints) {
      await expect(
        prisma.$executeRaw`
          INSERT INTO "osv_runtime_synchronization_request" (
            "job_type", "job_schema_version", "synchronization_reason", "work_scope",
            "lease_scope", "catalog_scope", "version_set_fingerprint", "requested_at",
            "correlation_id", "request_kind", "scheduler_window_id", "request_state"
          ) VALUES (
            'intelligence.osv.sync', 'osv_runtime_sync_job_schema_v1', 'scheduler',
            'osv_runtime_production_scope_six_prefix_v1',
            ${LEASE_SCOPE}, 'osv_gcs_six_prefix_public_export_v1', ${versionSetFingerprint},
            ${NOW}, ${randomUUID()}::uuid, 'scheduler_window', ${`window:${randomUUID()}`}, 'accepted'
          )
        `,
      ).rejects.toThrow();
    }
  });

  it('rejects canary/production substitutions through direct SQL', async () => {
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_synchronization_request" (
          "job_type", "job_schema_version", "synchronization_reason", "work_scope",
          "lease_scope", "catalog_scope", "version_set_fingerprint", "requested_at",
          "correlation_id", "request_kind", "scheduler_window_id", "request_state"
        ) VALUES (
          'intelligence.osv.sync', 'osv_runtime_sync_job_schema_v1', 'scheduler',
          'osv_runtime_canary_scope_crates_io_rustsec_v1',
          ${LEASE_SCOPE}, 'osv_gcs_six_prefix_public_export_v1', ${FINGERPRINT},
          ${NOW}, ${randomUUID()}::uuid, 'scheduler_window', ${`window:${randomUUID()}`}, 'accepted'
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_synchronization_request" (
          "job_type", "job_schema_version", "synchronization_reason", "work_scope",
          "lease_scope", "catalog_scope", "version_set_fingerprint", "requested_at",
          "correlation_id", "canary_policy_identifier", "request_kind",
          "operator_request_id", "request_state"
        ) VALUES (
          'intelligence.osv.sync', 'osv_runtime_sync_job_schema_v1', 'operator_production',
          'osv_runtime_production_scope_six_prefix_v1',
          ${LEASE_SCOPE}, 'osv_gcs_six_prefix_public_export_v1', ${FINGERPRINT},
          ${NOW}, ${randomUUID()}::uuid, 'osv_disabled_first_provider_canary_policy_v1',
          'operator_request', ${randomUUID()}::uuid, 'accepted'
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({
          workScope: PRODUCTION_SCOPE,
        }),
      }),
    ).rejects.toThrow();
  });

  it('rejects concurrent duplicate request, run, and attempt identities', async () => {
    const operatorId = randomUUID();
    const requestResults = await Promise.allSettled([
      prisma.osvRuntimeSynchronizationRequest.create({
        data: operatorProductionRequest({ operatorRequestId: operatorId }),
      }),
      prisma.osvRuntimeSynchronizationRequest.create({
        data: operatorProductionRequest({ operatorRequestId: operatorId }),
      }),
    ]);
    expect(requestResults.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(requestResults.filter((result) => result.status === 'rejected')).toHaveLength(1);

    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const runResults = await Promise.allSettled([
      prisma.osvRuntimeSynchronizationRun.create({ data: plannedRun(request) }),
      prisma.osvRuntimeSynchronizationRun.create({ data: plannedRun(request) }),
    ]);
    expect(runResults.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(runResults.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(
      await prisma.osvRuntimeSynchronizationRun.count({ where: { requestId: request.id } }),
    ).toBe(1);

    const run = await prisma.osvRuntimeSynchronizationRun.findUniqueOrThrow({
      where: { requestId: request.id },
    });
    const attemptResults = await Promise.allSettled([
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, { stage: 'parser_capacity', attemptOrdinal: 1 }),
      }),
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, { stage: 'parser_capacity', attemptOrdinal: 1 }),
      }),
    ]);
    expect(attemptResults.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(attemptResults.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('allows a stale held lease and rejects contradictory lease timestamps', async () => {
    await resetLeaseProjection();
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    const stale = await prisma.osvRuntimeLeaseProjection.create({
      data: heldLease(run.id, {
        acquiredAt: new Date('2000-01-01T00:00:00.000Z'),
        heartbeatAt: new Date('2000-01-01T00:01:00.000Z'),
        expiresAt: new Date('2000-01-01T00:16:00.000Z'),
        createdAt: new Date('2000-01-01T00:00:00.000Z'),
        updatedAt: new Date('2000-01-01T00:01:00.000Z'),
      }),
    });
    expect(stale.state).toBe('held');
    expect(stale.expiresAt < new Date()).toBe(true);
    await expect(
      prisma.osvRuntimeLeaseProjection.update({
        where: { scope: LEASE_SCOPE },
        data: {
          state: 'released',
          releasedAt: new Date('1999-12-31T23:59:00.000Z'),
          releaseReason: 'completed',
          rowRevision: 2n,
          fencingToken: 2n,
          updatedAt: HEARTBEAT,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeLeaseProjection.create({
        data: heldLease(run.id, { fencingToken: -1n, rowRevision: 3n }),
      }),
    ).rejects.toThrow();
  });

  it('supports heartbeat, release, and reacquisition without deleting the lease row', async () => {
    await resetLeaseProjection();
    const firstRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const secondRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const firstRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(firstRequest),
    });
    const secondRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(secondRequest),
    });
    await prisma.osvRuntimeLeaseProjection.create({ data: heldLease(firstRun.id) });
    const heartbeat = await prisma.osvRuntimeLeaseProjection.update({
      where: { scope: LEASE_SCOPE },
      data: {
        rowRevision: 2n,
        heartbeatAt: new Date('2026-09-07T12:02:00.000Z'),
        expiresAt: new Date('2026-09-07T12:17:00.000Z'),
        updatedAt: new Date('2026-09-07T12:02:00.000Z'),
      },
    });
    expect(heartbeat.fencingToken).toBe(1n);
    expect(heartbeat.rowRevision).toBe(2n);
    await expect(
      prisma.osvRuntimeLeaseProjection.update({
        where: { scope: LEASE_SCOPE },
        data: {
          rowRevision: 3n,
          fencingToken: 2n,
          heartbeatAt: new Date('2026-09-07T12:03:00.000Z'),
          expiresAt: new Date('2026-09-07T12:18:00.000Z'),
          updatedAt: new Date('2026-09-07T12:03:00.000Z'),
        },
      }),
    ).rejects.toThrow(/heartbeat cannot change fencing token|restrict_violation/);
    await expect(
      prisma.osvRuntimeLeaseProjection.update({
        where: { scope: LEASE_SCOPE },
        data: {
          rowRevision: 1n,
          updatedAt: HEARTBEAT,
        },
      }),
    ).rejects.toThrow(/row revision must increase|restrict_violation/);
    const released = await prisma.osvRuntimeLeaseProjection.update({
      where: { scope: LEASE_SCOPE },
      data: {
        state: 'released',
        releasedAt: new Date('2026-09-07T12:03:00.000Z'),
        releaseReason: 'completed',
        rowRevision: 3n,
        fencingToken: 2n,
        updatedAt: new Date('2026-09-07T12:03:00.000Z'),
      },
    });
    expect(released.state).toBe('released');
    expect(released.fencingToken).toBe(2n);
    const reacquired = await prisma.osvRuntimeLeaseProjection.update({
      where: { scope: LEASE_SCOPE },
      data: {
        state: 'held',
        runId: secondRun.id,
        holderTokenDigest: 'f'.repeat(64),
        releasedAt: null,
        releaseReason: null,
        rowRevision: 4n,
        fencingToken: 3n,
        acquiredAt: HEARTBEAT,
        heartbeatAt: HEARTBEAT,
        expiresAt: EXPIRES,
        updatedAt: HEARTBEAT,
      },
    });
    expect(reacquired.runId).toBe(secondRun.id);
    expect(reacquired.fencingToken).toBe(3n);
    expect(reacquired.holderTokenDigest).toBe('f'.repeat(64));
    await expect(
      prisma.osvRuntimeLeaseProjection.update({
        where: { scope: LEASE_SCOPE },
        data: {
          rowRevision: 5n,
          fencingToken: 1n,
          updatedAt: HEARTBEAT,
        },
      }),
    ).rejects.toThrow(/cannot decrease|restrict_violation/);
  });

  it('lets exactly one concurrent stale takeover win', async () => {
    await resetLeaseProjection();
    const firstRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const secondRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const thirdRequest = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const firstRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(firstRequest),
    });
    const secondRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(secondRequest),
    });
    const thirdRun = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(thirdRequest),
    });
    await prisma.osvRuntimeLeaseProjection.create({
      data: heldLease(firstRun.id, {
        acquiredAt: new Date('2000-01-01T00:00:00.000Z'),
        heartbeatAt: new Date('2000-01-01T00:01:00.000Z'),
        expiresAt: new Date('2000-01-01T00:16:00.000Z'),
        createdAt: new Date('2000-01-01T00:00:00.000Z'),
        updatedAt: new Date('2000-01-01T00:01:00.000Z'),
      }),
    });
    const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const results = await Promise.allSettled([
        clientA.$executeRaw`
          UPDATE "osv_runtime_lease_projection"
          SET
            "run_id" = ${secondRun.id}::uuid,
            "holder_token_digest" = ${'f'.repeat(64)},
            "row_revision" = "row_revision" + 1,
            "fencing_token" = "fencing_token" + 1,
            "acquired_at" = CURRENT_TIMESTAMP,
            "heartbeat_at" = CURRENT_TIMESTAMP,
            "expires_at" = CURRENT_TIMESTAMP + INTERVAL '900 seconds',
            "updated_at" = CURRENT_TIMESTAMP
          WHERE "scope" = ${LEASE_SCOPE}
            AND "row_revision" = 1
            AND "fencing_token" = 1
            AND "state" = 'held'
            AND CURRENT_TIMESTAMP >= "expires_at"
        `,
        clientB.$executeRaw`
          UPDATE "osv_runtime_lease_projection"
          SET
            "run_id" = ${thirdRun.id}::uuid,
            "holder_token_digest" = ${'e'.repeat(64)},
            "row_revision" = "row_revision" + 1,
            "fencing_token" = "fencing_token" + 1,
            "acquired_at" = CURRENT_TIMESTAMP,
            "heartbeat_at" = CURRENT_TIMESTAMP,
            "expires_at" = CURRENT_TIMESTAMP + INTERVAL '900 seconds',
            "updated_at" = CURRENT_TIMESTAMP
          WHERE "scope" = ${LEASE_SCOPE}
            AND "row_revision" = 1
            AND "fencing_token" = 1
            AND "state" = 'held'
            AND CURRENT_TIMESTAMP >= "expires_at"
        `,
      ]);
      const fulfilled = results.filter(
        (result): result is PromiseFulfilledResult<number> => result.status === 'fulfilled',
      );
      expect(fulfilled).toHaveLength(2);
      const updated = fulfilled.map((result) => result.value).sort((left, right) => left - right);
      expect(updated).toEqual([0, 1]);
      const winner = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
        where: { scope: LEASE_SCOPE },
      });
      expect(winner.rowRevision).toBe(2n);
      expect(winner.fencingToken).toBe(2n);
      expect([secondRun.id, thirdRun.id]).toContain(winner.runId);
      expect(winner.runId).not.toBe(firstRun.id);
      const staleOwnerUpdate = await prisma.$executeRaw`
        UPDATE "osv_runtime_lease_projection"
        SET
          "row_revision" = "row_revision" + 1,
          "updated_at" = CURRENT_TIMESTAMP
        WHERE "scope" = ${LEASE_SCOPE}
          AND "run_id" = ${firstRun.id}::uuid
          AND "holder_token_digest" = ${HOLDER_DIGEST}
          AND "fencing_token" = 1
      `;
      expect(staleOwnerUpdate).toBe(0);
    } finally {
      await clientA.$disconnect();
      await clientB.$disconnect();
    }
  });

  it('allows planned-to-running-to-terminal attempt transitions and freezes the terminal row', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    const attempt = await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, { stage: 'database_stage' }),
    });
    const running = await prisma.osvRuntimeStageAttempt.update({
      where: { id: attempt.id },
      data: { state: 'running', startedAt: NOW },
    });
    expect(running.state).toBe('running');
    const succeeded = await prisma.osvRuntimeStageAttempt.update({
      where: { id: attempt.id },
      data: {
        state: 'succeeded',
        terminalAt: HEARTBEAT,
        retryDisposition: 'no_retry',
      },
    });
    expect(succeeded.state).toBe('succeeded');
    await expect(
      prisma.osvRuntimeStageAttempt.update({
        where: { id: attempt.id },
        data: { state: 'cancelled', terminalAt: HEARTBEAT, retryDisposition: 'no_retry' },
      }),
    ).rejects.toThrow(/terminal stage attempts are immutable|restrict_violation/);
    await expect(
      prisma.osvRuntimeStageAttempt.update({
        where: { id: attempt.id },
        data: { attemptOrdinal: 2 },
      }),
    ).rejects.toThrow(/identity fields are immutable|restrict_violation/);
  });

  it('rejects inventory-convergence retry, parser-timeout ordinal 3, and oversized retry-not-before', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'inventory_convergence',
          attemptOrdinal: 2,
          nominalDelayMs: 1000,
          selectedDelayMs: 0,
          retryDisposition: 'no_retry',
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'inventory_convergence',
          state: 'retryable_failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          failureCode: 'inventory_did_not_converge',
          failureCatalog: 'listing_pagination',
          retryNotBefore: RETRY_AFTER_TERMINAL,
          retryDisposition: 'durable_retry',
        }),
      }),
    ).rejects.toThrow();
    await prisma.osvRuntimeStageAttempt.create({
      data: listingAttempt(run.id, {
        stage: 'inventory_convergence',
        retryDisposition: 'no_retry',
      }),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_startup',
          state: 'retryable_failed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          failureCode: 'timeout',
          failureCatalog: 'parser',
          retryNotBefore: new Date('2026-09-07T12:01:31.000Z'),
          retryDisposition: 'durable_retry',
        }),
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "osv_runtime_stage_attempt" (
          "run_id", "stage", "attempt_ordinal", "retry_policy_identifier", "state",
          "retry_disposition", "nominal_delay_ms", "selected_delay_ms", "retry_exhausted",
          "version_set_fingerprint"
        ) VALUES (
          ${run.id}::uuid, 'listing_page', 1.5, 'osv_runtime_retry_policy_v1', 'planned',
          'durable_retry', 0, 0, FALSE, ${FINGERPRINT}
        )
      `,
    ).rejects.toThrow();
  });

  it('rejects completed runs with durable retry and cancelled attempts with catalog-only failure', async () => {
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    await expect(
      prisma.osvRuntimeSynchronizationRun.create({
        data: plannedRun(request, {
          state: 'completed',
          startedAt: NOW,
          terminalAt: HEARTBEAT,
          retryDisposition: 'durable_retry',
        }),
      }),
    ).rejects.toThrow();
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(
        await prisma.osvRuntimeSynchronizationRequest.create({ data: productionRequest() }),
      ),
    });
    await expect(
      prisma.osvRuntimeStageAttempt.create({
        data: listingAttempt(run.id, {
          stage: 'parser_startup',
          state: 'cancelled',
          terminalAt: HEARTBEAT,
          retryDisposition: 'no_retry',
          failureCatalog: 'parser',
        }),
      }),
    ).rejects.toThrow();
  });

  it('rejects BIGINT fencing overflow past the signed maximum', async () => {
    await resetLeaseProjection();
    const request = await prisma.osvRuntimeSynchronizationRequest.create({
      data: productionRequest(),
    });
    const run = await prisma.osvRuntimeSynchronizationRun.create({
      data: plannedRun(request),
    });
    await prisma.osvRuntimeLeaseProjection.create({
      data: heldLease(run.id, { fencingToken: BIGINT_MAX, rowRevision: 1n }),
    });
    await expect(
      prisma.$executeRaw`
        UPDATE "osv_runtime_lease_projection"
        SET
          "row_revision" = "row_revision" + 1,
          "fencing_token" = "fencing_token" + 1,
          "run_id" = ${run.id}::uuid,
          "updated_at" = CURRENT_TIMESTAMP
        WHERE "scope" = ${LEASE_SCOPE}
      `,
    ).rejects.toThrow();
  });
});
