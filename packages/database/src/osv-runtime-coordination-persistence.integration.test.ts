import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeLeaseAcquirePersistenceCommand,
  createOsvRuntimeLeaseAcquireSecretForOwner,
  createOsvRuntimeLeaseHeartbeatCommand,
  createOsvRuntimeLeaseOwnershipProofForOwner,
  createOsvRuntimeLeaseOwnershipQuery,
  createOsvRuntimeLeaseReleaseCommand,
  createOsvRuntimeRetryEligibilityQuery,
  createOsvRuntimeRunTransitionCommand,
  createOsvRuntimeStageAttemptReserveCommand,
  createOsvRuntimeStageAttemptStartCommand,
  createOsvRuntimeStageAttemptTerminalCommand,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  digestOsvRuntimeHolderToken,
  OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER,
  OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
  OSV_RUNTIME_RETRY_POLICY_IDENTIFIER,
  type OsvRuntimeCoordinationPersistencePort,
  type OsvRuntimeCoordinationResult,
  type OsvRuntimeSyncJobPayload,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const HOLDER_A = '44444444-4444-4444-8444-444444444444';
const HOLDER_B = '55555555-5555-4555-8555-555555555555';
const HOLDER_C = '66666666-6666-4666-8666-666666666666';
const ARCH = OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER;
const RETRY = OSV_RUNTIME_RETRY_POLICY_IDENTIFIER;

function expectOk<T>(result: OsvRuntimeCoordinationResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function payload(
  reason: 'scheduler' | 'operator_canary' | 'operator_production',
  correlationId = randomUUID(),
  requestedAt = '2026-09-07T12:00:00Z',
): OsvRuntimeSyncJobPayload {
  return expectOk(
    createOsvRuntimeSyncJobPayload(
      createClosedOsvRuntimeSyncJobInput({
        synchronizationReason: reason,
        requestedAt,
        correlationId,
      }),
    ),
    'payload',
  );
}

function ensureCommand(
  job: OsvRuntimeSyncJobPayload,
  identity: {
    readonly requestKind: 'scheduler_window' | 'operator_request';
    readonly schedulerWindowId: string | null;
    readonly operatorRequestId: string | null;
  },
) {
  const idempotency = expectOk(
    createOsvRuntimeJobIdempotencyIdentity({
      workScope: job.workScope,
      reason: job.synchronizationReason,
      versionSetFingerprint: job.versionSetFingerprint,
      requestKind: identity.requestKind,
      schedulerWindowId: identity.schedulerWindowId,
      operatorRequestId: identity.operatorRequestId,
    }),
    'idempotency',
  );
  return expectOk(
    createOsvRuntimeSynchronizationRequestEnsureCommand({
      payload: job,
      idempotency,
      requestState: 'accepted',
    }),
    'ensure command',
  );
}

describe('session 12 Batch 7 OSV runtime coordination adapters', { timeout: 120_000 }, () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let adapters: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    adapters = createOsvRuntimeCoordinationPersistence(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function resetLease(): Promise<void> {
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_lease_projection"`;
  }

  async function seedRun(
    reason: 'scheduler' | 'operator_canary' | 'operator_production' = 'operator_production',
  ) {
    const job = payload(reason);
    const command =
      reason === 'scheduler'
        ? ensureCommand(job, {
            requestKind: 'scheduler_window',
            schedulerWindowId: `window:${randomUUID()}`,
            operatorRequestId: null,
          })
        : ensureCommand(job, {
            requestKind: 'operator_request',
            schedulerWindowId: null,
            operatorRequestId: randomUUID(),
          });
    const request = expectOk(await adapters.requests.ensure(command), 'request');
    const run = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: request.request.id }),
          'run command',
        ),
      ),
      'run',
    );
    return { job, request: request.request, run: run.run };
  }

  async function acquireWith(
    factory: OsvRuntimeCoordinationPersistencePort,
    runId: string,
    holderToken: string,
    expected?: { revision: string; fencing: string } | null,
  ) {
    const secret = expectOk(createOsvRuntimeLeaseAcquireSecretForOwner({ holderToken }), 'secret');
    return factory.leases.acquire(
      expectOk(
        createOsvRuntimeLeaseAcquirePersistenceCommand({
          runId,
          secret,
          architectureIdentifier: ARCH,
          retryPolicyIdentifier: RETRY,
          expectedLeaseRevision: expected?.revision ?? null,
          expectedFencingToken: expected?.fencing ?? null,
        }),
        'acquire command',
      ),
    );
  }

  async function acquire(
    runId: string,
    holderToken: string,
    expected?: { revision: string; fencing: string } | null,
  ) {
    return acquireWith(adapters, runId, holderToken, expected);
  }

  it('ensures requests idempotently and detects immutable conflicts', async () => {
    const job = payload('operator_production');
    const operatorRequestId = randomUUID();
    const command = ensureCommand(job, {
      requestKind: 'operator_request',
      schedulerWindowId: null,
      operatorRequestId,
    });
    const created = expectOk(await adapters.requests.ensure(command), 'created');
    expect(created.status).toBe('created');
    const replay = expectOk(await adapters.requests.ensure(command), 'replay');
    expect(replay.status).toBe('already_applied');
    expect(replay.request.id).toBe(created.request.id);
    const other = payload('operator_canary');
    const conflict = await adapters.requests.ensure(
      ensureCommand(other, {
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId,
      }),
    );
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
    const later = payload(
      'operator_production',
      job.correlationId as ReturnType<typeof randomUUID>,
      '2026-09-07T12:01:00Z',
    );
    const requestedAtConflict = await adapters.requests.ensure(
      ensureCommand(later, {
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId,
      }),
    );
    expect(requestedAtConflict.ok).toBe(false);
    if (!requestedAtConflict.ok) {
      expect(requestedAtConflict.code).toBe('immutable_conflict');
    }
    expect(JSON.stringify(created)).not.toContain(HOLDER_A);
    expect(JSON.stringify(created)).not.toMatch(/SELECT |Prisma|holder_token_digest/i);
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
    expect(
      await prisma.osvRuntimeSynchronizationRequest.count({
        where: { operatorRequestId },
      }),
    ).toBe(1);
    const otherCorrelation = payload(
      'operator_production',
      randomUUID() as ReturnType<typeof randomUUID>,
      job.requestedAt,
    );
    const correlationConflict = await adapters.requests.ensure(
      ensureCommand(otherCorrelation, {
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId,
      }),
    );
    expect(correlationConflict.ok).toBe(false);
    if (!correlationConflict.ok) {
      expect(correlationConflict.code).toBe('immutable_conflict');
    }
    expect(await prisma.vulnerabilitySyncRun.count()).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(0);
  });

  it('derives canary runs from canary requests and never treats Redis identity as a run key', async () => {
    const seeded = await seedRun('operator_canary');
    expect(seeded.run.workScope).toBe(seeded.request.workScope);
    expect(seeded.run.workScope).toBe('osv_runtime_canary_scope_crates_io_rustsec_v1');
    expect(seeded.request.synchronizationReason).toBe('operator_canary');
    expect(seeded.request.canaryPolicyIdentifier).not.toBeNull();
    expect(seeded.run.redisJobIdIsAuthoritative).toBe(false);
    expect(
      await prisma.osvRuntimeSynchronizationRun.count({ where: { requestId: seeded.request.id } }),
    ).toBe(1);
  });

  it('reuses one run for duplicate delivery and does not treat Redis identity as authority', async () => {
    const seeded = await seedRun();
    const replay = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: seeded.request.id }),
          'run replay command',
        ),
      ),
      'run replay',
    );
    expect(replay.status).toBe('already_applied');
    expect(replay.run.id).toBe(seeded.run.id);
    expect(replay.run.redisJobIdIsAuthoritative).toBe(false);
    expect(
      await prisma.osvRuntimeSynchronizationRun.count({ where: { requestId: seeded.request.id } }),
    ).toBe(1);
  });

  it('acquires, heartbeats, and releases with database time and digest-only storage', async () => {
    await resetLease();
    const seeded = await seedRun();
    const first = expectOk(await acquire(seeded.run.id, HOLDER_A), 'acquire');
    expect(first.outcome).toBe('acquired');
    expect(first.proof).not.toBeNull();
    const stored = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    expect(stored.holderTokenDigest).toBe(
      expectOk(digestOsvRuntimeHolderToken(HOLDER_A), 'digest'),
    );
    expect(stored.rowRevision).toBe(1n);
    expect(stored.fencingToken).toBe(1n);
    expect(JSON.stringify(first)).not.toContain(HOLDER_A);
    expect(JSON.stringify(first)).not.toContain(stored.holderTokenDigest);
    const same = expectOk(await acquire(seeded.run.id, HOLDER_A), 'same owner');
    expect(same.outcome).toBe('already_held_by_same_owner');
    expect(same.projection.fencingToken).toBe('1');
    const other = expectOk(await acquire(seeded.run.id, HOLDER_B), 'other');
    expect(other.outcome).toBe('held_by_other');
    expect(other.proof).toBeNull();
    expect(JSON.stringify(other)).not.toContain(stored.holderTokenDigest);
    const proof = first.proof;
    if (proof === null) {
      throw new Error('missing proof');
    }
    const beat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(createOsvRuntimeLeaseHeartbeatCommand({ proof }), 'heartbeat command'),
      ),
      'heartbeat',
    );
    expect(beat.outcome).toBe('accepted');
    expect(beat.projection.fencingToken).toBe(first.projection.fencingToken);
    expect(BigInt(beat.projection.leaseRevision)).toBeGreaterThan(
      BigInt(first.projection.leaseRevision),
    );
    const staleRevisionBeat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(
          createOsvRuntimeLeaseHeartbeatCommand({ proof }),
          'stale revision heartbeat command',
        ),
      ),
      'stale revision heartbeat',
    );
    expect(staleRevisionBeat.outcome).toBe('ownership_lost');
    if (beat.proof === null) {
      throw new Error('missing heartbeat proof');
    }
    const released = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof: beat.proof, reason: 'completed' }),
          'release command',
        ),
      ),
      'release',
    );
    expect(released.outcome).toBe('released');
    expect(BigInt(released.projection.fencingToken)).toBeGreaterThan(
      BigInt(beat.projection.fencingToken),
    );
    expect(
      await prisma.osvRuntimeLeaseProjection.count({
        where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
      }),
    ).toBe(1);
    const replayRelease = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof: beat.proof, reason: 'completed' }),
          'release replay command',
        ),
      ),
      'release replay',
    );
    expect(replayRelease.outcome).toBe('already_released');
    expect(replayRelease.projection.leaseRevision).toBe(released.projection.leaseRevision);
    const foreignProof = expectOk(
      createOsvRuntimeLeaseOwnershipProofForOwner({
        scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
        runId: seeded.run.id,
        holderToken: HOLDER_B,
        leaseRevision: beat.proof.leaseRevision,
        fencingToken: beat.proof.fencingToken,
        acquiredAt: beat.proof.acquiredAt,
        heartbeatAt: beat.proof.heartbeatAt,
        expiresAt: beat.proof.expiresAt,
      }),
      'foreign proof',
    );
    const otherRelease = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof: foreignProof, reason: 'completed' }),
          'other release command',
        ),
      ),
      'other release',
    );
    expect(otherRelease.outcome).toBe('stale_owner');
    const reacquired = expectOk(await acquire(seeded.run.id, HOLDER_A), 'reacquire');
    expect(reacquired.outcome).toBe('acquired');
    expect(BigInt(reacquired.projection.fencingToken)).toBeGreaterThan(
      BigInt(released.projection.fencingToken),
    );
  });

  it('lets exactly one concurrent stale takeover win and rejects the prior owner', async () => {
    await resetLease();
    const firstSeed = await seedRun();
    const secondSeed = await seedRun();
    const thirdSeed = await seedRun();
    const initial = expectOk(await acquire(firstSeed.run.id, HOLDER_A), 'initial acquire');
    if (initial.proof === null) {
      throw new Error('missing initial proof');
    }
    await prisma.$executeRaw`
      UPDATE "osv_runtime_lease_projection"
      SET
        "heartbeat_at" = "acquired_at",
        "expires_at" = "acquired_at" + INTERVAL '1 millisecond',
        "row_revision" = "row_revision" + 1,
        "updated_at" = CURRENT_TIMESTAMP
      WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
    `;
    const expired = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    const expected = {
      revision: expired.rowRevision.toString(),
      fencing: expired.fencingToken.toString(),
    };
    const expiredHeartbeat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(
          createOsvRuntimeLeaseHeartbeatCommand({ proof: initial.proof }),
          'expired heartbeat command',
        ),
      ),
      'expired heartbeat',
    );
    expect(expiredHeartbeat.outcome).toBe('expired');
    const contenderA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const contenderB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const factoryA = createOsvRuntimeCoordinationPersistence(contenderA);
    const factoryB = createOsvRuntimeCoordinationPersistence(contenderB);
    try {
      const results = await Promise.all([
        acquireWith(factoryA, secondSeed.run.id, HOLDER_B, expected),
        acquireWith(factoryB, thirdSeed.run.id, HOLDER_C, expected),
      ]);
      const outcomes = results.map((result) => (result.ok ? result.value.outcome : result.code));
      expect(outcomes.sort()).toEqual(['held_by_other', 'stale_takeover_acquired']);
      const winner = results.find(
        (result) => result.ok && result.value.outcome === 'stale_takeover_acquired',
      );
      if (winner === undefined || !winner.ok || winner.value.proof === null) {
        throw new Error('expected one takeover winner');
      }
      expect(winner.value.projection.runId).not.toBe(firstSeed.run.id);
      const staleHeartbeat = expectOk(
        await adapters.leases.heartbeat(
          expectOk(
            createOsvRuntimeLeaseHeartbeatCommand({ proof: initial.proof }),
            'stale heartbeat command',
          ),
        ),
        'stale heartbeat',
      );
      expect(staleHeartbeat.outcome).toBe('ownership_lost');
      const staleRelease = expectOk(
        await adapters.leases.release(
          expectOk(
            createOsvRuntimeLeaseReleaseCommand({ proof: initial.proof, reason: 'completed' }),
            'stale release command',
          ),
        ),
        'stale release',
      );
      expect(staleRelease.outcome).toBe('stale_owner');
      const staleOwnership = expectOk(
        await adapters.leases.validateOwnership(
          expectOk(
            createOsvRuntimeLeaseOwnershipQuery({
              proof: initial.proof,
              expectedRunId: firstSeed.run.id,
            }),
            'stale ownership command',
          ),
        ),
        'stale ownership',
      );
      expect(staleOwnership.authorized).toBe(false);
      const staleComplete = await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: firstSeed.run.id,
            expectedState: 'running',
            nextState: 'completed',
            terminalCode: null,
            retryDisposition: 'no_retry',
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: initial.proof,
          }),
          'stale complete command',
        ),
      );
      expect(staleComplete.ok).toBe(false);
    } finally {
      await contenderA.$disconnect();
      await contenderB.$disconnect();
    }
  });

  it('reserves immutable attempts, starts them, records retry-not-before from database time, and exhausts ordinal 3', async () => {
    await resetLease();
    const seeded = await seedRun();
    const waiting = expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: seeded.run.id,
            expectedState: 'planned',
            nextState: 'waiting_for_lease',
            terminalCode: null,
            retryDisposition: null,
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: null,
          }),
          'waiting command',
        ),
      ),
      'waiting',
    );
    expect(waiting.run.state).toBe('waiting_for_lease');
    const held = expectOk(await acquire(seeded.run.id, HOLDER_A), 'lease for attempts');
    if (held.proof === null) {
      throw new Error('missing proof');
    }
    const running = expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: seeded.run.id,
            expectedState: 'waiting_for_lease',
            nextState: 'running',
            terminalCode: null,
            retryDisposition: null,
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: held.proof,
          }),
          'running command',
        ),
      ),
      'running',
    );
    expect(running.run.state).toBe('running');
    const reserve1 = expectOk(
      await adapters.attempts.reserve(
        expectOk(
          createOsvRuntimeStageAttemptReserveCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 1,
            versionSetFingerprint: seeded.run.versionSetFingerprint,
            selectedDelayMs: 0,
            retryDisposition: 'durable_retry',
          }),
          'reserve 1',
        ),
      ),
      'reserved 1',
    );
    expect(reserve1.status).toBe('created');
    const replay = expectOk(
      await adapters.attempts.reserve(
        expectOk(
          createOsvRuntimeStageAttemptReserveCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 1,
            versionSetFingerprint: seeded.run.versionSetFingerprint,
            selectedDelayMs: 0,
            retryDisposition: 'durable_retry',
          }),
          'reserve replay',
        ),
      ),
      'reserve replay',
    );
    expect(replay.status).toBe('already_applied');
    const started = expectOk(
      await adapters.attempts.start(
        expectOk(
          createOsvRuntimeStageAttemptStartCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 1,
          }),
          'start 1',
        ),
      ),
      'started',
    );
    expect(started.attempt.state).toBe('running');
    const failed = expectOk(
      await adapters.attempts.recordTerminal(
        expectOk(
          createOsvRuntimeStageAttemptTerminalCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 1,
            expectedState: 'running',
            terminalState: 'retryable_failed',
            failureCode: 'listing_timeout',
            failureCatalog: 'listing_transport',
            retryDelayMs: 30000,
          }),
          'terminal 1',
        ),
      ),
      'failed 1',
    );
    expect(failed.attempt.state).toBe('retryable_failed');
    expect(failed.attempt.retryNotBefore).not.toBeNull();
    expect(failed.attempt.retryExhausted).toBe(false);
    const tooEarly = expectOk(
      await adapters.attempts.inspectRetryEligibility(
        expectOk(
          createOsvRuntimeRetryEligibilityQuery({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            proof: held.proof,
          }),
          'inspect early',
        ),
      ),
      'inspect early',
    );
    expect(tooEarly.status).toBe('too_early');
    const retryWait = expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: seeded.run.id,
            expectedState: 'running',
            nextState: 'retry_wait',
            terminalCode: null,
            retryDisposition: 'durable_retry',
            lastAcceptedStage: 'listing_page',
            cancellationBoundary: null,
            proof: held.proof,
          }),
          'retry wait command',
        ),
      ),
      'retry wait',
    );
    expect(retryWait.run.state).toBe('retry_wait');
    const reserve4 = createOsvRuntimeStageAttemptReserveCommand({
      runId: seeded.run.id,
      stage: 'listing_page',
      targetIdentityDigest: null,
      attemptOrdinal: 4,
      versionSetFingerprint: seeded.run.versionSetFingerprint,
      selectedDelayMs: 0,
      retryDisposition: 'durable_retry',
    });
    expect(reserve4.ok).toBe(false);
    expectOk(
      await adapters.attempts.reserve(
        expectOk(
          createOsvRuntimeStageAttemptReserveCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 2,
            versionSetFingerprint: seeded.run.versionSetFingerprint,
            selectedDelayMs: 1000,
            retryDisposition: 'durable_retry',
          }),
          'reserve 2',
        ),
      ),
      'reserved 2',
    );
    expectOk(
      await adapters.attempts.start(
        expectOk(
          createOsvRuntimeStageAttemptStartCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 2,
          }),
          'start 2',
        ),
      ),
      'started 2',
    );
    expectOk(
      await adapters.attempts.recordTerminal(
        expectOk(
          createOsvRuntimeStageAttemptTerminalCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 2,
            expectedState: 'running',
            terminalState: 'retryable_failed',
            failureCode: 'listing_timeout',
            failureCatalog: 'listing_transport',
            retryDelayMs: 4000,
          }),
          'terminal 2',
        ),
      ),
      'failed 2',
    );
    expectOk(
      await adapters.attempts.reserve(
        expectOk(
          createOsvRuntimeStageAttemptReserveCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 3,
            versionSetFingerprint: seeded.run.versionSetFingerprint,
            selectedDelayMs: 4000,
            retryDisposition: 'no_retry',
          }),
          'reserve 3',
        ),
      ),
      'reserved 3',
    );
    expectOk(
      await adapters.attempts.start(
        expectOk(
          createOsvRuntimeStageAttemptStartCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 3,
          }),
          'start 3',
        ),
      ),
      'started 3',
    );
    const exhausted = expectOk(
      await adapters.attempts.recordTerminal(
        expectOk(
          createOsvRuntimeStageAttemptTerminalCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 3,
            expectedState: 'running',
            terminalState: 'retryable_failed',
            failureCode: 'listing_timeout',
            failureCatalog: 'listing_transport',
            retryDelayMs: 1000,
          }),
          'terminal 3',
        ),
      ),
      'exhausted',
    );
    expect(exhausted.attempt.state).toBe('exhausted');
    expect(exhausted.attempt.retryExhausted).toBe(true);
    expect(exhausted.attempt.retryNotBefore).toBeNull();
    expect(exhausted.attempt.failureCode).toBe('listing_timeout');
    const status = expectOk(
      await adapters.attempts.inspectRetryEligibility(
        expectOk(
          createOsvRuntimeRetryEligibilityQuery({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            proof: held.proof,
          }),
          'inspect exhausted',
        ),
      ),
      'inspect exhausted',
    );
    expect(status.status).toBe('exhausted');
    const parserThree = createOsvRuntimeStageAttemptReserveCommand({
      runId: seeded.run.id,
      stage: 'parser_execution_timeout',
      targetIdentityDigest: null,
      attemptOrdinal: 3,
      versionSetFingerprint: seeded.run.versionSetFingerprint,
      selectedDelayMs: 4000,
      retryDisposition: 'no_retry',
    });
    expect(parserThree.ok).toBe(false);
    expect(await prisma.finding.count()).toBe(0);
  });
});
