import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeLeaseAcquirePersistenceCommand,
  createOsvRuntimeLeaseAcquireSecretForOwner,
  createOsvRuntimeRetryEligibilityQuery,
  createOsvRuntimeRunTransitionCommand,
  createOsvRuntimeStageAttemptReserveCommand,
  createOsvRuntimeStageAttemptStartCommand,
  createOsvRuntimeStageAttemptTerminalCommand,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER,
  OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
  OSV_RUNTIME_RETRY_POLICY_IDENTIFIER,
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
const ARCH = OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER;
const RETRY = OSV_RUNTIME_RETRY_POLICY_IDENTIFIER;

function expectOk<T>(result: OsvRuntimeCoordinationResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function payload(): OsvRuntimeSyncJobPayload {
  return expectOk(
    createOsvRuntimeSyncJobPayload(
      createClosedOsvRuntimeSyncJobInput({
        synchronizationReason: 'operator_production',
        requestedAt: '2026-09-07T12:00:00Z',
        correlationId: randomUUID(),
      }),
    ),
    'payload',
  );
}

describe('session 12 Batch 7-R attempt ordering and retry inspection', { timeout: 120_000 }, () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let adapters: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
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

  async function seedRunning() {
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_lease_projection"`;
    const job = payload();
    const request = expectOk(
      await adapters.requests.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRequestEnsureCommand({
            payload: job,
            idempotency: expectOk(
              createOsvRuntimeJobIdempotencyIdentity({
                workScope: job.workScope,
                reason: job.synchronizationReason,
                versionSetFingerprint: job.versionSetFingerprint,
                requestKind: 'operator_request',
                schedulerWindowId: null,
                operatorRequestId: randomUUID(),
              }),
              'idempotency',
            ),
            requestState: 'accepted',
          }),
          'ensure command',
        ),
      ),
      'request',
    );
    const run = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: request.request.id }),
          'run command',
        ),
      ),
      'run',
    );
    expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: run.run.id,
            expectedState: 'planned',
            nextState: 'waiting_for_lease',
            terminalCode: null,
            retryDisposition: null,
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: null,
          }),
          'waiting',
        ),
      ),
      'waiting',
    );
    const held = expectOk(
      await adapters.leases.acquire(
        expectOk(
          createOsvRuntimeLeaseAcquirePersistenceCommand({
            runId: run.run.id,
            secret: expectOk(
              createOsvRuntimeLeaseAcquireSecretForOwner({ holderToken: HOLDER_A }),
              'secret',
            ),
            architectureIdentifier: ARCH,
            retryPolicyIdentifier: RETRY,
            expectedLeaseRevision: null,
            expectedFencingToken: null,
          }),
          'acquire command',
        ),
      ),
      'acquire',
    );
    if (held.proof === null) {
      throw new Error('missing proof');
    }
    expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: run.run.id,
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
    return { run: run.run, proof: held.proof };
  }

  it('rejects attempt 2 while attempt 1 is planned and rejects skipped ordinals', async () => {
    const seeded = await seedRunning();
    expectOk(
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
    const earlyTwo = await adapters.attempts.reserve(
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
        'reserve 2 early',
      ),
    );
    expect(earlyTwo.ok).toBe(false);
    if (!earlyTwo.ok) {
      expect(earlyTwo.code).toBe('state_conflict');
    }
    const skipThree = await adapters.attempts.reserve(
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
        'skip 3',
      ),
    );
    expect(skipThree.ok).toBe(false);
    if (!skipThree.ok) {
      expect(skipThree.code).toBe('state_conflict');
    }
    expect(
      await prisma.osvRuntimeStageAttempt.count({
        where: { runId: seeded.run.id, stage: 'listing_page' },
      }),
    ).toBe(1);
  });

  it('does not treat retry inspection as dispatch and reserves only one next ordinal', async () => {
    const seeded = await seedRunning();
    expectOk(
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
    expectOk(
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
      'started 1',
    );
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
            retryDelayMs: 0,
          }),
          'terminal 1',
        ),
      ),
      'failed 1',
    );
    expect(failed.attempt.retryNotBefore).not.toBeNull();
    const inspectA = expectOk(
      await adapters.attempts.inspectRetryEligibility(
        expectOk(
          createOsvRuntimeRetryEligibilityQuery({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            proof: seeded.proof,
          }),
          'inspect A',
        ),
      ),
      'inspect A',
    );
    const inspectB = expectOk(
      await adapters.attempts.inspectRetryEligibility(
        expectOk(
          createOsvRuntimeRetryEligibilityQuery({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            proof: seeded.proof,
          }),
          'inspect B',
        ),
      ),
      'inspect B',
    );
    expect(inspectA.status).toBe('eligible');
    expect(inspectB.status).toBe('eligible');
    const skipThree = await adapters.attempts.reserve(
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
        'skip 3 after retryable 1',
      ),
    );
    expect(skipThree.ok).toBe(false);
    if (!skipThree.ok) {
      expect(skipThree.code).toBe('invalid_attempt_ordinal');
    }
    expect(
      await prisma.osvRuntimeStageAttempt.count({
        where: { runId: seeded.run.id, stage: 'listing_page' },
      }),
    ).toBe(1);
    const reserved = expectOk(
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
    expect(reserved.status).toBe('created');
    const duplicate = expectOk(
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
          'reserve 2 replay',
        ),
      ),
      'reserved 2 replay',
    );
    expect(duplicate.status).toBe('already_applied');
    expect(
      await prisma.osvRuntimeStageAttempt.count({
        where: { runId: seeded.run.id, stage: 'listing_page' },
      }),
    ).toBe(2);
  });

  it('preserves cancellation and does not start work after a terminal run', async () => {
    const seeded = await seedRunning();
    expectOk(
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
    const cancelled = expectOk(
      await adapters.attempts.recordTerminal(
        expectOk(
          createOsvRuntimeStageAttemptTerminalCommand({
            runId: seeded.run.id,
            stage: 'listing_page',
            targetIdentityDigest: null,
            attemptOrdinal: 1,
            expectedState: 'planned',
            terminalState: 'cancelled',
            failureCode: null,
            failureCatalog: null,
            retryDelayMs: null,
          }),
          'cancel 1',
        ),
      ),
      'cancelled 1',
    );
    expect(cancelled.attempt.state).toBe('cancelled');
    expect(cancelled.attempt.retryExhausted).toBe(false);
    const nextAfterCancel = await adapters.attempts.reserve(
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
        'reserve after cancel',
      ),
    );
    expect(nextAfterCancel.ok).toBe(false);
    if (!nextAfterCancel.ok) {
      expect(nextAfterCancel.code).toBe('state_conflict');
    }
    expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: seeded.run.id,
            expectedState: 'running',
            nextState: 'cancelled',
            terminalCode: null,
            retryDisposition: 'no_retry',
            lastAcceptedStage: null,
            cancellationBoundary: 'during_pagination',
            proof: null,
          }),
          'cancel run',
        ),
      ),
      'cancelled run',
    );
    const afterRunTerminal = await adapters.attempts.reserve(
      expectOk(
        createOsvRuntimeStageAttemptReserveCommand({
          runId: seeded.run.id,
          stage: 'parser_startup',
          targetIdentityDigest: null,
          attemptOrdinal: 1,
          versionSetFingerprint: seeded.run.versionSetFingerprint,
          selectedDelayMs: 0,
          retryDisposition: 'durable_retry',
        }),
        'reserve after run terminal',
      ),
    );
    expect(afterRunTerminal.ok).toBe(false);
    if (!afterRunTerminal.ok) {
      expect(afterRunTerminal.code).toBe('state_conflict');
    }
    expect(await prisma.finding.count()).toBe(0);
    expect(
      await prisma.osvRuntimeLeaseProjection.count({
        where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
      }),
    ).toBe(1);
  });
});
