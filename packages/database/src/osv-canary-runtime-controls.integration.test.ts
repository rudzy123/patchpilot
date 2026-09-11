/**
 * Session 13 Batch 2E heartbeat controller plus Batch 7 adapter integration.
 * Disposable PostgreSQL only. No provider contact, lease takeover, or OSV
 * enablement.
 */

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  canaryHeartbeatPortsFromRuntimePersistence,
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryHeartbeatStartContext,
  createOsvCanaryLeaseHeartbeatController,
  createOsvRuntimeHaltStatePort,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeLeaseAcquirePersistenceCommand,
  createOsvRuntimeLeaseAcquireSecretForOwner,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  createOsvRuntimeTrustedHaltSnapshot,
  OSV_CANARY_HEARTBEAT_INTERVAL_MS,
  OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER,
  OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
  OSV_RUNTIME_RETRY_POLICY_IDENTIFIER,
  readOsvCanaryHeartbeatReleaseProof,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const HOLDER = '44444444-4444-4444-8444-444444444444';
const ARCH = OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER;
const RETRY = OSV_RUNTIME_RETRY_POLICY_IDENTIFIER;

function expectOk<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: string },
  label: string,
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function createFakeClock(start = 0): OsvCanaryMonotonicClockPort & {
  advance(ms: number): void;
} {
  let now = start;
  return {
    now: () => now,
    advance(ms) {
      now += ms;
    },
  };
}

function createFakeScheduler(clock: { now(): number }): OsvCanaryOneShotSchedulerPort & {
  pendingCount(): number;
  fireDue(): void;
} {
  const items: Array<{ fireAt: number; callback: () => void; cancelled: boolean }> = [];
  return {
    schedule(delayMs, callback) {
      const item = { fireAt: clock.now() + delayMs, callback, cancelled: false };
      items.push(item);
      return {
        cancel() {
          item.cancelled = true;
        },
      };
    },
    pendingCount() {
      return items.filter((item) => !item.cancelled).length;
    },
    fireDue() {
      const now = clock.now();
      for (const item of items) {
        if (!item.cancelled && item.fireAt <= now) {
          item.cancelled = true;
          item.callback();
        }
      }
    },
  };
}

describe('session 13 Batch 2E canary heartbeat adapter coordination', { timeout: 120_000 }, () => {
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

  async function seedCanaryRun() {
    const job = expectOk(
      createOsvRuntimeSyncJobPayload(
        createClosedOsvRuntimeSyncJobInput({
          synchronizationReason: 'operator_canary',
          requestedAt: '2026-09-08T12:00:00Z',
          correlationId: randomUUID(),
        }),
      ),
      'payload',
    );
    const idempotency = expectOk(
      createOsvRuntimeJobIdempotencyIdentity({
        workScope: job.workScope,
        reason: job.synchronizationReason,
        versionSetFingerprint: job.versionSetFingerprint,
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId: randomUUID(),
      }),
      'idempotency',
    );
    const request = expectOk(
      await adapters.requests.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRequestEnsureCommand({
            payload: job,
            idempotency,
            requestState: 'accepted',
          }),
          'request command',
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
    return run.run;
  }

  it('heartbeats through Batch 7, refreshes revision, and yields it for later release', async () => {
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_lease_projection"`;
    const run = await seedCanaryRun();
    const secret = expectOk(
      createOsvRuntimeLeaseAcquireSecretForOwner({ holderToken: HOLDER }),
      'secret',
    );
    const acquired = expectOk(
      await adapters.leases.acquire(
        expectOk(
          createOsvRuntimeLeaseAcquirePersistenceCommand({
            runId: run.id,
            secret,
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
    expect(acquired.outcome).toBe('acquired');
    if (acquired.proof === null) {
      throw new Error('missing proof');
    }
    const clock = createFakeClock();
    const scheduler = createFakeScheduler(clock);
    const ports = canaryHeartbeatPortsFromRuntimePersistence(adapters);
    const controller = createOsvCanaryLeaseHeartbeatController({
      heartbeat: ports.heartbeat,
      ownership: ports.ownership,
      haltState: createOsvRuntimeHaltStatePort(
        createOsvRuntimeTrustedHaltSnapshot({
          control: 'permitted_by_halt_control',
          source: 'explicit',
        }),
      ),
      clock,
      scheduler,
    });
    const start = expectOk(
      createOsvCanaryHeartbeatStartContext({
        proof: acquired.proof,
        cancellationSignal: new AbortController().signal,
        phase: 'listing_only',
      }),
      'start context',
    );
    await controller.start(start);
    expect(controller.inspect().state).toBe('scheduled');
    clock.advance(OSV_CANARY_HEARTBEAT_INTERVAL_MS);
    scheduler.fireDue();
    for (let i = 0; i < 12; i += 1) {
      await Promise.resolve();
    }
    const stopped = await controller.stop();
    expect(stopped.state).toBe('stopped');
    const latest = readOsvCanaryHeartbeatReleaseProof(stopped.release);
    expect(latest).not.toBeNull();
    expect(latest?.fencingToken).toBe(acquired.proof.fencingToken);
    expect(BigInt(latest?.leaseRevision ?? '0')).toBeGreaterThan(
      BigInt(acquired.proof.leaseRevision),
    );
    const stored = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    expect(stored.fencingToken).toBe(1n);
    expect(stored.rowRevision).toBe(BigInt(latest?.leaseRevision ?? '0'));
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
  });
});
