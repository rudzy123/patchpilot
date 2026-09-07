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
  createOsvRuntimeRunTransitionCommand,
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
const HOLDER_D = '77777777-7777-4777-8777-777777777777';
const ARCH = OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER;
const RETRY = OSV_RUNTIME_RETRY_POLICY_IDENTIFIER;
const BEYOND_SAFE = 9_007_199_254_740_993n;

function expectOk<T>(result: OsvRuntimeCoordinationResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function payload(
  reason: 'scheduler' | 'operator_canary' | 'operator_production' = 'operator_production',
): OsvRuntimeSyncJobPayload {
  return expectOk(
    createOsvRuntimeSyncJobPayload(
      createClosedOsvRuntimeSyncJobInput({
        synchronizationReason: reason,
        requestedAt: '2026-09-07T12:00:00Z',
        correlationId: randomUUID(),
      }),
    ),
    'payload',
  );
}

describe('session 12 Batch 7-R lease fencing and database time', { timeout: 120_000 }, () => {
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

  async function seedRun() {
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

  async function expireHeldLease(): Promise<void> {
    await prisma.$executeRaw`
      UPDATE "osv_runtime_lease_projection"
      SET
        "heartbeat_at" = "acquired_at",
        "expires_at" = "acquired_at" + INTERVAL '1 millisecond',
        "row_revision" = "row_revision" + 1,
        "updated_at" = CURRENT_TIMESTAMP
      WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
    `;
  }

  async function currentOwnerProof(runId: string, holderToken: string) {
    const row = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    return expectOk(
      createOsvRuntimeLeaseOwnershipProofForOwner({
        scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
        runId,
        holderToken,
        leaseRevision: row.rowRevision.toString(),
        fencingToken: row.fencingToken.toString(),
        acquiredAt: row.acquiredAt.toISOString(),
        heartbeatAt: row.heartbeatAt.toISOString(),
        expiresAt: row.expiresAt.toISOString(),
      }),
      'current proof',
    );
  }

  it('rejects expired-owner release and heartbeat while leaving the row held', async () => {
    await resetLease();
    const seeded = await seedRun();
    const first = expectOk(await acquire(seeded.run.id, HOLDER_A), 'acquire');
    await expireHeldLease();
    const proof = await currentOwnerProof(seeded.run.id, HOLDER_A);
    const released = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof, reason: 'completed' }),
          'expired release command',
        ),
      ),
      'expired release',
    );
    expect(released.outcome).toBe('stale_owner');
    expect(released.projection.state).toBe('held');
    const stored = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    expect(stored.state).toBe('held');
    expect(stored.releaseReason).toBeNull();
    const beat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(createOsvRuntimeLeaseHeartbeatCommand({ proof }), 'expired heartbeat command'),
      ),
      'expired heartbeat',
    );
    expect(beat.outcome).toBe('expired');
    expect(beat.proof).toBeNull();
    expect(JSON.stringify(beat)).not.toContain(HOLDER_A);
    expect(JSON.stringify(beat)).not.toContain(stored.holderTokenDigest);
    const foreignBeat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(
          createOsvRuntimeLeaseHeartbeatCommand({
            proof: expectOk(
              createOsvRuntimeLeaseOwnershipProofForOwner({
                scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
                runId: seeded.run.id,
                holderToken: HOLDER_B,
                leaseRevision: proof.leaseRevision,
                fencingToken: proof.fencingToken,
                acquiredAt: proof.acquiredAt,
                heartbeatAt: proof.heartbeatAt,
                expiresAt: proof.expiresAt,
              }),
              'foreign proof',
            ),
          }),
          'foreign expired heartbeat',
        ),
      ),
      'foreign expired heartbeat',
    );
    expect(foreignBeat.outcome).toBe('ownership_lost');
    expect(first.projection.fencingToken).toBe('1');
  });

  it('treats expired same-owner acquire as takeover, not idempotent replay', async () => {
    await resetLease();
    const seeded = await seedRun();
    const first = expectOk(await acquire(seeded.run.id, HOLDER_A), 'acquire');
    await expireHeldLease();
    const expired = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    const replay = expectOk(
      await acquire(seeded.run.id, HOLDER_A, {
        revision: expired.rowRevision.toString(),
        fencing: expired.fencingToken.toString(),
      }),
      'expired same owner',
    );
    expect(replay.outcome).toBe('stale_takeover_acquired');
    expect(BigInt(replay.projection.fencingToken)).toBeGreaterThan(
      BigInt(first.projection.fencingToken),
    );
    expect(replay.projection.leaseRevision).not.toBe(first.projection.leaseRevision);
    expect(replay.projection.state).toBe('held');
    expect(replay.proof).not.toBeNull();
    if (first.proof === null) {
      throw new Error('missing first proof');
    }
    if (replay.proof !== null) {
      expect(replay.proof.fencingToken).toBe(replay.projection.fencingToken);
    }
    const staleA = expectOk(
      await adapters.leases.validateOwnership(
        expectOk(
          createOsvRuntimeLeaseOwnershipQuery({
            proof: first.proof,
            expectedRunId: seeded.run.id,
          }),
          'stale A query',
        ),
      ),
      'stale A validation',
    );
    expect(staleA.authorized).toBe(false);
    expect(staleA.status).toBe('lost');
  });

  it('increments fencing on each ABA ownership generation and rejects stale A', async () => {
    await resetLease();
    const firstSeed = await seedRun();
    const secondSeed = await seedRun();
    const a1 = expectOk(await acquire(firstSeed.run.id, HOLDER_A), 'A1');
    if (a1.proof === null) {
      throw new Error('missing A1 proof');
    }
    const releasedA = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof: a1.proof, reason: 'completed' }),
          'release A',
        ),
      ),
      'released A',
    );
    const b1 = expectOk(await acquire(secondSeed.run.id, HOLDER_B), 'B1');
    if (b1.proof === null) {
      throw new Error('missing B1 proof');
    }
    expect(BigInt(b1.projection.fencingToken)).toBeGreaterThan(
      BigInt(releasedA.projection.fencingToken),
    );
    const releasedB = expectOk(
      await adapters.leases.release(
        expectOk(
          createOsvRuntimeLeaseReleaseCommand({ proof: b1.proof, reason: 'shutdown' }),
          'release B',
        ),
      ),
      'released B',
    );
    const a2 = expectOk(await acquire(firstSeed.run.id, HOLDER_A), 'A2');
    expect(BigInt(a2.projection.fencingToken)).toBeGreaterThan(
      BigInt(releasedB.projection.fencingToken),
    );
    const staleA = expectOk(
      await adapters.leases.validateOwnership(
        expectOk(
          createOsvRuntimeLeaseOwnershipQuery({
            proof: a1.proof,
            expectedRunId: firstSeed.run.id,
          }),
          'stale A query',
        ),
      ),
      'stale A',
    );
    expect(staleA.authorized).toBe(false);
    expect(staleA.status).toBe('lost');
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
          proof: a1.proof,
        }),
        'stale complete',
      ),
    );
    expect(staleComplete.ok).toBe(false);
  });

  it('preserves BIGINT precision across heartbeat above Number.MAX_SAFE_INTEGER', async () => {
    await resetLease();
    const seeded = await seedRun();
    expectOk(await acquire(seeded.run.id, HOLDER_A), 'acquire');
    await prisma.$executeRaw`
      UPDATE "osv_runtime_lease_projection"
      SET
        "row_revision" = ${BEYOND_SAFE},
        "updated_at" = CURRENT_TIMESTAMP
      WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
    `;
    const proof = await currentOwnerProof(seeded.run.id, HOLDER_A);
    expect(proof.leaseRevision).toBe('9007199254740993');
    const beat = expectOk(
      await adapters.leases.heartbeat(
        expectOk(createOsvRuntimeLeaseHeartbeatCommand({ proof }), 'bigint heartbeat'),
      ),
      'bigint heartbeat',
    );
    expect(beat.outcome).toBe('accepted');
    expect(beat.projection.leaseRevision).toBe('9007199254740994');
    expect(beat.projection.fencingToken).toBe('1');
    const stored = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    expect(stored.rowRevision).toBe(9007199254740994n);
    expect(stored.fencingToken).toBe(1n);
    expect(JSON.stringify(beat)).not.toContain(HOLDER_A);
    expect(JSON.stringify(beat)).not.toContain(stored.holderTokenDigest);
  });

  it('admits exactly one winner among three stale-takeover contenders', async () => {
    await resetLease();
    const first = await seedRun();
    const second = await seedRun();
    const third = await seedRun();
    const fourth = await seedRun();
    expectOk(await acquire(first.run.id, HOLDER_A), 'initial');
    await expireHeldLease();
    const expired = await prisma.osvRuntimeLeaseProjection.findUniqueOrThrow({
      where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
    });
    const expected = {
      revision: expired.rowRevision.toString(),
      fencing: expired.fencingToken.toString(),
    };
    const clients = [
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
    ];
    try {
      const results = await Promise.all([
        acquireWith(
          createOsvRuntimeCoordinationPersistence(clients[0]!),
          second.run.id,
          HOLDER_B,
          expected,
        ),
        acquireWith(
          createOsvRuntimeCoordinationPersistence(clients[1]!),
          third.run.id,
          HOLDER_C,
          expected,
        ),
        acquireWith(
          createOsvRuntimeCoordinationPersistence(clients[2]!),
          fourth.run.id,
          HOLDER_D,
          expected,
        ),
      ]);
      const outcomes = results.map((result) => (result.ok ? result.value.outcome : result.code));
      expect(outcomes.filter((outcome) => outcome === 'stale_takeover_acquired')).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome === 'held_by_other')).toHaveLength(2);
      const winner = results.find(
        (result) => result.ok && result.value.outcome === 'stale_takeover_acquired',
      );
      if (winner === undefined || !winner.ok) {
        throw new Error('expected one takeover winner');
      }
      expect(JSON.stringify(winner.value)).not.toContain(
        expectOk(digestOsvRuntimeHolderToken(HOLDER_A), 'digest A'),
      );
    } finally {
      await Promise.all(clients.map((client) => client.$disconnect()));
    }
  });
});
