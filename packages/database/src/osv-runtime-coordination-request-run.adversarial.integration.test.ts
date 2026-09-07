import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeRunTransitionCommand,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  type OsvRuntimeCoordinationResult,
  type OsvRuntimeSyncJobPayload,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

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

describe('session 12 Batch 7-R request and run authority', { timeout: 120_000 }, () => {
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

  it('admits one concurrent identical request insert and reloads immutable authority', async () => {
    const job = payload('operator_production');
    const operatorRequestId = randomUUID();
    const command = ensureCommand(job, {
      requestKind: 'operator_request',
      schedulerWindowId: null,
      operatorRequestId,
    });
    const left = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const right = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const [first, second] = await Promise.all([
        createOsvRuntimeCoordinationPersistence(left).requests.ensure(command),
        createOsvRuntimeCoordinationPersistence(right).requests.ensure(command),
      ]);
      const statuses = [first, second].map((result) =>
        result.ok ? result.value.status : result.code,
      );
      expect(statuses.sort()).toEqual(['already_applied', 'created']);
      expect(
        await prisma.osvRuntimeSynchronizationRequest.count({ where: { operatorRequestId } }),
      ).toBe(1);
    } finally {
      await left.$disconnect();
      await right.$disconnect();
    }
  });

  it('rejects concurrent conflicting operator requests without updating the stored row', async () => {
    const operatorRequestId = randomUUID();
    const production = ensureCommand(payload('operator_production'), {
      requestKind: 'operator_request',
      schedulerWindowId: null,
      operatorRequestId,
    });
    const created = expectOk(await adapters.requests.ensure(production), 'created');
    const conflict = await adapters.requests.ensure(
      ensureCommand(payload('operator_canary'), {
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId,
      }),
    );
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
    const stored = await prisma.osvRuntimeSynchronizationRequest.findUniqueOrThrow({
      where: { operatorRequestId },
    });
    expect(stored.id).toBe(created.request.id);
    expect(stored.synchronizationReason).toBe('operator_production');
    expect(JSON.stringify(conflict)).not.toMatch(/Prisma|SELECT |holder_token/i);
  });

  it('reuses one run for duplicate delivery and keeps canary distinct from production', async () => {
    const canaryJob = payload('operator_canary');
    const canaryRequest = expectOk(
      await adapters.requests.ensure(
        ensureCommand(canaryJob, {
          requestKind: 'operator_request',
          schedulerWindowId: null,
          operatorRequestId: randomUUID(),
        }),
      ),
      'canary request',
    );
    const canaryRun = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({
            requestId: canaryRequest.request.id,
          }),
          'canary run command',
        ),
      ),
      'canary run',
    );
    const replay = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({
            requestId: canaryRequest.request.id,
          }),
          'canary run replay command',
        ),
      ),
      'canary run replay',
    );
    expect(replay.status).toBe('already_applied');
    expect(replay.run.id).toBe(canaryRun.run.id);
    expect(canaryRun.run.workScope).toBe('osv_runtime_canary_scope_crates_io_rustsec_v1');
    expect(
      await prisma.osvRuntimeSynchronizationRun.count({
        where: { requestId: canaryRequest.request.id },
      }),
    ).toBe(1);
    const productionRequest = expectOk(
      await adapters.requests.ensure(
        ensureCommand(payload('operator_production'), {
          requestKind: 'operator_request',
          schedulerWindowId: null,
          operatorRequestId: randomUUID(),
        }),
      ),
      'production request',
    );
    const productionRun = expectOk(
      await adapters.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({
            requestId: productionRequest.request.id,
          }),
          'production run command',
        ),
      ),
      'production run',
    );
    expect(productionRun.run.workScope).toBe('osv_runtime_production_scope_six_prefix_v1');
    expect(productionRun.run.id).not.toBe(canaryRun.run.id);
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(0);
  });

  it('rejects forbidden run transitions and duplicate terminal conflicts', async () => {
    const request = expectOk(
      await adapters.requests.ensure(
        ensureCommand(payload('scheduler'), {
          requestKind: 'scheduler_window',
          schedulerWindowId: `window:${randomUUID()}`,
          operatorRequestId: null,
        }),
      ),
      'scheduler request',
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
    const completedFromPlanned = await adapters.runs.transition(
      expectOk(
        createOsvRuntimeRunTransitionCommand({
          runId: run.run.id,
          expectedState: 'planned',
          nextState: 'completed',
          terminalCode: null,
          retryDisposition: 'no_retry',
          lastAcceptedStage: null,
          cancellationBoundary: null,
          proof: null,
        }),
        'illegal complete',
      ),
    );
    expect(completedFromPlanned.ok).toBe(false);
    if (!completedFromPlanned.ok) {
      expect(completedFromPlanned.code).toBe('state_conflict');
    }
    const halted = expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: run.run.id,
            expectedState: 'planned',
            nextState: 'halted',
            terminalCode: 'halt_engaged',
            retryDisposition: 'no_retry',
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: null,
          }),
          'halt',
        ),
      ),
      'halted',
    );
    expect(halted.run.state).toBe('halted');
    expect(halted.run.terminalAt).not.toBeNull();
    const replayHalt = expectOk(
      await adapters.runs.transition(
        expectOk(
          createOsvRuntimeRunTransitionCommand({
            runId: run.run.id,
            expectedState: 'planned',
            nextState: 'halted',
            terminalCode: 'halt_engaged',
            retryDisposition: 'no_retry',
            lastAcceptedStage: null,
            cancellationBoundary: null,
            proof: null,
          }),
          'halt replay',
        ),
      ),
      'halt replay',
    );
    expect(replayHalt.status).toBe('already_applied');
    expect(replayHalt.run.terminalAt).toBe(halted.run.terminalAt);
    const cancelAfterHalt = await adapters.runs.transition(
      expectOk(
        createOsvRuntimeRunTransitionCommand({
          runId: run.run.id,
          expectedState: 'halted',
          nextState: 'cancelled',
          terminalCode: null,
          retryDisposition: 'no_retry',
          lastAcceptedStage: null,
          cancellationBoundary: 'before_lease_acquisition',
          proof: null,
        }),
        'cancel after halt',
      ),
    );
    expect(cancelAfterHalt.ok).toBe(false);
  });
});
