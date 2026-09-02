import { UnrecoverableError } from 'bullmq';
import { describe, expect, it } from 'vitest';

import { INTELLIGENCE_SYNC_JOB_TYPE, SBOM_INGEST_JOB_TYPE } from '@patchpilot/domain';

import {
  PATCHPILOT_QUEUE_JOB_TYPES,
  createPatchpilotJobRegistry,
  createPatchpilotQueueWorker,
} from './queue-job-router.js';
import {
  PATCHPILOT_QUEUE_WORKER_CONCURRENCY,
  patchpilotWorkerLockDurationMs,
  patchpilotWorkerLockRenewTimeMs,
} from './worker-lock.js';

const silent = {
  info() {
    return;
  },
  warn() {
    return;
  },
};

describe('patchpilot queue worker lock and router', () => {
  it('uses concurrency 2 and covers the longer of the SBOM and KEV leases', () => {
    expect(PATCHPILOT_QUEUE_WORKER_CONCURRENCY).toBe(2);
    expect(
      patchpilotWorkerLockDurationMs({
        sbomProcessingLeaseMs: 900_000,
        kevJobLeaseMs: 600_000,
      }),
    ).toBe(900_000);
    expect(
      patchpilotWorkerLockDurationMs({
        sbomProcessingLeaseMs: 120_000,
        kevJobLeaseMs: 600_000,
      }),
    ).toBe(600_000);
    const lockDuration = 900_000;
    const renew = patchpilotWorkerLockRenewTimeMs({
      lockDurationMs: lockDuration,
      jobLeaseRenewalIntervalMs: 60_000,
    });
    expect(renew).toBe(60_000);
    expect(renew).toBeLessThan(lockDuration / 2);
    expect(PATCHPILOT_QUEUE_JOB_TYPES).toEqual([SBOM_INGEST_JOB_TYPE, INTELLIGENCE_SYNC_JOB_TYPE]);
    expect(createPatchpilotJobRegistry().map((job) => job.name)).toEqual([
      SBOM_INGEST_JOB_TYPE,
      INTELLIGENCE_SYNC_JOB_TYPE,
    ]);
  });

  it('routes sbom.ingest and intelligence.sync and rejects unknown names', async () => {
    const routed: string[] = [];
    let handler: ((job: { name: string; id: string; data: unknown }) => Promise<void>) | undefined;
    const worker = createPatchpilotQueueWorker({
      connection: { host: '127.0.0.1', port: 9 },
      processSbom: async () => {
        routed.push('sbom');
        return { kind: 'completed' };
      },
      processIntelligence: async () => {
        routed.push('intelligence');
      },
      logger: silent,
      sbomProcessingLeaseMs: 900_000,
      kevJobLeaseMs: 600_000,
      jobLeaseRenewalIntervalMs: 60_000,
      workerFactory: (processor) => {
        handler = processor;
        return {
          waitUntilReady: async () => undefined,
          close: async () => undefined,
        };
      },
    });
    await worker.start();
    if (handler === undefined) {
      throw new Error('missing handler');
    }
    await handler({ name: SBOM_INGEST_JOB_TYPE, id: '1', data: {} });
    await handler({ name: INTELLIGENCE_SYNC_JOB_TYPE, id: '2', data: {} });
    await expect(handler({ name: 'other.job', id: '3', data: {} })).rejects.toBeInstanceOf(
      UnrecoverableError,
    );
    expect(routed).toEqual(['sbom', 'intelligence']);
    await worker.stop();
  });
});
