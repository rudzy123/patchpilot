import { UnrecoverableError, Worker, type ConnectionOptions, type Job } from 'bullmq';

import {
  INTELLIGENCE_SYNC_JOB_TYPE,
  OUTBOX_QUEUE_NAME,
  SBOM_INGEST_JOB_TYPE,
  type ProcessSbomIngestionOutcome,
} from '@patchpilot/domain';
import type { JobRegistry } from '@patchpilot/integrations';

import { processSbomIngestQueueJob } from './sbom-ingest-processor.js';
import {
  PATCHPILOT_QUEUE_WORKER_CONCURRENCY,
  patchpilotWorkerLockDurationMs,
  patchpilotWorkerLockRenewTimeMs,
} from './worker-lock.js';

export const PATCHPILOT_QUEUE_JOB_TYPES = [
  SBOM_INGEST_JOB_TYPE,
  INTELLIGENCE_SYNC_JOB_TYPE,
] as const;

export type PatchpilotQueueJobLike = Pick<Job, 'name' | 'id' | 'data'>;

export function createPatchpilotJobRegistry(): JobRegistry {
  return PATCHPILOT_QUEUE_JOB_TYPES.map((name) => ({ name }));
}

export type PatchpilotQueueWorker = {
  start(): Promise<void>;
  stop(): Promise<void>;
};

export type PatchpilotQueueWorkerLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

type QueueWorkerHandle = {
  waitUntilReady(): Promise<unknown>;
  close(): Promise<void>;
};

export function createPatchpilotQueueWorker(options: {
  connection: ConnectionOptions;
  processSbom: (payload: unknown) => Promise<ProcessSbomIngestionOutcome>;
  processIntelligence: (job: PatchpilotQueueJobLike) => Promise<void>;
  logger: PatchpilotQueueWorkerLogger;
  sbomProcessingLeaseMs: number;
  kevJobLeaseMs: number;
  jobLeaseRenewalIntervalMs: number;
  queueName?: string;
  workerFactory?: (processor: (job: PatchpilotQueueJobLike) => Promise<void>) => QueueWorkerHandle;
}): PatchpilotQueueWorker {
  const queueName = options.queueName ?? OUTBOX_QUEUE_NAME;
  const lockDuration = patchpilotWorkerLockDurationMs({
    sbomProcessingLeaseMs: options.sbomProcessingLeaseMs,
    kevJobLeaseMs: options.kevJobLeaseMs,
  });
  const lockRenewTime = patchpilotWorkerLockRenewTimeMs({
    lockDurationMs: lockDuration,
    jobLeaseRenewalIntervalMs: options.jobLeaseRenewalIntervalMs,
  });
  let worker: QueueWorkerHandle | undefined;

  return {
    async start(): Promise<void> {
      if (worker !== undefined) {
        return;
      }
      const handle = async (job: PatchpilotQueueJobLike): Promise<void> => {
        if (job.name === SBOM_INGEST_JOB_TYPE) {
          await processSbomIngestQueueJob(job, options.processSbom, options.logger);
          return;
        }
        if (job.name === INTELLIGENCE_SYNC_JOB_TYPE) {
          await options.processIntelligence(job);
          return;
        }
        throw new UnrecoverableError('Unsupported queue job name.');
      };
      const created: QueueWorkerHandle =
        options.workerFactory?.(handle) ??
        new Worker(queueName, handle, {
          connection: options.connection,
          concurrency: PATCHPILOT_QUEUE_WORKER_CONCURRENCY,
          lockDuration,
          lockRenewTime,
        });
      worker = created;
      await created.waitUntilReady();
    },
    async stop(): Promise<void> {
      if (worker === undefined) {
        return;
      }
      await worker.close();
      worker = undefined;
    },
  };
}
