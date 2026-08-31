import { UnrecoverableError, Worker, type ConnectionOptions, type Job } from 'bullmq';

import {
  OUTBOX_QUEUE_NAME,
  SBOM_INGEST_JOB_TYPE,
  type ProcessSbomIngestionOutcome,
} from '@patchpilot/domain';

export type SbomIngestProcessor = {
  start(): Promise<void>;
  stop(): Promise<void>;
};

export type SbomIngestJobLike = Pick<Job, 'name' | 'id' | 'data'>;

export type SbomIngestProcessorLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

type QueueWorker = {
  waitUntilReady(): Promise<unknown>;
  close(): Promise<void>;
};

export async function processSbomIngestQueueJob(
  job: SbomIngestJobLike,
  execute: (payload: unknown) => Promise<ProcessSbomIngestionOutcome>,
  logger: SbomIngestProcessorLogger,
): Promise<void> {
  if (job.name !== SBOM_INGEST_JOB_TYPE) {
    throw new UnrecoverableError(`Unexpected job type ${job.name}.`);
  }

  const result = await execute(job.data);
  const bindings: Record<string, unknown> = {
    jobId: job.id,
    jobType: SBOM_INGEST_JOB_TYPE,
    outcome: result.kind,
    ...('code' in result ? { code: result.code } : {}),
  };
  if (result.kind === 'retry') {
    logger.warn(bindings, 'sbom ingest job will retry');
    throw new Error('SBOM ingest job will retry.');
  }
  logger.info(bindings, 'sbom ingest job finished');
}

export function createSbomIngestProcessor(options: {
  connection: ConnectionOptions;
  execute: (payload: unknown) => Promise<ProcessSbomIngestionOutcome>;
  logger: SbomIngestProcessorLogger;
  queueName?: string;
  workerFactory?: (processor: (job: Job) => Promise<void>) => QueueWorker;
}): SbomIngestProcessor {
  const queueName = options.queueName ?? OUTBOX_QUEUE_NAME;
  let worker: QueueWorker | undefined;

  return {
    async start(): Promise<void> {
      if (worker !== undefined) {
        return;
      }
      const handle = async (job: Job): Promise<void> =>
        processSbomIngestQueueJob(job, options.execute, options.logger);
      const created: QueueWorker =
        options.workerFactory?.(handle) ??
        new Worker(queueName, handle, {
          connection: options.connection,
          concurrency: 1,
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
