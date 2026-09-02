import { Queue, type ConnectionOptions } from 'bullmq';

import {
  INTELLIGENCE_SYNC_JOB_TYPE,
  OUTBOX_QUEUE_NAME,
  type IntelligenceSyncJobPayload,
} from '@patchpilot/domain';

import { isDuplicateJobError } from './bullmq-outbox-publisher.js';
import { createBullmqConnectionOptions } from './queue-connection.js';

export type IntelligenceJobRedispatchResult = { ok: true; duplicate: boolean } | { ok: false };

export type IntelligenceJobRedispatch = {
  add(input: {
    jobId: string;
    payload: IntelligenceSyncJobPayload;
    delayMs?: number;
  }): Promise<IntelligenceJobRedispatchResult>;
  close(): Promise<void>;
};

const LIVE_REDIS_JOB_STATES = new Set([
  'active',
  'delayed',
  'paused',
  'waiting',
  'waiting-children',
]);

type RedispatchJobHandle = {
  getState?: () => Promise<string>;
  remove?: () => Promise<void>;
};

type RedispatchQueue = {
  add(
    name: string,
    data: IntelligenceSyncJobPayload,
    options: {
      jobId: string;
      delay?: number;
      removeOnComplete?: boolean;
      removeOnFail?: boolean;
    },
  ): Promise<unknown>;
  getJob?: (jobId: string) => Promise<unknown>;
  close(): Promise<void>;
};

export function createIntelligenceJobRedispatch(options: {
  connection?: ConnectionOptions;
  redisUrl?: string;
  queueName?: string;
  queue?: RedispatchQueue;
}): IntelligenceJobRedispatch {
  const queueName = options.queueName ?? OUTBOX_QUEUE_NAME;
  const queue =
    options.queue ??
    new Queue(queueName, {
      connection:
        options.connection ?? createBullmqConnectionOptions(requiredRedisUrl(options.redisUrl)),
    });

  return {
    async add(input): Promise<IntelligenceJobRedispatchResult> {
      try {
        if (queue.getJob !== undefined) {
          const existing = await queue.getJob(input.jobId);
          if (existing !== undefined && existing !== null) {
            const disposition = await inspectExistingRedisJob(existing);
            if (disposition === 'live') {
              return { ok: true, duplicate: true };
            }
            if (disposition === 'unknown') {
              return { ok: true, duplicate: true };
            }
          }
        }
        const delay = input.delayMs !== undefined && input.delayMs > 0 ? input.delayMs : undefined;
        await queue.add(INTELLIGENCE_SYNC_JOB_TYPE, input.payload, {
          jobId: input.jobId,
          removeOnComplete: true,
          removeOnFail: true,
          ...(delay === undefined ? {} : { delay }),
        });
        return { ok: true, duplicate: false };
      } catch (error) {
        if (isDuplicateJobError(error)) {
          return { ok: true, duplicate: true };
        }
        return { ok: false };
      }
    },
    async close(): Promise<void> {
      await queue.close();
    },
  };
}

async function inspectExistingRedisJob(existing: unknown): Promise<'live' | 'removed' | 'unknown'> {
  if (typeof existing !== 'object' || existing === null) {
    return 'unknown';
  }
  const job = existing as RedispatchJobHandle;
  if (typeof job.getState !== 'function') {
    return 'unknown';
  }
  const state = await job.getState();
  if (LIVE_REDIS_JOB_STATES.has(state)) {
    return 'live';
  }
  if ((state === 'completed' || state === 'failed') && typeof job.remove === 'function') {
    await job.remove();
    return 'removed';
  }
  return 'unknown';
}

function requiredRedisUrl(redisUrl: string | undefined): string {
  if (redisUrl === undefined || redisUrl.length === 0) {
    throw new Error('Redis URL is required to construct intelligence job redispatch.');
  }
  return redisUrl;
}
