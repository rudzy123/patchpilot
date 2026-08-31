import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';

import {
  OUTBOX_QUEUE_NAME,
  type OutboxQueueJob,
  type OutboxQueuePublishResult,
  type OutboxQueuePublisherPort,
} from '@patchpilot/domain';

import { createBullmqConnectionOptions } from './queue-connection.js';

export type BullmqQueueLike = {
  add(name: string, data: unknown, options: { jobId: string }): Promise<unknown>;
  close(): Promise<void>;
  waitUntilReady?: () => Promise<void>;
  getJob?: (jobId: string) => Promise<unknown>;
};

export type BullmqOutboxPublisher = OutboxQueuePublisherPort & {
  close(): Promise<void>;
};

export function createBullmqOutboxPublisher(options: {
  redisUrl?: string;
  connection?: ConnectionOptions;
  queueName?: string;
  queue?: BullmqQueueLike;
}): BullmqOutboxPublisher {
  const queueName = options.queueName ?? OUTBOX_QUEUE_NAME;
  const queue =
    options.queue ??
    new Queue(queueName, {
      connection:
        options.connection ?? createBullmqConnectionOptions(requiredRedisUrl(options.redisUrl)),
    });

  return {
    async publish(job: OutboxQueueJob): Promise<OutboxQueuePublishResult> {
      try {
        if (queue.waitUntilReady !== undefined) {
          await queue.waitUntilReady();
        }
        if (queue.getJob !== undefined) {
          const existing = await queue.getJob(job.jobId);
          if (existing !== undefined && existing !== null) {
            return { ok: true, duplicate: true };
          }
        }
        await queue.add(
          job.jobType,
          {
            organizationId: job.organizationId,
            outboxEventId: job.outboxEventId,
            aggregateType: job.aggregateType,
            aggregateId: job.aggregateId,
            eventType: job.eventType,
            dedupeKey: job.dedupeKey,
          },
          { jobId: job.jobId },
        );
        return { ok: true, duplicate: false };
      } catch (error) {
        if (isDuplicateJobError(error)) {
          return { ok: true, duplicate: true };
        }
        return { ok: false, retryable: true };
      }
    },
    async close(): Promise<void> {
      await queue.close();
    },
  };
}

export function isDuplicateJobError(error: unknown): boolean {
  if (error === null || typeof error !== 'object') {
    return false;
  }
  const code = 'code' in error ? String(error.code) : '';
  const message = error instanceof Error ? error.message : String(error);
  return code === 'JOB_ALREADY_EXISTS' || /already exists/i.test(message);
}

function requiredRedisUrl(redisUrl: string | undefined): string {
  if (redisUrl === undefined || redisUrl.length === 0) {
    throw new Error('Redis URL is required to construct the outbox queue publisher.');
  }
  return redisUrl;
}
