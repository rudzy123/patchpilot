import { describe, expect, it } from 'vitest';

import { SBOM_INGEST_JOB_TYPE, SBOM_INGESTION_REQUESTED_EVENT_TYPE } from '@patchpilot/domain';

import {
  createBullmqOutboxPublisher,
  isDuplicateJobError,
  type BullmqQueueLike,
} from './bullmq-outbox-publisher.js';

const JOB = {
  jobId: 'sbom.ingestion.requested.v1__aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  jobType: SBOM_INGEST_JOB_TYPE,
  organizationId: '11111111-1111-4111-8111-111111111111',
  outboxEventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  aggregateType: 'sbom_ingestion',
  aggregateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
  dedupeKey: 'org:sbom.ingest:sbom:0.1.0',
};

describe('BullMQ outbox publisher', () => {
  it('publishes ids only and treats a duplicate job id as success', async () => {
    const added: Array<{ name: string; data: unknown; jobId: string }> = [];
    const queue: BullmqQueueLike = {
      async add(name, data, options) {
        if (added.some((row) => row.jobId === options.jobId)) {
          throw Object.assign(new Error(`Job ${options.jobId} already exists`), {
            code: 'JOB_ALREADY_EXISTS',
          });
        }
        added.push({ name, data, jobId: options.jobId });
        return { id: options.jobId };
      },
      async close() {
        return;
      },
    };
    const publisher = createBullmqOutboxPublisher({ queue });
    const first = await publisher.publish(JOB);
    const duplicate = await publisher.publish(JOB);
    expect(first).toEqual({ ok: true, duplicate: false });
    expect(duplicate).toEqual({ ok: true, duplicate: true });
    expect(added).toHaveLength(1);
    expect(JSON.stringify(added[0]?.data)).not.toMatch(/bomFormat|objectKey|filename/);
    await publisher.close();
  });

  it('classifies Redis outages as retryable without throwing', async () => {
    const publisher = createBullmqOutboxPublisher({
      queue: {
        async add() {
          throw new Error('ECONNREFUSED');
        },
        async close() {
          return;
        },
      },
    });
    await expect(publisher.publish(JOB)).resolves.toEqual({ ok: false, retryable: true });
    expect(isDuplicateJobError(new Error('ECONNREFUSED'))).toBe(false);
  });
});
