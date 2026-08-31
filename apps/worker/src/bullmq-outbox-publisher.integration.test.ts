import { randomUUID } from 'node:crypto';

import { Queue } from 'bullmq';
import { loadServerConfigFrom } from '@patchpilot/config';
import { SBOM_INGEST_JOB_TYPE, SBOM_INGESTION_REQUESTED_EVENT_TYPE } from '@patchpilot/domain';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterEach, describe, expect, it } from 'vitest';

import { createBullmqOutboxPublisher } from './bullmq-outbox-publisher.js';
import { createBullmqConnectionOptions } from './queue-connection.js';

describe('BullMQ outbox publisher integration', () => {
  const publishers: Array<{ close(): Promise<void> }> = [];
  const queues: Queue[] = [];

  afterEach(async () => {
    await Promise.all(publishers.splice(0).map((publisher) => publisher.close()));
    await Promise.all(queues.splice(0).map((queue) => queue.close()));
  });

  it('accepts a duplicate deterministic job id against Compose Redis', async () => {
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const queueName = `patchpilot-it-${Date.now()}`;
    const publisher = createBullmqOutboxPublisher({
      redisUrl: config.redisUrl,
      queueName,
    });
    publishers.push(publisher);
    const job = {
      jobId: `sbom.ingestion.requested.v1__${randomUUID()}`,
      jobType: SBOM_INGEST_JOB_TYPE,
      organizationId: '11111111-1111-4111-8111-111111111111',
      outboxEventId: randomUUID(),
      aggregateType: 'sbom_ingestion',
      aggregateId: randomUUID(),
      eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
      dedupeKey: `it:${randomUUID()}`,
    };
    expect(await publisher.publish(job)).toEqual({ ok: true, duplicate: false });
    expect(await publisher.publish(job)).toEqual({ ok: true, duplicate: true });

    const inspector = new Queue(queueName, {
      connection: createBullmqConnectionOptions(config.redisUrl),
    });
    queues.push(inspector);
    const stored = await inspector.getJob(job.jobId);
    expect(stored?.name).toBe(SBOM_INGEST_JOB_TYPE);
    expect(JSON.stringify(stored?.data)).not.toMatch(/bomFormat|objectKey/);
    await inspector.obliterate({ force: true });
  });
});
