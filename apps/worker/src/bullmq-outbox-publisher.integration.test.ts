import { randomUUID } from 'node:crypto';

import { Queue } from 'bullmq';
import { loadServerConfigFrom } from '@patchpilot/config';
import {
  SBOM_INGEST_JOB_TYPE,
  SBOM_INGESTION_REQUESTED_EVENT_TYPE,
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
} from '@patchpilot/domain';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterEach, describe, expect, it } from 'vitest';

import { createBullmqOutboxPublisher } from './bullmq-outbox-publisher.js';
import { createIntelligenceJobRedispatch } from './intelligence-job-redispatch.js';
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

  it('publishes an intelligence.sync locator with organizationId null', async () => {
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const queueName = `patchpilot-it-intel-${Date.now()}`;
    const publisher = createBullmqOutboxPublisher({
      redisUrl: config.redisUrl,
      queueName,
    });
    publishers.push(publisher);
    const outboxEventId = randomUUID();
    const job = {
      jobId: `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${outboxEventId}`,
      jobType: INTELLIGENCE_SYNC_JOB_TYPE,
      organizationId: null,
      outboxEventId,
      aggregateType: 'intelligence_sync_run',
      aggregateId: randomUUID(),
      eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
      dedupeKey:
        'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
    };
    expect(await publisher.publish(job)).toEqual({ ok: true, duplicate: false });
    expect(await publisher.publish(job)).toEqual({ ok: true, duplicate: true });
    const inspector = new Queue(queueName, {
      connection: createBullmqConnectionOptions(config.redisUrl),
    });
    queues.push(inspector);
    const stored = await inspector.getJob(job.jobId);
    expect(stored?.name).toBe(INTELLIGENCE_SYNC_JOB_TYPE);
    expect(stored?.data).toMatchObject({
      organizationId: null,
      eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
    });
    expect(JSON.stringify(stored?.data)).not.toMatch(/https:\/\/|objectKey|etag|CVE-/i);
    await inspector.obliterate({ force: true });
  });

  it('re-adds a missing intelligence retry job after Redis loss', async () => {
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const queueName = `patchpilot-it-intel-retry-${Date.now()}`;
    const redispatch = createIntelligenceJobRedispatch({
      redisUrl: config.redisUrl,
      queueName,
    });
    publishers.push(redispatch);
    const outboxEventId = randomUUID();
    const jobId = `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${outboxEventId}__retry__1`;
    const payload = {
      organizationId: null,
      outboxEventId,
      aggregateType: 'intelligence_sync_run' as const,
      aggregateId: randomUUID(),
      eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
      dedupeKey:
        'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
    };
    expect(await redispatch.add({ jobId, payload })).toEqual({ ok: true, duplicate: false });
    const inspector = new Queue(queueName, {
      connection: createBullmqConnectionOptions(config.redisUrl),
    });
    queues.push(inspector);
    expect(await inspector.getJob(jobId)).toBeTruthy();
    await inspector.obliterate({ force: true });
    expect(await inspector.getJob(jobId)).toBeUndefined();
    expect(await redispatch.add({ jobId, payload })).toEqual({ ok: true, duplicate: false });
    const restored = await inspector.getJob(jobId);
    expect(restored?.name).toBe(INTELLIGENCE_SYNC_JOB_TYPE);
    expect(restored?.data).toMatchObject({ organizationId: null, outboxEventId });
    await inspector.obliterate({ force: true });
  });
});
