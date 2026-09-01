import { describe, expect, it } from 'vitest';

import { INTELLIGENCE_SYNC_JOB_TYPE } from '@patchpilot/domain';

import { createIntelligenceJobRedispatch } from './intelligence-job-redispatch.js';

const PAYLOAD = {
  organizationId: null,
  outboxEventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  aggregateType: 'intelligence_sync_run' as const,
  aggregateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  eventType: 'intelligence.sync.requested.v1' as const,
  dedupeKey:
    'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
};

describe('intelligence job redispatch', () => {
  it('treats a live Redis job as an idempotent duplicate', async () => {
    const added: string[] = [];
    const redispatch = createIntelligenceJobRedispatch({
      queue: {
        async add(_name, _data, options) {
          added.push(options.jobId);
        },
        async getJob() {
          return {
            async getState() {
              return 'delayed';
            },
            async remove() {
              throw new Error('must not remove a live job');
            },
          };
        },
        async close() {
          return;
        },
      },
    });
    await expect(redispatch.add({ jobId: 'retry-1', payload: PAYLOAD })).resolves.toEqual({
      ok: true,
      duplicate: true,
    });
    expect(added).toEqual([]);
    await redispatch.close();
  });

  it('removes a completed leftover and re-adds the same job id', async () => {
    const added: Array<{ jobId: string; removeOnComplete?: boolean; removeOnFail?: boolean }> = [];
    const removed: string[] = [];
    const redispatch = createIntelligenceJobRedispatch({
      queue: {
        async add(name, data, options) {
          expect(name).toBe(INTELLIGENCE_SYNC_JOB_TYPE);
          expect(data).toEqual(PAYLOAD);
          added.push({
            jobId: options.jobId,
            ...(options.removeOnComplete === undefined
              ? {}
              : { removeOnComplete: options.removeOnComplete }),
            ...(options.removeOnFail === undefined ? {} : { removeOnFail: options.removeOnFail }),
          });
        },
        async getJob() {
          return {
            async getState() {
              return 'completed';
            },
            async remove() {
              removed.push('completed');
            },
          };
        },
        async close() {
          return;
        },
      },
    });
    await expect(redispatch.add({ jobId: 'retry-1', payload: PAYLOAD })).resolves.toEqual({
      ok: true,
      duplicate: false,
    });
    expect(removed).toEqual(['completed']);
    expect(added).toEqual([{ jobId: 'retry-1', removeOnComplete: true, removeOnFail: true }]);
    await redispatch.close();
  });

  it('re-adds after a failed leftover so PostgreSQL retry intent can recover', async () => {
    const added: string[] = [];
    const redispatch = createIntelligenceJobRedispatch({
      queue: {
        async add(_name, _data, options) {
          added.push(options.jobId);
        },
        async getJob() {
          return {
            async getState() {
              return 'failed';
            },
            async remove() {
              return;
            },
          };
        },
        async close() {
          return;
        },
      },
    });
    await expect(redispatch.add({ jobId: 'retry-lost', payload: PAYLOAD })).resolves.toEqual({
      ok: true,
      duplicate: false,
    });
    expect(added).toEqual(['retry-lost']);
    await redispatch.close();
  });
});
