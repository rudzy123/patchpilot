import { describe, expect, it } from 'vitest';

import type { IntelligenceRedeliveryCandidate } from '@patchpilot/domain';

import { createIntelligenceRetryReconciler } from './intelligence-retry-reconciler.js';

const LOCATOR = {
  organizationId: null,
  outboxEventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  aggregateType: 'intelligence_sync_run' as const,
  aggregateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  eventType: 'intelligence.sync.requested.v1' as const,
  dedupeKey:
    'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
};

function candidate(
  overrides?: Partial<IntelligenceRedeliveryCandidate>,
): IntelligenceRedeliveryCandidate {
  return {
    syncRunId: LOCATOR.aggregateId,
    backgroundJobId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    outboxEventId: LOCATOR.outboxEventId,
    jobAttempt: 1,
    jobStatus: 'queued',
    syncRunState: 'retry_wait',
    nextAttemptAt: new Date('2026-09-01T12:00:00.000Z'),
    leaseExpiresAt: null,
    locator: LOCATOR,
    ...overrides,
  };
}

function createGate() {
  const waiting: Array<() => void> = [];
  return {
    delay(_ms: number, signal: AbortSignal): Promise<void> {
      return new Promise((resolve) => {
        if (signal.aborted) {
          resolve();
          return;
        }
        waiting.push(resolve);
        signal.addEventListener('abort', () => resolve(), { once: true });
      });
    },
    async releaseOne(): Promise<void> {
      const next = waiting.shift();
      next?.();
      await Promise.resolve();
    },
  };
}

describe('intelligence retry reconciler', () => {
  it('redispatches due candidates without claiming jobs and continues after one failure', async () => {
    const gate = createGate();
    const added: string[] = [];
    const listed: Date[] = [];
    const reconciler = createIntelligenceRetryReconciler({
      listDue: async (now) => {
        listed.push(now);
        return [
          candidate(),
          candidate({
            syncRunId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
            outboxEventId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
            locator: { ...LOCATOR, outboxEventId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' },
          }),
        ];
      },
      redispatch: {
        add: async (input) => {
          if (input.jobId.includes('eeeeeeee')) {
            throw new Error('redis down');
          }
          added.push(input.jobId);
          return { ok: true, duplicate: false };
        },
        close: async () => undefined,
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      intervalMs: 15_000,
      now: () => new Date('2026-09-01T12:00:00.000Z'),
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    reconciler.start();
    expect(listed).toHaveLength(0);
    await gate.releaseOne();
    await Promise.resolve();
    expect(listed).toHaveLength(1);
    expect(added).toHaveLength(1);
    await reconciler.stop();
  });

  it('stops during the interval delay without listing candidates', async () => {
    const gate = createGate();
    let listed = 0;
    const reconciler = createIntelligenceRetryReconciler({
      listDue: async () => {
        listed += 1;
        return [];
      },
      redispatch: {
        add: async () => ({ ok: true, duplicate: false }),
        close: async () => undefined,
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      intervalMs: 15_000,
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    reconciler.start();
    await reconciler.stop();
    expect(listed).toBe(0);
  });

  it('treats Redis unavailability as a warning and leaves PostgreSQL state unchanged', async () => {
    const gate = createGate();
    const warnings: string[] = [];
    const reconciler = createIntelligenceRetryReconciler({
      listDue: async () => [candidate()],
      redispatch: {
        add: async () => ({ ok: false }),
        close: async () => undefined,
      },
      logger: {
        info() {
          return;
        },
        warn(_bindings, message) {
          warnings.push(message);
        },
      },
      intervalMs: 15_000,
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    reconciler.start();
    await gate.releaseOne();
    await Promise.resolve();
    expect(warnings).toContain('kev retry redispatch failed');
    await reconciler.stop();
  });
});
