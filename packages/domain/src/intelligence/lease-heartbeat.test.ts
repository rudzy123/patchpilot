import { describe, expect, it } from 'vitest';

import { err, ok } from '../result.js';
import type { BackgroundJobExecutionPort, BackgroundJobLease } from '../sbom/ports.js';
import { createIntelligenceLeaseHeartbeat } from './lease-heartbeat.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');

describe('intelligence lease heartbeat', () => {
  it('renews on the injected scheduler and aborts on lease loss', async () => {
    const ticks: Array<() => void> = [];
    let stopped = false;
    let renewals = 0;
    const jobs = {
      async renewLease() {
        renewals += 1;
        if (renewals >= 2) {
          return err({ code: 'conflict' as const, message: 'lost' });
        }
        const lease: BackgroundJobLease = {
          jobId: '55555555-5555-4555-8555-555555555555',
          workerIdentifier: 'worker-1',
          leaseExpiresAt: new Date(NOW.getTime() + 60_000),
        };
        return ok(lease);
      },
    };
    const heartbeat = createIntelligenceLeaseHeartbeat({
      jobs: jobs as unknown as BackgroundJobExecutionPort,
      ownership: {
        jobId: '55555555-5555-4555-8555-555555555555',
        workerIdentifier: 'worker-1',
        organizationId: null,
      },
      clock: { now: () => NOW },
      leaseMs: 600_000,
      intervalMs: 60_000,
      scheduler: {
        schedule(_intervalMs, tick) {
          ticks.push(tick);
          return {
            stop() {
              stopped = true;
            },
          };
        },
      },
    });
    heartbeat.start();
    const first = await heartbeat.renewNow();
    expect(first.ok).toBe(true);
    ticks[0]?.();
    await Promise.resolve();
    expect(heartbeat.signal.aborted).toBe(true);
    heartbeat.stop();
    expect(stopped).toBe(true);
  });

  it('does not continue renewing after stop', async () => {
    let renewals = 0;
    const heartbeat = createIntelligenceLeaseHeartbeat({
      jobs: {
        async renewLease() {
          renewals += 1;
          return ok({
            jobId: '55555555-5555-4555-8555-555555555555',
            workerIdentifier: 'worker-1',
            leaseExpiresAt: NOW,
          });
        },
      } as unknown as BackgroundJobExecutionPort,
      ownership: {
        jobId: '55555555-5555-4555-8555-555555555555',
        workerIdentifier: 'worker-1',
        organizationId: null,
      },
      clock: { now: () => NOW },
      leaseMs: 600_000,
      intervalMs: 60_000,
      scheduler: {
        schedule() {
          return { stop() {} };
        },
      },
    });
    heartbeat.stop();
    const result = await heartbeat.renewNow();
    expect(result.ok).toBe(false);
    expect(renewals).toBe(0);
  });
});
