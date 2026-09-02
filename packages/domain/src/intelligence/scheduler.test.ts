import { describe, expect, it } from 'vitest';

import { ok } from '../result.js';
import { createEvaluateKevSyncScheduleUseCase } from './scheduler.js';
import type { IntelligenceSyncRunRecord } from './records.js';
import type { IntelligenceProviderFreshness } from './freshness.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');
const INTERVAL = 86_400;
const WINDOW_KEY =
  'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z';

function run(state: IntelligenceSyncRunRecord['state']): IntelligenceSyncRunRecord {
  return {
    id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    state,
    stage: null,
    requestedAt: NOW,
    startedAt: null,
    completedAt: null,
    nextAttemptAt: null,
    executionAttempt: 0,
    snapshotId: null,
    generationId: null,
    priorAcceptedGenerationId: null,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    failureCategory: null,
    failureCode: null,
    acceptedEntryCount: null,
    warningCount: null,
    notModifiedReason: null,
    correlationId: 'corr-1',
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function freshness(lastSuccessfulSyncAt: Date | null): IntelligenceProviderFreshness {
  return {
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    implementationStatus: 'available',
    runtimeEnabled: true,
    lastSuccessfulSyncAt,
    lastAttemptAt: lastSuccessfulSyncAt,
    latestAcceptedCatalogVersion: null,
    latestAcceptedCatalogReleasedAt: null,
    currentEntryCount: null,
    lastSafeFailureCode: null,
    lastFailureAt: null,
    staleThresholdSeconds: 259_200,
  };
}

describe('createEvaluateKevSyncScheduleUseCase', () => {
  it('does not request work when KEV is disabled', async () => {
    const calls: string[] = [];
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: false,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: {
        findLatestByProviderAndSource: async () => {
          calls.push('sync');
          return undefined;
        },
      },
      freshness: {
        loadCurrentProviderStatus: async () => {
          calls.push('freshness');
          return freshness(null);
        },
      },
      scheduler: {
        requestSync: async () => {
          calls.push('request');
          throw new Error('must not request');
        },
      },
    });
    await expect(useCase.execute({ shutdown: false })).resolves.toEqual({ kind: 'disabled' });
    expect(calls).not.toContain('request');
  });

  it('creates an initial request with a schedule-window dedupe key', async () => {
    const requested: string[] = [];
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: true,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: { findLatestByProviderAndSource: async () => undefined },
      freshness: { loadCurrentProviderStatus: async () => freshness(null) },
      scheduler: {
        requestSync: async (input) => {
          requested.push(input.dedupeKey);
          return ok({
            outcome: 'created' as const,
            syncRun: { ...run('requested'), id: input.syncRunId },
          });
        },
      },
    });
    await expect(useCase.execute({ shutdown: false })).resolves.toEqual({
      kind: 'due_initial',
      syncRunId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    });
    expect(requested).toEqual([WINDOW_KEY]);
  });

  it('maps duplicate_window without treating it as an internal conflict', async () => {
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: true,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: { findLatestByProviderAndSource: async () => run('completed') },
      freshness: {
        loadCurrentProviderStatus: async () => freshness(new Date(NOW.getTime() - 86_400_000)),
      },
      scheduler: {
        requestSync: async () => ok({ outcome: 'duplicate_window' as const }),
      },
    });
    await expect(useCase.execute({ shutdown: false })).resolves.toEqual({
      kind: 'duplicate_window',
    });
  });

  it('does not request while a retry_wait run is inflight', async () => {
    let requested = 0;
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: true,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: { findLatestByProviderAndSource: async () => run('retry_wait') },
      freshness: { loadCurrentProviderStatus: async () => freshness(null) },
      scheduler: {
        requestSync: async () => {
          requested += 1;
          throw new Error('must not request');
        },
      },
    });
    await expect(useCase.execute({ shutdown: false })).resolves.toEqual({
      kind: 'retry_wait_inflight',
    });
    expect(requested).toBe(0);
  });

  it('returns persistence_failure when requestSync fails', async () => {
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: true,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: { findLatestByProviderAndSource: async () => undefined },
      freshness: { loadCurrentProviderStatus: async () => freshness(null) },
      scheduler: {
        requestSync: async () => ({
          ok: false as const,
          error: { code: 'internal', message: 'unavailable' },
        }),
      },
    });
    await expect(useCase.execute({ shutdown: false })).resolves.toEqual({
      kind: 'persistence_failure',
    });
  });

  it('returns shutdown without requesting', async () => {
    const useCase = createEvaluateKevSyncScheduleUseCase({
      clock: { now: () => NOW },
      createId: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      kevEnabled: true,
      syncIntervalSeconds: INTERVAL,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      syncRuns: { findLatestByProviderAndSource: async () => undefined },
      freshness: { loadCurrentProviderStatus: async () => freshness(null) },
      scheduler: {
        requestSync: async () => {
          throw new Error('must not request');
        },
      },
    });
    await expect(useCase.execute({ shutdown: true })).resolves.toEqual({ kind: 'shutdown' });
  });
});
