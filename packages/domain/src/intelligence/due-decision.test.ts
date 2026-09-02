import { describe, expect, it } from 'vitest';

import { decideKevSyncDue } from './due-decision.js';
import type { IntelligenceSyncRunRecord } from './records.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');
const INTERVAL = 86_400;

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
    nextAttemptAt: state === 'retry_wait' ? new Date(NOW.getTime() + 30_000) : null,
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

describe('decideKevSyncDue', () => {
  it('returns disabled without creating work', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: false,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: undefined,
        lastSuccessfulSyncAt: null,
      }),
    ).toEqual({ kind: 'disabled' });
  });

  it('returns shutdown before due evaluation', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: true,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: undefined,
        lastSuccessfulSyncAt: null,
      }),
    ).toEqual({ kind: 'shutdown' });
  });

  it('requests an initial synchronization when no successful run exists', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: undefined,
        lastSuccessfulSyncAt: null,
      }),
    ).toEqual({ kind: 'due_initial' });
  });

  it('is not due when elapsed time is less than the interval', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('completed'),
        lastSuccessfulSyncAt: new Date(NOW.getTime() - 86_399_000),
      }),
    ).toEqual({ kind: 'not_due' });
  });

  it('is due when elapsed time equals the interval', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('completed'),
        lastSuccessfulSyncAt: new Date(NOW.getTime() - 86_400_000),
      }),
    ).toEqual({ kind: 'due_periodic' });
  });

  it('treats nonterminal runs as inflight no-ops', () => {
    for (const state of [
      'requested',
      'fetching',
      'stored',
      'parsing',
      'staging',
      'activating',
    ] as const) {
      expect(
        decideKevSyncDue({
          kevEnabled: true,
          shutdown: false,
          now: NOW,
          syncIntervalSeconds: INTERVAL,
          latestSyncRun: run(state),
          lastSuccessfulSyncAt: null,
        }),
      ).toEqual({ kind: 'inflight' });
    }
  });

  it('treats retry_wait as a distinct inflight no-op', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('retry_wait'),
        lastSuccessfulSyncAt: null,
      }),
    ).toEqual({ kind: 'retry_wait_inflight' });
  });

  it('allows the next ordinary window after a failed or quarantined run', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('failed'),
        lastSuccessfulSyncAt: new Date(NOW.getTime() - 86_400_000),
      }),
    ).toEqual({ kind: 'due_periodic' });
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('quarantined'),
        lastSuccessfulSyncAt: null,
      }),
    ).toEqual({ kind: 'due_initial' });
  });

  it('does not use the stale threshold as a due trigger', () => {
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: INTERVAL,
        latestSyncRun: run('completed'),
        lastSuccessfulSyncAt: new Date(NOW.getTime() - 200_000_000),
      }),
    ).toEqual({ kind: 'due_periodic' });
  });
});
