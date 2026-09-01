import { describe, expect, it } from 'vitest';

import {
  applyIntelligenceSyncRunTransition,
  assertSyncRunStateInvariants,
  isIntelligenceForbiddenSyncStage,
  isIntelligenceTerminalSyncRunState,
  syncRunFreshnessMayAdvance,
  type IntelligenceSyncRunCommand,
  type IntelligenceSyncRunSnapshot,
} from './transitions.js';

const requestedAt = new Date('2026-08-31T16:00:00.000Z');
const startedAt = new Date('2026-08-31T16:01:00.000Z');
const completedAt = new Date('2026-08-31T16:10:00.000Z');
const nextAttemptAt = new Date('2026-08-31T16:06:00.000Z');
const SNAPSHOT_ID = '11111111-1111-4111-8111-111111111111';
const GENERATION_ID = '22222222-2222-4222-8222-222222222222';
const PRIOR_GENERATION_ID = '33333333-3333-4333-8333-333333333333';

function unwrap(result: {
  ok: boolean;
  value?: IntelligenceSyncRunSnapshot;
}): IntelligenceSyncRunSnapshot {
  if (!result.ok || result.value === undefined) {
    throw new Error('expected transition success');
  }
  return result.value;
}

function requested(): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(undefined, { type: 'create_requested', requestedAt }),
  );
}

function fetching(
  from: IntelligenceSyncRunSnapshot = requested(),
  attempt = 1,
): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(from, {
      type: 'start_fetching',
      startedAt,
      executionAttempt: attempt,
    }),
  );
}

function retryWait(): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(fetching(), {
      type: 'record_retry_wait',
      nextAttemptAt,
      failureCode: 'connection_timeout',
    }),
  );
}

function stored(): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(fetching(), {
      type: 'record_stored',
      snapshotId: SNAPSHOT_ID,
    }),
  );
}

function parsing(): IntelligenceSyncRunSnapshot {
  return unwrap(applyIntelligenceSyncRunTransition(stored(), { type: 'start_parsing' }));
}

function staging(): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(parsing(), {
      type: 'start_staging',
      generationId: GENERATION_ID,
    }),
  );
}

function activating(): IntelligenceSyncRunSnapshot {
  return unwrap(
    applyIntelligenceSyncRunTransition(staging(), {
      type: 'start_activating',
      generationComplete: true,
    }),
  );
}

describe('intelligence sync-run transitions', () => {
  it('allows every permitted transition', () => {
    expect(requested()).toMatchObject({
      state: 'requested',
      startedAt: null,
      completedAt: null,
      snapshotId: null,
      generationId: null,
    });
    expect(fetching().state).toBe('fetching');
    expect(retryWait().state).toBe('retry_wait');
    expect(fetching(retryWait(), 2).state).toBe('fetching');
    expect(
      unwrap(
        applyIntelligenceSyncRunTransition(fetching(), {
          type: 'complete_not_modified',
          completedAt,
          priorAcceptedGenerationId: PRIOR_GENERATION_ID,
          reason: 'content_sha256_unchanged',
        }),
      ).state,
    ).toBe('not_modified');
    expect(stored().snapshotId).toBe(SNAPSHOT_ID);
    expect(parsing().state).toBe('parsing');
    expect(staging().generationId).toBe(GENERATION_ID);
    expect(activating().state).toBe('activating');
    const completed = unwrap(
      applyIntelligenceSyncRunTransition(activating(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 3,
      }),
    );
    expect(completed.state).toBe('completed');
    expect(completed.acceptedEntryCount).toBe(3);
    expect(syncRunFreshnessMayAdvance(completed)).toBe(true);
  });

  it('allows failed from each non-requested in-progress state', () => {
    for (const snapshot of [
      fetching(),
      retryWait(),
      stored(),
      parsing(),
      staging(),
      activating(),
    ]) {
      const failed = applyIntelligenceSyncRunTransition(snapshot, {
        type: 'fail',
        completedAt,
        failureCode: 'processing_failed',
      });
      expect(failed.ok).toBe(true);
      if (failed.ok) {
        expect(failed.value.state).toBe('failed');
        expect(failed.value.failureCode).toBe('processing_failed');
        expect(syncRunFreshnessMayAdvance(failed.value)).toBe(false);
      }
    }
  });

  it('allows quarantined from stored, parsing, staging, activating, and fetching without a snapshot', () => {
    for (const snapshot of [stored(), parsing(), staging(), activating(), fetching()]) {
      const quarantined = applyIntelligenceSyncRunTransition(snapshot, {
        type: 'quarantine',
        completedAt,
        failureCode: 'schema_invalid',
      });
      expect(quarantined.ok).toBe(true);
      if (quarantined.ok) {
        expect(quarantined.value.state).toBe('quarantined');
        expect(syncRunFreshnessMayAdvance(quarantined.value)).toBe(false);
      }
    }
  });

  it('permits fetching to quarantined only when snapshot evidence was never stored', () => {
    const beforeStorage = applyIntelligenceSyncRunTransition(fetching(), {
      type: 'quarantine',
      completedAt,
      failureCode: 'content_type_invalid',
    });
    expect(beforeStorage.ok).toBe(true);
    if (beforeStorage.ok) {
      expect(beforeStorage.value.snapshotId).toBeNull();
      expect(beforeStorage.value.failureCategory).toBe('content');
    }
  });

  it('rejects prohibited transitions including terminal reopening and Finding stages', () => {
    const completed = unwrap(
      applyIntelligenceSyncRunTransition(activating(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 1,
      }),
    );
    expect(isIntelligenceTerminalSyncRunState(completed.state)).toBe(true);
    expect(
      applyIntelligenceSyncRunTransition(completed, {
        type: 'start_fetching',
        startedAt,
        executionAttempt: 1,
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(requested(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 1,
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(fetching(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 1,
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(parsing(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 1,
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(staging(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: 1,
      }).ok,
    ).toBe(false);
    expect(isIntelligenceForbiddenSyncStage('match')).toBe(true);
    expect(isIntelligenceForbiddenSyncStage('correlate')).toBe(true);
    expect(isIntelligenceForbiddenSyncStage('enrich_findings')).toBe(true);
    expect(isIntelligenceForbiddenSyncStage('score')).toBe(true);
    expect(isIntelligenceForbiddenSyncStage('remediate')).toBe(true);
  });

  it('enforces retry_wait, stored, staging, completed, not_modified, failure, and quarantine metadata', () => {
    const wait = retryWait();
    expect(wait.nextAttemptAt).toEqual(nextAttemptAt);
    expect(wait.failureCode).toBe('connection_timeout');
    expect(wait.completedAt).toBeNull();
    expect(wait.executionAttempt).toBe(1);
    expect(assertSyncRunStateInvariants(wait).ok).toBe(true);
    expect(
      assertSyncRunStateInvariants({
        ...wait,
        executionAttempt: 0,
      }).ok,
    ).toBe(false);
    expect(
      assertSyncRunStateInvariants({
        ...wait,
        failureCode: 'schema_invalid',
        failureCategory: 'schema',
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(fetching(), {
        type: 'record_retry_wait',
        nextAttemptAt,
        failureCode: 'schema_invalid',
      }).ok,
    ).toBe(false);

    expect(assertSyncRunStateInvariants(stored()).ok).toBe(true);
    expect(staging().generationId).toBe(GENERATION_ID);
    expect(
      applyIntelligenceSyncRunTransition(activating(), {
        type: 'complete',
        completedAt,
        acceptedEntryCount: -1,
      }).ok,
    ).toBe(false);
    expect(
      applyIntelligenceSyncRunTransition(fetching(), {
        type: 'complete_not_modified',
        completedAt,
        priorAcceptedGenerationId: '',
        reason: 'http_not_modified',
      }).ok,
    ).toBe(false);
    const notModified = unwrap(
      applyIntelligenceSyncRunTransition(fetching(), {
        type: 'complete_not_modified',
        completedAt,
        priorAcceptedGenerationId: PRIOR_GENERATION_ID,
        reason: 'http_not_modified',
      }),
    );
    expect(notModified.snapshotId).toBeNull();
    expect(notModified.generationId).toBeNull();
    expect(syncRunFreshnessMayAdvance(notModified)).toBe(true);
  });

  it('rejects unknown command types through the closed union', () => {
    const bogus = { type: 'create_findings' } as unknown as IntelligenceSyncRunCommand;
    expect(() => applyIntelligenceSyncRunTransition(requested(), bogus)).toThrow(
      /Unexpected value/,
    );
  });
});
