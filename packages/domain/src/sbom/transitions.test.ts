import { describe, expect, it } from 'vitest';

import type { SbomIngestionStage } from '../lifecycle.js';
import {
  applySession8IngestionTransition,
  type Session8IngestionCommand,
  type Session8IngestionSnapshot,
} from './transitions.js';

const startedAt = new Date('2026-08-29T16:00:00.000Z');
const completedAt = new Date('2026-08-29T16:05:00.000Z');

function accepted(): Session8IngestionSnapshot {
  const created = applySession8IngestionTransition(undefined, { type: 'create_accepted' });
  if (!created.ok) {
    throw new Error('expected accepted snapshot');
  }
  return created.value;
}

function queued(): Session8IngestionSnapshot {
  const next = applySession8IngestionTransition(accepted(), { type: 'queue' });
  if (!next.ok) {
    throw new Error('expected queued snapshot');
  }
  return next.value;
}

function processing(
  stage: 'validate' | 'parse' | 'persist_graph' = 'persist_graph',
): Session8IngestionSnapshot {
  const next = applySession8IngestionTransition(queued(), {
    type: 'start_processing',
    startedAt,
    stage,
  });
  if (!next.ok) {
    throw new Error('expected processing snapshot');
  }
  return next.value;
}

describe('session 8 ingestion transitions', () => {
  it('allows initial creation to accepted', () => {
    expect(applySession8IngestionTransition(undefined, { type: 'create_accepted' })).toEqual({
      ok: true,
      value: {
        state: 'accepted',
        stage: null,
        startedAt: null,
        completedAt: null,
        graphCompleteness: null,
        componentCount: null,
        dependencyEdgeCount: null,
        warningCount: null,
        failureCategory: null,
        failureCode: null,
      },
    });
  });

  it('allows accepted to queued', () => {
    const next = applySession8IngestionTransition(accepted(), { type: 'queue' });
    expect(next.ok).toBe(true);
    if (next.ok) {
      expect(next.value.state).toBe('queued');
    }
  });

  it('allows accepted to processing', () => {
    const next = applySession8IngestionTransition(accepted(), {
      type: 'start_processing',
      startedAt,
      stage: 'validate',
    });
    expect(next.ok).toBe(true);
    if (next.ok) {
      expect(next.value.state).toBe('processing');
      expect(next.value.startedAt).toEqual(startedAt);
      expect(next.value.stage).toBe('validate');
    }
  });

  it('allows queued to processing', () => {
    const next = applySession8IngestionTransition(queued(), {
      type: 'start_processing',
      startedAt,
      stage: 'parse',
    });
    expect(next.ok).toBe(true);
    if (next.ok) {
      expect(next.value.state).toBe('processing');
    }
  });

  it('allows processing to queued for retryable infrastructure failure', () => {
    const next = applySession8IngestionTransition(processing(), {
      type: 'release_for_retry',
      failureCode: 'storage_timeout',
    });
    expect(next.ok).toBe(true);
    if (next.ok) {
      expect(next.value.state).toBe('queued');
      expect(next.value.startedAt).toBeNull();
    }
  });

  it('allows processing to completed, rejected, quarantined, and failed', () => {
    const complete = applySession8IngestionTransition(processing(), {
      type: 'complete',
      completedAt,
      graphCompleteness: 'complete',
      componentCount: 2,
      dependencyEdgeCount: 1,
      warningCount: 0,
    });
    expect(complete.ok).toBe(true);
    if (complete.ok) {
      expect(complete.value.state).toBe('completed');
      expect(complete.value.stage).toBe('persist_graph');
      expect(complete.value.graphCompleteness).toBe('complete');
    }

    const rejected = applySession8IngestionTransition(processing(), {
      type: 'reject',
      completedAt,
      failureCode: 'schema_invalid',
    });
    expect(rejected.ok).toBe(true);
    if (rejected.ok) {
      expect(rejected.value.state).toBe('rejected');
      expect(rejected.value.failureCategory).toBe('validation');
    }

    const quarantined = applySession8IngestionTransition(processing(), {
      type: 'quarantine',
      completedAt,
      failureCode: 'parser_timeout',
    });
    expect(quarantined.ok).toBe(true);
    if (quarantined.ok) {
      expect(quarantined.value.state).toBe('quarantined');
    }

    const failed = applySession8IngestionTransition(processing(), {
      type: 'fail',
      completedAt,
      failureCode: 'processing_failed',
    });
    expect(failed.ok).toBe(true);
    if (failed.ok) {
      expect(failed.value.state).toBe('failed');
    }
  });

  it('closes terminal states', () => {
    const terminals: Session8IngestionSnapshot[] = [];
    const completed = applySession8IngestionTransition(processing(), {
      type: 'complete',
      completedAt,
      graphCompleteness: 'empty',
      componentCount: 0,
      dependencyEdgeCount: 0,
      warningCount: 0,
    });
    const rejected = applySession8IngestionTransition(processing(), {
      type: 'reject',
      completedAt,
      failureCode: 'not_cyclonedx',
    });
    const quarantined = applySession8IngestionTransition(processing(), {
      type: 'quarantine',
      completedAt,
      failureCode: 'parser_crash',
    });
    const failed = applySession8IngestionTransition(processing(), {
      type: 'fail',
      completedAt,
      failureCode: 'processing_failed',
    });
    if (completed.ok) terminals.push(completed.value);
    if (rejected.ok) terminals.push(rejected.value);
    if (quarantined.ok) terminals.push(quarantined.value);
    if (failed.ok) terminals.push(failed.value);

    const commands: Session8IngestionCommand[] = [
      { type: 'create_accepted' },
      { type: 'queue' },
      { type: 'start_processing', startedAt, stage: 'validate' },
      { type: 'release_for_retry', failureCode: 'storage_timeout' },
      {
        type: 'complete',
        completedAt,
        graphCompleteness: 'empty',
        componentCount: 0,
        dependencyEdgeCount: 0,
        warningCount: 0,
      },
      { type: 'reject', completedAt, failureCode: 'schema_invalid' },
      { type: 'quarantine', completedAt, failureCode: 'parser_timeout' },
      { type: 'fail', completedAt, failureCode: 'processing_failed' },
    ];

    for (const snapshot of terminals) {
      for (const command of commands) {
        expect(
          applySession8IngestionTransition(snapshot, command).ok,
          `${snapshot.state} ${command.type}`,
        ).toBe(false);
      }
    }
  });

  it('rejects duplicate-state ingestion rows for evidence deduplication', () => {
    const duplicate: Session8IngestionSnapshot = {
      ...accepted(),
      state: 'duplicate',
    };
    expect(applySession8IngestionTransition(duplicate, { type: 'queue' }).ok).toBe(false);
    expect(applySession8IngestionTransition(accepted(), { type: 'create_accepted' }).ok).toBe(
      false,
    );
  });

  it('rejects processing without startedAt', () => {
    const missingStart: Session8IngestionSnapshot = {
      ...processing(),
      startedAt: null,
    };
    expect(
      applySession8IngestionTransition(missingStart, {
        type: 'complete',
        completedAt,
        graphCompleteness: 'empty',
        componentCount: 0,
        dependencyEdgeCount: 0,
        warningCount: 0,
      }).ok,
    ).toBe(false);
  });

  it('rejects completed snapshots that omit graph completeness or counts', () => {
    const incomplete = {
      type: 'complete',
      completedAt,
      graphCompleteness: undefined,
      componentCount: 1,
      dependencyEdgeCount: 0,
      warningCount: 0,
    } as unknown as Session8IngestionCommand;
    expect(applySession8IngestionTransition(processing(), incomplete).ok).toBe(false);
    expect(
      applySession8IngestionTransition(processing(), {
        type: 'complete',
        completedAt,
        graphCompleteness: 'complete',
        componentCount: 0,
        dependencyEdgeCount: 0,
        warningCount: 0,
      }).ok,
    ).toBe(false);
  });

  it('rejects completion through correlate, enrich, or score and other unsupported stages', () => {
    for (const stage of ['correlate', 'enrich', 'score'] as const) {
      const current: Session8IngestionSnapshot = {
        ...processing(),
        stage,
      };
      expect(
        applySession8IngestionTransition(current, {
          type: 'complete',
          completedAt,
          graphCompleteness: 'empty',
          componentCount: 0,
          dependencyEdgeCount: 0,
          warningCount: 0,
        }).ok,
      ).toBe(false);
      expect(
        applySession8IngestionTransition(queued(), {
          type: 'start_processing',
          startedAt,
          stage: stage as unknown as 'validate',
        }).ok,
      ).toBe(false);
    }

    expect(
      applySession8IngestionTransition(processing(), {
        type: 'start_processing',
        startedAt,
        stage: 'persist_graph',
      }).ok,
    ).toBe(false);
    expect(
      applySession8IngestionTransition(processing('validate'), {
        type: 'release_for_retry',
        failureCode: 'schema_invalid',
      }).ok,
    ).toBe(false);
  });

  it('does not treat lease timestamps as the processor lock', () => {
    expect(applySession8IngestionTransition.toString()).not.toContain('leaseExpiresAt');
    const next = applySession8IngestionTransition(processing(), {
      type: 'complete',
      completedAt,
      graphCompleteness: 'no_dependencies',
      componentCount: 1,
      dependencyEdgeCount: 0,
      warningCount: 0,
    });
    expect(next.ok).toBe(true);
    if (next.ok) {
      expect(Object.keys(next.value).sort()).toEqual([
        'completedAt',
        'componentCount',
        'dependencyEdgeCount',
        'failureCategory',
        'failureCode',
        'graphCompleteness',
        'stage',
        'startedAt',
        'state',
        'warningCount',
      ]);
    }
  });

  it('rejects forbidden non-terminal jumps', () => {
    expect(applySession8IngestionTransition(queued(), { type: 'queue' }).ok).toBe(false);
    expect(
      applySession8IngestionTransition(accepted(), {
        type: 'complete',
        completedAt,
        graphCompleteness: 'empty',
        componentCount: 0,
        dependencyEdgeCount: 0,
        warningCount: 0,
      }).ok,
    ).toBe(false);
    expect(
      applySession8IngestionTransition(queued(), {
        type: 'reject',
        completedAt,
        failureCode: 'schema_invalid',
      }).ok,
    ).toBe(false);
  });

  it('uses Session 8 stages only in helpers', () => {
    const unused: SbomIngestionStage[] = ['correlate', 'enrich', 'score'];
    expect(unused).toHaveLength(3);
  });
});
