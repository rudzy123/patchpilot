import { describe, expect, it } from 'vitest';

import { attemptsRemain, mapIntelligenceSyncFailure } from './sync-failures.js';

describe('intelligence sync failure mapping', () => {
  it('uses retry_wait only before a snapshot is stored', () => {
    expect(
      mapIntelligenceSyncFailure({
        code: 'connection_timeout',
        layer: 'pre_snapshot',
        attemptsRemaining: true,
      }),
    ).toEqual({ kind: 'retry_wait', code: 'connection_timeout' });
  });

  it('keeps post-snapshot retryable failures on the BackgroundJob', () => {
    expect(
      mapIntelligenceSyncFailure({
        code: 'parser_timeout',
        layer: 'post_snapshot',
        attemptsRemaining: true,
      }),
    ).toEqual({ kind: 'job_retry', code: 'parser_timeout' });
    expect(
      mapIntelligenceSyncFailure({
        code: 'parser_crash',
        layer: 'post_snapshot',
        attemptsRemaining: true,
      }),
    ).toEqual({ kind: 'job_retry', code: 'parser_crash' });
  });

  it('quarantines provider-content failures and fails when attempts are exhausted', () => {
    expect(
      mapIntelligenceSyncFailure({
        code: 'schema_invalid',
        layer: 'post_snapshot',
        attemptsRemaining: true,
      }),
    ).toEqual({ kind: 'quarantined', code: 'schema_invalid' });
    expect(
      mapIntelligenceSyncFailure({
        code: 'connection_timeout',
        layer: 'pre_snapshot',
        attemptsRemaining: false,
      }),
    ).toEqual({ kind: 'failed', code: 'connection_timeout' });
    expect(attemptsRemain(4, 5)).toBe(true);
    expect(attemptsRemain(5, 5)).toBe(false);
  });
});
