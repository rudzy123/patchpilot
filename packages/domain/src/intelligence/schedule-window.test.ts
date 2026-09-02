import { describe, expect, it } from 'vitest';

import {
  INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH,
  INTELLIGENCE_DEDUPE_KEY_PATTERN,
} from './constants.js';
import {
  buildKevScheduleWindowDedupeKey,
  calculateKevScheduleWindow,
  formatUtcWindowStart,
} from './schedule-window.js';

describe('KEV schedule window', () => {
  it('assigns an exact UTC boundary to the new window', () => {
    const window = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T00:00:00.000Z'),
      syncIntervalSeconds: 86_400,
    });
    expect(window).toEqual({
      ok: true,
      value: {
        windowStartMs: Date.parse('2026-09-01T00:00:00.000Z'),
        windowStartUtc: '2026-09-01T00:00:00Z',
      },
    });
  });

  it('assigns one millisecond before a boundary to the previous window', () => {
    const window = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T00:00:00.000Z') - 1,
      syncIntervalSeconds: 86_400,
    });
    expect(window.ok && window.value.windowStartUtc).toBe('2026-08-31T00:00:00Z');
  });

  it('aligns hourly intervals to UTC hours', () => {
    const window = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T13:45:12.123Z'),
      syncIntervalSeconds: 3_600,
    });
    expect(window.ok && window.value.windowStartUtc).toBe('2026-09-01T13:00:00Z');
  });

  it('aligns daily intervals to Unix-epoch UTC midnights', () => {
    const window = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T23:59:59.999Z'),
      syncIntervalSeconds: 86_400,
    });
    expect(window.ok && window.value.windowStartUtc).toBe('2026-09-01T00:00:00Z');
  });

  it('supports a non-day-dividing interval', () => {
    const window = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T01:00:00.000Z'),
      syncIntervalSeconds: 90_000,
    });
    expect(window.ok && window.value.windowStartUtc).toBe('2026-08-31T21:00:00Z');
    const nextBoundary = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T22:00:00.000Z'),
      syncIntervalSeconds: 90_000,
    });
    expect(nextBoundary.ok && nextBoundary.value.windowStartUtc).toBe('2026-09-01T22:00:00Z');
    const beforeNext = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T22:00:00.000Z') - 1,
      syncIntervalSeconds: 90_000,
    });
    expect(beforeNext.ok && beforeNext.value.windowStartUtc).toBe('2026-08-31T21:00:00Z');
  });

  it('is independent of US daylight-saving transitions', () => {
    const before = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-03-08T06:30:00.000Z'),
      syncIntervalSeconds: 3_600,
    });
    const after = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-03-08T08:30:00.000Z'),
      syncIntervalSeconds: 3_600,
    });
    expect(before.ok && before.value.windowStartUtc).toBe('2026-03-08T06:00:00Z');
    expect(after.ok && after.value.windowStartUtc).toBe('2026-03-08T08:00:00Z');
  });

  it('builds the exact schedule-window dedupe key grammar', () => {
    const key = buildKevScheduleWindowDedupeKey('2026-09-01T00:00:00Z');
    expect(key).toEqual({
      ok: true,
      value:
        'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
    });
    expect(key.ok && key.value.length).toBeLessThanOrEqual(INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH);
    expect(key.ok && INTELLIGENCE_DEDUPE_KEY_PATTERN.test(key.value)).toBe(true);
  });

  it('does not backfill when the interval changes', () => {
    const daily = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T12:00:00.000Z'),
      syncIntervalSeconds: 86_400,
    });
    const hourly = calculateKevScheduleWindow({
      nowEpochMs: Date.parse('2026-09-01T12:00:00.000Z'),
      syncIntervalSeconds: 3_600,
    });
    expect(daily.ok && daily.value.windowStartUtc).toBe('2026-09-01T00:00:00Z');
    expect(hourly.ok && hourly.value.windowStartUtc).toBe('2026-09-01T12:00:00Z');
  });

  it('rejects an invalid interval', () => {
    expect(calculateKevScheduleWindow({ nowEpochMs: 1, syncIntervalSeconds: 0 }).ok).toBe(false);
    expect(calculateKevScheduleWindow({ nowEpochMs: 1, syncIntervalSeconds: -3600 }).ok).toBe(
      false,
    );
    expect(calculateKevScheduleWindow({ nowEpochMs: 1, syncIntervalSeconds: 1.5 }).ok).toBe(false);
  });

  it('rejects unsafe integer clock values', () => {
    expect(
      calculateKevScheduleWindow({
        nowEpochMs: Number.MAX_SAFE_INTEGER + 1,
        syncIntervalSeconds: 3600,
      }).ok,
    ).toBe(false);
    expect(formatUtcWindowStart(-1).ok).toBe(false);
  });
});
