import { err, ok, type Result } from '../result.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH,
  INTELLIGENCE_DEDUPE_KEY_PATTERN,
  INTELLIGENCE_SCHEDULE_WINDOW_UTC_PATTERN,
} from './constants.js';
import { intelligenceValidationError } from './errors.js';
import { isPositiveSafeInteger } from './normalize.js';
import { buildIntelligenceSyncDedupeKey } from './outbox.js';

export type KevScheduleWindow = {
  windowStartMs: number;
  windowStartUtc: string;
};

function pad2(value: number): string {
  return value < 10 ? `0${String(value)}` : String(value);
}

/**
 * Canonical UTC whole-second timestamp. Uses UTC getters only — never local
 * timezone or locale formatting.
 */
export function formatUtcWindowStart(windowStartMs: number): Result<string> {
  if (!Number.isSafeInteger(windowStartMs) || windowStartMs < 0) {
    return err(
      intelligenceValidationError('Schedule window start is not a safe epoch millisecond.'),
    );
  }
  const date = new Date(windowStartMs);
  if (Number.isNaN(date.getTime()) || date.getTime() !== windowStartMs) {
    return err(intelligenceValidationError('Schedule window start is not a UTC instant.'));
  }
  const formatted = `${String(date.getUTCFullYear())}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())}T${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())}Z`;
  if (!INTELLIGENCE_SCHEDULE_WINDOW_UTC_PATTERN.test(formatted)) {
    return err(
      intelligenceValidationError('Schedule window timestamp is not canonical UTC seconds.'),
    );
  }
  return ok(formatted);
}

/**
 * Align `nowEpochMs` to the closed UTC interval that starts at
 * `floor(now / intervalMs) * intervalMs`. An exact boundary belongs to the
 * new window. One millisecond before the boundary belongs to the previous
 * window. Interval changes are not backfilled.
 */
export function calculateKevScheduleWindow(input: {
  nowEpochMs: number;
  syncIntervalSeconds: number;
}): Result<KevScheduleWindow> {
  if (!Number.isSafeInteger(input.nowEpochMs) || input.nowEpochMs < 0) {
    return err(intelligenceValidationError('Schedule clock is not a safe epoch millisecond.'));
  }
  if (!isPositiveSafeInteger(input.syncIntervalSeconds)) {
    return err(
      intelligenceValidationError('Synchronization interval must be a positive safe integer.'),
    );
  }
  const intervalMs = input.syncIntervalSeconds * 1000;
  if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
    return err(
      intelligenceValidationError('Synchronization interval overflowed safe integer milliseconds.'),
    );
  }
  const windowStartMs = Math.floor(input.nowEpochMs / intervalMs) * intervalMs;
  if (!Number.isSafeInteger(windowStartMs) || windowStartMs < 0) {
    return err(
      intelligenceValidationError('Schedule window start overflowed safe integer milliseconds.'),
    );
  }
  const windowStartUtc = formatUtcWindowStart(windowStartMs);
  if (!windowStartUtc.ok) {
    return windowStartUtc;
  }
  return ok({
    windowStartMs,
    windowStartUtc: windowStartUtc.value,
  });
}

export function buildKevScheduleWindowDedupeKey(windowStartUtc: string): Result<string> {
  if (!INTELLIGENCE_SCHEDULE_WINDOW_UTC_PATTERN.test(windowStartUtc)) {
    return err(intelligenceValidationError('Schedule window is not canonical UTC seconds.'));
  }
  const key = buildIntelligenceSyncDedupeKey({
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    scheduleWindow: windowStartUtc,
  });
  if (!key.ok) {
    return key;
  }
  if (key.value.length > INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH) {
    return err(intelligenceValidationError('Dedupe key exceeds the bounded length.'));
  }
  if (!INTELLIGENCE_DEDUPE_KEY_PATTERN.test(key.value)) {
    return err(intelligenceValidationError('Dedupe key uses disallowed characters.'));
  }
  return key;
}
