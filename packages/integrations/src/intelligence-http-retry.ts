import { setTimeout as delay } from 'node:timers/promises';

import {
  classifyIntelligenceSafeFailure,
  type IntelligenceSafeFailureCode,
} from '@patchpilot/domain';
import type { Clock } from '@patchpilot/domain';

export type IntelligenceRetryDelay = (ms: number, signal?: AbortSignal) => Promise<void>;
export type IntelligenceRetryJitter = (computedBackoffMs: number) => number;

const HTTP_RETRYABLE_CODES = new Set<IntelligenceSafeFailureCode>([
  'connection_timeout',
  'response_timeout',
  'rate_limited',
  'provider_server_error',
]);

export function isIntelligenceHttpRetryable(code: IntelligenceSafeFailureCode): boolean {
  return HTTP_RETRYABLE_CODES.has(code) && classifyIntelligenceSafeFailure(code).retryable;
}

export function exponentialBackoffMs(
  attempt: number,
  floorMs: number,
  ceilingMs: number,
  jitter: IntelligenceRetryJitter,
): number {
  const exp = Math.min(ceilingMs, floorMs * 2 ** Math.max(0, attempt));
  const withJitter = jitter(exp);
  if (!Number.isFinite(withJitter)) {
    return Math.min(ceilingMs, Math.max(floorMs, exp));
  }

  return Math.min(ceilingMs, Math.max(floorMs, Math.trunc(withJitter)));
}

export function parseRetryAfterMs(
  header: string | string[] | undefined,
  now: Date,
  _floorMs: number,
  _ceilingMs: number,
): number | undefined {
  if (header === undefined) {
    return undefined;
  }

  const raw = Array.isArray(header) ? header[0] : header;
  if (raw === undefined) {
    return undefined;
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  if (/^[0-9]+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    if (!Number.isSafeInteger(seconds)) {
      return undefined;
    }

    return seconds * 1000;
  }

  const parsed = Date.parse(trimmed);
  if (Number.isNaN(parsed)) {
    return undefined;
  }

  return parsed - now.getTime();
}

export function resolveIntelligenceRetryDelayMs(input: {
  retryAfterHeader?: string | string[];
  attempt: number;
  floorMs: number;
  ceilingMs: number;
  now: Date;
  jitter: IntelligenceRetryJitter;
}): number {
  const parsed = parseRetryAfterMs(
    input.retryAfterHeader,
    input.now,
    input.floorMs,
    input.ceilingMs,
  );
  if (parsed === undefined) {
    return exponentialBackoffMs(input.attempt, input.floorMs, input.ceilingMs, input.jitter);
  }

  if (parsed <= 0) {
    return input.floorMs;
  }

  if (parsed > input.ceilingMs) {
    return input.ceilingMs;
  }

  return parsed;
}

export function clampRetryAfterMs(value: number, ceilingMs: number): number {
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }

  return Math.min(ceilingMs, Math.trunc(value));
}

export async function defaultIntelligenceRetryDelay(
  ms: number,
  signal?: AbortSignal,
): Promise<void> {
  if (ms <= 0) {
    return;
  }

  await delay(ms, undefined, signal === undefined ? {} : { signal });
}

export function defaultIntelligenceRetryJitter(computedBackoffMs: number): number {
  const spread = Math.max(0, Math.trunc(computedBackoffMs * 0.2));
  if (spread === 0) {
    return computedBackoffMs;
  }

  return computedBackoffMs - Math.floor(Math.random() * (spread + 1));
}

export type { Clock };
