import { describe, expect, it } from 'vitest';

import {
  parseApprovedSbomContentType,
  parseDeclaredByteLength,
  parseIdempotencyKeyHeader,
} from './sbom-content-type.js';

describe('SBOM content-type parsing', () => {
  it('accepts approved media types and optional UTF-8 charset', () => {
    expect(parseApprovedSbomContentType('application/json')).toEqual({
      ok: true,
      contentType: 'application/json',
    });
    expect(parseApprovedSbomContentType('application/vnd.cyclonedx+json; charset=utf-8')).toEqual({
      ok: true,
      contentType: 'application/vnd.cyclonedx+json',
    });
    expect(parseApprovedSbomContentType('Application/JSON; charset="UTF-8"')).toEqual({
      ok: true,
      contentType: 'application/json',
    });
    expect(parseApprovedSbomContentType('application/json;charset=utf8')).toEqual({
      ok: true,
      contentType: 'application/json',
    });
  });

  it('rejects unapproved media types, non-UTF-8 charsets, and unknown parameters', () => {
    expect(parseApprovedSbomContentType(undefined).ok).toBe(false);
    expect(parseApprovedSbomContentType('application/zip')).toEqual({
      ok: false,
      reason: 'media_type',
    });
    expect(parseApprovedSbomContentType('application/json; charset=utf-16')).toEqual({
      ok: false,
      reason: 'charset',
    });
    expect(parseApprovedSbomContentType('application/json; boundary=abc')).toEqual({
      ok: false,
      reason: 'parameter',
    });
  });
});

describe('SBOM upload headers', () => {
  it('requires a visible ASCII Idempotency-Key within bounds', () => {
    expect(parseIdempotencyKeyHeader('upload-1', 1, 256)).toEqual({ ok: true, value: 'upload-1' });
    expect(parseIdempotencyKeyHeader(undefined, 1, 256).ok).toBe(false);
    expect(parseIdempotencyKeyHeader('a'.repeat(257), 1, 256).ok).toBe(false);
    expect(parseIdempotencyKeyHeader('has space', 1, 256).ok).toBe(false);
  });

  it('enforces Content-Length against the per-route upload ceiling', () => {
    expect(parseDeclaredByteLength(undefined, 64)).toEqual({ ok: true });
    expect(parseDeclaredByteLength('32', 64)).toEqual({ ok: true, value: 32 });
    expect(parseDeclaredByteLength('65', 64)).toEqual({ ok: false, tooLarge: true });
    expect(parseDeclaredByteLength('0', 64)).toEqual({ ok: false, tooLarge: false });
    expect(parseDeclaredByteLength('12ab', 64)).toEqual({ ok: false, tooLarge: false });
  });
});
