import { describe, expect, it } from 'vitest';

import {
  isIdentityContentEncoding,
  parseApprovedJsonMediaType,
  parseDeclaredContentLength,
} from './intelligence-http-media-type.js';

describe('intelligence HTTP media type', () => {
  it('accepts application/json with optional UTF-8 charset and insignificant whitespace', () => {
    expect(parseApprovedJsonMediaType('application/json')).toBe('application/json');
    expect(parseApprovedJsonMediaType('Application/JSON')).toBe('application/json');
    expect(parseApprovedJsonMediaType('application/json; charset=utf-8')).toBe(
      'application/json; charset=utf-8',
    );
    expect(parseApprovedJsonMediaType('application/json ; charset = "UTF-8"')).toBe(
      'application/json; charset=utf-8',
    );
  });

  it('rejects unsupported, duplicate, and non-JSON media types', () => {
    expect(parseApprovedJsonMediaType('application/json; charset=utf-16')).toBeUndefined();
    expect(
      parseApprovedJsonMediaType('application/json; charset=utf-8; charset=utf-8'),
    ).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/json, application/json')).toBeUndefined();
    expect(parseApprovedJsonMediaType(['application/json', 'text/plain'])).toBeUndefined();
    expect(parseApprovedJsonMediaType('text/html')).toBeUndefined();
    expect(parseApprovedJsonMediaType('text/plain')).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/octet-stream')).toBeUndefined();
    expect(parseApprovedJsonMediaType('multipart/form-data')).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/xml')).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/zip')).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/gzip')).toBeUndefined();
    expect(parseApprovedJsonMediaType('application/vnd.api+json')).toBeUndefined();
  });

  it('accepts absent or identity Content-Encoding and rejects compression', () => {
    expect(isIdentityContentEncoding(undefined)).toBe(true);
    expect(isIdentityContentEncoding('identity')).toBe(true);
    expect(isIdentityContentEncoding('IDENTITY')).toBe(true);
    expect(isIdentityContentEncoding('gzip')).toBe(false);
    expect(isIdentityContentEncoding('br')).toBe(false);
    expect(isIdentityContentEncoding('deflate')).toBe(false);
    expect(isIdentityContentEncoding(['identity', 'gzip'])).toBe(false);
  });

  it('parses Content-Length and rejects invalid or conflicting values', () => {
    expect(parseDeclaredContentLength(undefined)).toEqual({ kind: 'absent' });
    expect(parseDeclaredContentLength('12')).toEqual({ kind: 'value', bytes: 12 });
    expect(parseDeclaredContentLength('0')).toEqual({ kind: 'value', bytes: 0 });
    expect(parseDeclaredContentLength('abc')).toEqual({ kind: 'invalid' });
    expect(parseDeclaredContentLength(['12', '13'])).toEqual({ kind: 'invalid' });
  });
});
