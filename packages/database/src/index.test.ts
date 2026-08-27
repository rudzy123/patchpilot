import { describe, expect, it } from 'vitest';

import { boundPageSize, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './paging.js';
import {
  normalizeEmail,
  normalizeSlug,
  requirePositiveByteLength,
  requireSha256,
} from './guards.js';

describe('input guards', () => {
  it('accepts lowercase SHA-256 digests', () => {
    const digest = 'a'.repeat(64);
    expect(requireSha256(digest, 'sha256')).toBe(digest);
  });

  it('rejects uppercase or short SHA-256 values', () => {
    expect(() => requireSha256('A'.repeat(64), 'sha256')).toThrow(/64 lowercase/);
    expect(() => requireSha256('abc', 'sha256')).toThrow(/64 lowercase/);
  });

  it('requires positive byte lengths', () => {
    expect(requirePositiveByteLength(1, 'byteLength')).toBe(1);
    expect(() => requirePositiveByteLength(0, 'byteLength')).toThrow(/positive/);
  });

  it('normalizes slugs and emails', () => {
    expect(normalizeSlug('Acme-Org', 'slug')).toBe('acme-org');
    expect(() => normalizeSlug('Acme_Org', 'slug')).toThrow(/slug/);
    expect(normalizeEmail('Owner@Synthetic.PatchPilot.Test')).toBe(
      'owner@synthetic.patchpilot.test',
    );
  });
});

describe('page bounds', () => {
  it('clamps repository page sizes', () => {
    expect(boundPageSize(undefined)).toBe(DEFAULT_PAGE_SIZE);
    expect(boundPageSize(500)).toBe(MAX_PAGE_SIZE);
  });
});
