import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';
import { boundPageSize, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './paging.js';
import {
  normalizeEmail,
  normalizeSlug,
  requireArgon2idPhc,
  requirePasswordRevision,
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

  it('accepts Argon2id PHC strings and password revisions >= 1', () => {
    const phc =
      '$argon2id$v=19$m=19456,p=1,t=2$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaGZvcmxvY2FsY3JlZGU';
    expect(requireArgon2idPhc(phc, 'passwordHash')).toBe(phc);
    expect(() =>
      requireArgon2idPhc('plaintext-password-value-long-enough', 'passwordHash'),
    ).toThrow(/Argon2id PHC/);
    expect(requirePasswordRevision(1, 'passwordRevision')).toBe(1);
    expect(() => requirePasswordRevision(0, 'passwordRevision')).toThrow(/>= 1/);
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
    expect(() => normalizeEmail('owner@synthetic..patchpilot.test')).toThrow(/email/);
    expect(() => normalizeEmail('owner@nodot')).toThrow(/email/);
  });

  it('rejects oversized email input before regex matching', () => {
    const oversized = `${'a'.repeat(321)}@example.test`;
    const started = Date.now();
    expect(() => normalizeEmail(oversized)).toThrow(/email/);
    expect(Date.now() - started).toBeLessThan(1000);

    const adversarial = `!@${'!.'.repeat(50_000)}`;
    const attackStarted = Date.now();
    expect(() => normalizeEmail(adversarial)).toThrow(/email/);
    expect(Date.now() - attackStarted).toBeLessThan(1000);
  });
});

describe('page bounds', () => {
  it('clamps repository page sizes', () => {
    expect(boundPageSize(undefined)).toBe(DEFAULT_PAGE_SIZE);
    expect(boundPageSize(500)).toBe(MAX_PAGE_SIZE);
  });
});

describe('public package surface', () => {
  it('does not export the persistence fixture as application API', () => {
    expect('persistTenantChangeWithAuditAndOutbox' in databasePublic).toBe(false);
  });
});
