import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';
import { boundPageSize, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from './paging.js';
import {
  isUuid,
  normalizeEmail,
  normalizeSlug,
  requireArgon2idPhc,
  requirePasswordRevision,
  requirePositiveByteLength,
  requireSha256,
  requireVersionLabel,
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

  it('requires bounded version labels', () => {
    expect(requireVersionLabel('1.0.0', 'parserVersion')).toBe('1.0.0');
    expect(() => requireVersionLabel('../escape', 'parserVersion')).toThrow(/version label/);
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

  it('accepts UUID v1-v8 values used as tenant identifiers', () => {
    expect(isUuid('11111111-1111-4111-8111-111111111111')).toBe(true);
    expect(isUuid('not-a-uuid')).toBe(false);
    expect(isUuid('')).toBe(false);
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
    expect('createIntelligencePersistence' in databasePublic).toBe(true);
    expect('createIntelligenceStatusReader' in databasePublic).toBe(true);
    expect('seedZeroFindingBaseline' in databasePublic).toBe(false);
  });
});

describe('intelligence adapter source boundary', () => {
  it('does not import AWS, Redis, BullMQ, or HTTP clients', () => {
    const persistence = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'intelligence-persistence.ts'),
      'utf8',
    );
    const status = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'intelligence-status.ts'),
      'utf8',
    );
    for (const source of [persistence, status]) {
      expect(source).not.toMatch(/ioredis|bullmq|@aws-sdk|S3Client|undici|\bfetch\s*\(/);
      expect(source).not.toContain('renewExecutionLease');
      expect(source).not.toContain('FindingRepository');
    }
    expect(status).not.toMatch(
      /organizationId|kevEntry|\$executeRaw|\.create\(|\.update\(|\.delete\(/,
    );
    expect(status).toContain("providerKey: 'cisa_kev'");
    expect(status).toContain('expectedEntryCount');
    expect(status).not.toContain("providerKey: 'osv'");
  });
});

describe('outbox claim SQL', () => {
  it('keeps FOR UPDATE SKIP LOCKED on both production claim statements', () => {
    const source = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'outbox-relay-persistence.ts'),
      'utf8',
    );
    expect(source).toMatch(/WHERE "status" = 'pending'[\s\S]*?FOR UPDATE SKIP LOCKED/);
    expect(source).toMatch(/WHERE "status" = 'claimed'[\s\S]*?FOR UPDATE SKIP LOCKED/);
  });
});

describe('Session 10 Batch 4B public exports', () => {
  const srcDir = path.dirname(fileURLToPath(import.meta.url));

  it('exports the CVE identity factory and not mapper internals', () => {
    expect(existsSync(path.join(srcDir, 'cve-identity-persistence.ts'))).toBe(true);
    expect(existsSync(path.join(srcDir, 'cve-identity-mappers.ts'))).toBe(true);
    expect('createCveIdentityPersistence' in databasePublic).toBe(true);
    expect('mapCveIdentity' in databasePublic).toBe(false);
    expect('mapVulnerabilityCveIdentityLink' in databasePublic).toBe(false);
    expect('CveIdentityMappingError' in databasePublic).toBe(false);
    expect('PrismaCveIdentityPersistence' in databasePublic).toBe(false);
    expect('uniqueTargetTokens' in databasePublic).toBe(false);
  });
});
