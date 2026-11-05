/**
 * Source bounds for the candidate adapter.
 * The PostgreSQL cases live in the integration test.
 */

import { readFileSync } from 'node:fs';

import type { PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { createProductMatchCandidatePersistence } from './product-match-candidate-persistence.js';

describe('product match candidate persistence source', () => {
  it('requires the root Prisma client', () => {
    expect(() => createProductMatchCandidatePersistence({} as PrismaClient)).toThrow(
      /root Prisma client/,
    );
  });

  it('reuses candidate assembly and does not write audit or lock rows', () => {
    const source = readFileSync(
      new URL('./product-match-candidate-persistence.ts', import.meta.url),
      'utf8',
    );
    expect(source).toContain('assembleProductMatchCandidatePage');
    expect(source).toContain('productMatchIdentityKeyForGroup');
    expect(source).toContain('decisions.classifyIdentity');
    expect(source).not.toContain('auditEvent');
    expect(source).not.toContain("revisionDisposition: 'recorded'");
    expect(source).not.toContain('FOR UPDATE');
    expect(source).not.toContain('pg_advisory_xact_lock');
  });
});
