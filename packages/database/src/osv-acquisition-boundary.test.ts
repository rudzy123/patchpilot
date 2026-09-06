import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));

const PRODUCTION = [
  'osv-acquisition-persistence.ts',
  'osv-acquisition-mappers.ts',
  'osv-acquisition-errors.ts',
  'osv-acquisition-graphs.ts',
  'osv-acquisition-inspection.ts',
] as const;

const BANNED =
  /ioredis|bullmq|@aws-sdk|S3Client|MinIO|from 'fastify'|from "fastify"|from 'next'|from "next"|worker_threads|child_process|process\.env|https\.request|http\.request|\bfetch\s*\(|from 'apps\/|from "apps\/|FindingRepository|FindingObservationRepository|EvidenceRepository|RiskCalculationRepository|ComponentRepository|createFinding|finding\.recalculate|INTELLIGENCE_OSV_ENABLED|yauzl|unzipper|node-stream-zip|organizationId|tenantId|assetId|findingId|\.upsert\(|\$executeRaw|eval\(|new Function/;

describe('OSV acquisition adapter source boundary', () => {
  it('keeps production adapters free of tenant, Finding, transport, and storage coupling', () => {
    for (const name of PRODUCTION) {
      const source = readFileSync(path.join(srcDir, name), 'utf8');
      expect(source, name).not.toMatch(BANNED);
      expect(source, name).not.toContain('setTimeout');
      expect(source, name).not.toContain('setInterval');
      expect(source, name).not.toContain('new Worker');
      expect(source, name).not.toContain('Uint8Array');
      expect(source, name).not.toContain('presignedUrl');
      expect(source, name).not.toContain('storage.googleapis.com');
    }
    const persistence = readFileSync(path.join(srcDir, 'osv-acquisition-persistence.ts'), 'utf8');
    expect(persistence).toContain("from '@prisma/client'");
    expect(persistence).toContain('@patchpilot/vulnerability-intelligence');
    expect(persistence).toContain('createOsvIdempotencyResult');
    expect(persistence).toContain('already_applied');
    expect(persistence).toContain('immutable_conflict');
    expect(persistence).toContain('pg_advisory_xact_lock');
    expect(persistence).toContain('FOR UPDATE');
    expect(persistence).toContain('Serializable');
    expect(persistence).not.toContain('.delete(');
    expect(persistence).not.toContain('.deleteMany(');
    expect(persistence).not.toContain('.upsert(');
    expect(persistence).toContain('MAX_TRANSACTION_ATTEMPTS = 1');
  });

  it('does not perform import-time database or network work', () => {
    expect(existsSync(path.join(srcDir, 'osv-acquisition-persistence.ts'))).toBe(true);
    expect('createOsvAcquisitionPersistence' in databasePublic).toBe(true);
    expect('createOsvAcquisitionResumeInspection' in databasePublic).toBe(true);
    expect('createOsvAcquisitionPersistenceForClient' in databasePublic).toBe(false);
    expect('PrismaOsvInventoryPersistence' in databasePublic).toBe(false);
    expect('mapCatalogGeneration' in databasePublic).toBe(false);
    expect('PrismaClient' in databasePublic).toBe(false);
  });
});
