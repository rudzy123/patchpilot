import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));

const BANNED =
  /ioredis|bullmq|@aws-sdk|S3Client|MinIO|from 'fastify'|from "fastify"|from 'next'|from "next"|worker_threads|process\.env|https\.request|http\.request|\bfetch\s*\(|from 'apps\/|from "apps\/|FindingRepository|FindingObservationRepository|EvidenceRepository|RiskCalculationRepository|ComponentRepository|ComponentOccurrenceRepository|AssetRepository|SbomRepository|createFinding|finding\.recalculate|remediation|correlation runtime|INTELLIGENCE_OSV|yauzl|unzipper|node-stream-zip|fflate|adm-zip|jszip|createCveIdentityPersistence|ensureIdentity|ensureLink/;

describe('active KEV membership adapter source boundary', () => {
  it('keeps the production adapter free of HTTP, queues, Finding, and identity writes', () => {
    const source = readFileSync(path.join(srcDir, 'active-kev-membership.ts'), 'utf8');
    expect(source).not.toMatch(BANNED);
    expect(source).not.toContain('setTimeout');
    expect(source).not.toContain('setInterval');
    expect(source).not.toContain('new Worker');
    expect(source).not.toContain('$executeRaw');
    expect(source).not.toContain('.create(');
    expect(source).not.toContain('.update(');
    expect(source).not.toContain('.updateMany(');
    expect(source).not.toContain('.upsert(');
    expect(source).not.toContain('.delete(');
    expect(source).not.toContain('.count(');
    expect(source).not.toContain('listActiveEntries');
    expect(source).not.toContain('organizationId');
    expect(source).not.toContain('cveIdentity');
    expect(source).not.toContain('vendorProject');
    expect(source).not.toContain('rawKnownRansomwareCampaignUse');
    expect(source).toContain('PrismaClientLike');
    expect(source).toContain('@patchpilot/domain');
    expect(source).toContain('providerKey: CISA_KEV_PROVIDER');
    expect(source).toContain('take: 2');
  });

  it('does not perform network, database, timer, or worker work on import', () => {
    expect('createActiveKevMembershipPersistence' in databasePublic).toBe(true);
    expect('PrismaActiveKevMembershipPersistence' in databasePublic).toBe(false);
    expect('SOURCE_SELECT' in databasePublic).toBe(false);
    expect('SelectedSource' in databasePublic).toBe(false);
    expect('mapLoadedSource' in databasePublic).toBe(false);
  });
});
