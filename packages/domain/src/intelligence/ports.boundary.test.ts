import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { err, ok } from '../result.js';
import { INTELLIGENCE_ARBITRARY_URL_FORBIDDEN } from './errors.js';
import { parseIntelligenceSnapshotObjectKey } from './object-keys.js';
import type {
  IntelligenceGenerationPersistencePort,
  IntelligenceProviderHttpPort,
  IntelligenceProviderHttpRequest,
  IntelligenceSnapshotPersistencePort,
  IntelligenceSnapshotStoragePort,
  IntelligenceSourceFreshnessPort,
  IntelligenceSyncRunPersistencePort,
} from './ports.js';
import { buildIntelligenceSyncRequestCommands } from './scheduler.js';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)));

function productionTypeScriptFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...productionTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.name.endsWith('.test.ts')) {
      continue;
    }
    if (entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

const BANNED =
  /FindingRepository|FindingObservation|createFinding|finding\.recalculate|ComponentRepository|ComponentOccurrence|AssetRepository|SbomRepository|RiskCalculation|@prisma\/client|@patchpilot\/database|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|from 'fastify'|from "fastify"|from 'next'|process\.env|https\.request|http\.request|\bfetch\s*\(|S3Client|@aws-sdk|IncomingMessage|undici/;

describe('intelligence ports and zero-Finding boundary', () => {
  it('keeps intelligence production sources free of Finding, HTTP, database, and queue runtimes', () => {
    const files = productionTypeScriptFiles(packageRoot);
    expect(files.length).toBeGreaterThan(0);
    for (const filePath of files) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(BANNED);
    }
  });

  it('rejects arbitrary URLs on the provider HTTP port and keeps responses streaming', () => {
    const source = readFileSync(join(packageRoot, 'ports.ts'), 'utf8');
    expect(source).not.toMatch(/url\?: string|url: string/);
    expect(source).toContain('body: IntelligenceByteStream');
    expect(source).toContain('completion: Promise<IntelligenceProviderHttpCompletion>');
    expect(source).toContain('cancel: () => Promise<void>');
    expect(source).not.toContain('IncomingMessage');
    expect(source).not.toContain('redirectUrl');
    expect(source).not.toContain('redirectTarget');
    expect(INTELLIGENCE_ARBITRARY_URL_FORBIDDEN.message).toContain('caller-supplied URLs');
    const request: IntelligenceProviderHttpRequest = {
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      maxBytes: 1024,
      connectTimeoutMs: 1000,
      totalTimeoutMs: 5000,
      retryPolicy: { maxRetries: 0, backoffFloorMs: 250, backoffCeilingMs: 1000 },
      correlationId: 'corr-1',
    };
    expect(request).not.toHaveProperty('url');
    const http: Pick<IntelligenceProviderHttpPort, 'fetchCatalog'> = {
      fetchCatalog: async (_request) => ({
        kind: 'failure',
        category: 'network',
        code: 'dns_rejected',
      }),
    };
    expect(http.fetchCatalog.length).toBe(1);
  });

  it('keeps snapshot storage provider-neutral, streaming, and distinct from SBOM keys', () => {
    const source = readFileSync(join(packageRoot, 'ports.ts'), 'utf8');
    expect(source).not.toMatch(/S3Client|PutObjectCommand|GetObjectCommand|@aws-sdk/);
    expect(source).not.toContain('publicUrl');
    expect(source).toContain('IntelligenceSnapshotObjectKey');
    expect(source).not.toContain('SbomObjectKey');
    const key = parseIntelligenceSnapshotObjectKey('kev-snapshot-opaque-internal-1');
    expect(key.ok).toBe(true);
    const storage: Pick<IntelligenceSnapshotStoragePort, 'putTemporarySnapshot'> = {
      putTemporarySnapshot: async (input) =>
        ok({ sha256: 'a'.repeat(64), observedByteLength: input.maxBytes }),
    };
    expect(storage.putTemporarySnapshot.length).toBe(1);
  });

  it('scopes intelligence persistence globally without organizationId or raw bodies', () => {
    const source = readFileSync(join(packageRoot, 'ports.ts'), 'utf8');
    expect(source).toContain('organizationId: null');
    expect(source).not.toMatch(/organizationId\?: string/);
    expect(source).not.toMatch(/organizationId: string[;,]|organizationId: string \| undefined/);
    expect(source).not.toMatch(/rawBody|rawEtag|providerError|providerException/);
    expect(source).toContain('applyCompareAndSetTransition');
    expect(source).toContain('listActiveEntries');
    expect(source).toContain('activateCompleteGeneration');
    expect(source).toContain('previousActiveGenerationId');
    expect(source).toContain('atomically');
    expect(source).toContain('createStagingGeneration');
    expect(source).not.toContain('renewExecutionLease');
    expect(source).not.toContain('leaseExpiresAt');
    expect(source).toContain('IntelligenceSyncUnitOfWork');
    const runs: Pick<
      IntelligenceSyncRunPersistencePort,
      'findById' | 'applyCompareAndSetTransition'
    > = {
      findById: async (id) => {
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
      applyCompareAndSetTransition: async (input) =>
        err({ code: 'conflict', message: input.expectedState }),
    };
    const snapshots: Pick<IntelligenceSnapshotPersistencePort, 'findById'> = {
      findById: async (_id) => undefined,
    };
    const generations: Pick<IntelligenceGenerationPersistencePort, 'findActiveGeneration'> = {
      findActiveGeneration: async (_provider, _source) => undefined,
    };
    const freshness: Pick<IntelligenceSourceFreshnessPort, 'loadCurrentProviderStatus'> = {
      loadCurrentProviderStatus: async (_provider, _source, _now) => ({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        implementationStatus: 'available',
        runtimeEnabled: true,
        lastSuccessfulSyncAt: null,
        lastAttemptAt: null,
        latestAcceptedCatalogVersion: null,
        latestAcceptedCatalogReleasedAt: null,
        currentEntryCount: null,
        lastSafeFailureCode: null,
        lastFailureAt: null,
        staleThresholdSeconds: 259_200,
      }),
    };
    void runs.findById('id');
    expect(runs.findById.length).toBe(1);
    expect(snapshots.findById.length).toBe(1);
    expect(generations.findActiveGeneration.length).toBe(2);
    expect(freshness.loadCurrentProviderStatus.length).toBe(3);
  });

  it('builds scheduler commands without a unit of work or tenant IDs', () => {
    const built = buildIntelligenceSyncRequestCommands({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      requestedAt: new Date('2026-08-31T16:00:00.000Z'),
      correlationId: 'corr-intel-1',
      syncRunId: '99999999-9999-4999-8999-999999999999',
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      requestToken: 'manual-1',
    });
    expect(built.ok).toBe(true);
    if (built.ok) {
      expect(built.value.syncRun.state).toBe('requested');
      expect(built.value.audit.actorType).toBe('system');
      expect(built.value.outbox.eventType).toBe('intelligence.sync.requested.v1');
      expect(built.value.outbox.organizationId).toBeUndefined();
      expect(built.value.outbox.payload.ids['syncRunId']).toBe(
        '99999999-9999-4999-8999-999999999999',
      );
    }
    expect(
      buildIntelligenceSyncRequestCommands({
        provider: 'osv',
        sourceIdentifier: 'cisa_kev_json_catalog',
        requestedAt: new Date('2026-08-31T16:00:00.000Z'),
        correlationId: 'corr-intel-1',
        syncRunId: '99999999-9999-4999-8999-999999999999',
        parserVersion: '0.1.0',
        normalizationVersion: '1',
        requestToken: 'manual-1',
      }).ok,
    ).toBe(false);
  });
});
