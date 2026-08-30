import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { err, ok } from '../result.js';
import {
  buildFinalSbomObjectKey,
  buildTemporarySbomObjectKey,
  isFinalSbomObjectKey,
  isTemporarySbomObjectKey,
} from './object-keys.js';
import {
  deterministicOutboxQueueJobId,
  type BackgroundJobExecutionPort,
  type ComponentGraphPersistencePort,
  type OutboxRelayPersistencePort,
  type SbomIngestionPersistencePort,
  type SbomMetadataPersistencePort,
  type SbomObjectStoragePort,
  type SbomUploadIdempotencyPort,
} from './ports.js';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

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
  /@prisma\/client|Prisma\.|@aws-sdk|S3Client|PutObjectCommand|GetObjectCommand|bullmq|JobsOptions|QueueEvents|ioredis|from 'fastify'|from "fastify"|from 'next'|process\.env/;

describe('session 8 port and domain boundary', () => {
  it('keeps domain production sources provider-neutral', () => {
    const files = productionTypeScriptFiles(packageRoot);
    expect(files.length).toBeGreaterThan(0);
    for (const filePath of files) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(BANNED);
    }
  });

  it('excludes raw Idempotency-Key from idempotency port inputs', () => {
    const source = readFileSync(join(packageRoot, 'sbom/ports.ts'), 'utf8');
    expect(source).toContain('keyHash');
    expect(source).not.toMatch(/rawKey|idempotencyKey/);
    expect(source).not.toContain('Idempotency-Key');
    const port: Pick<SbomUploadIdempotencyPort, 'reserveStarted'> = {
      reserveStarted: async (input) => ({
        kind: 'acquired',
        record: {
          id: '11111111-1111-4111-8111-111111111111',
          organizationId: input.organizationId,
          scope: input.scope,
          keyHash: input.keyHash,
          reservationFingerprint: input.reservationFingerprint,
          status: 'started',
          expiresAt: input.expiresAt,
          completedAt: null,
          response: null,
          finalFingerprint: null,
        },
      }),
    };
    expect(port.reserveStarted.length).toBe(1);
  });

  it('keeps object-storage ports free of AWS SDK types and public-key leakage helpers', () => {
    const storage: Pick<SbomObjectStoragePort, 'verifyBucketAvailability' | 'getObject'> = {
      verifyBucketAvailability: async () =>
        ok({ bucketPrivate: true, publicAccessDisabled: true, signedUrlsDisabled: true }),
      getObject: async (input) =>
        ok({
          body: (async function* () {
            yield new Uint8Array();
          })(),
          byteLength: input.maxBytes,
        }),
    };
    expect(storage.verifyBucketAvailability.length).toBeLessThanOrEqual(1);
    const source = readFileSync(join(packageRoot, 'sbom/ports.ts'), 'utf8');
    expect(source).not.toMatch(/S3Client|PutObjectCommand|GetObjectCommand|@aws-sdk|\$metadata/);
    expect(
      isTemporarySbomObjectKey(
        buildTemporarySbomObjectKey({
          organizationId: '11111111-1111-4111-8111-111111111111',
          assetId: '22222222-2222-4222-8222-222222222222',
          uploadId: '33333333-3333-4333-8333-333333333333',
        }),
      ),
    ).toBe(true);
    expect(
      isFinalSbomObjectKey(
        buildFinalSbomObjectKey({
          organizationId: '11111111-1111-4111-8111-111111111111',
          assetId: '22222222-2222-4222-8222-222222222222',
          sha256: 'a'.repeat(64),
        }),
      ),
    ).toBe(true);
  });

  it('keeps queue and outbox ports free of BullMQ job objects', () => {
    const relay: Pick<OutboxRelayPersistencePort, 'markProcessedAfterQueueAcceptance'> = {
      markProcessedAfterQueueAcceptance: async (_input) =>
        err({ code: 'internal', message: 'adapter deferred' }),
    };
    const jobs: Pick<BackgroundJobExecutionPort, 'findIdempotentTerminal'> = {
      findIdempotentTerminal: async (_input) => undefined,
    };
    expect(relay.markProcessedAfterQueueAcceptance.length).toBe(1);
    expect(jobs.findIdempotentTerminal.length).toBe(1);
    expect(deterministicOutboxQueueJobId({ id: 'evt', eventType: 'sbom.ingest' })).toBe(
      'sbom.ingest:evt',
    );
    const source = readFileSync(join(packageRoot, 'sbom/ports.ts'), 'utf8');
    expect(source).not.toMatch(/bullmq|JobsOptions|Job<|QueueEvents|WorkerOptions|FlowProducer/);
  });

  it('scopes persistence ports by organizationId and omits raw upload bodies', () => {
    const metadata: Pick<SbomMetadataPersistencePort, 'findById'> = {
      findById: async (organizationId, sbomId) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(sbomId.length).toBeGreaterThan(0);
        return undefined;
      },
    };
    const ingestions: Pick<SbomIngestionPersistencePort, 'findById'> = {
      findById: async (organizationId, ingestionId) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(ingestionId.length).toBeGreaterThan(0);
        return undefined;
      },
    };
    const graph: Pick<ComponentGraphPersistencePort, 'persistOnceForIngestion'> = {
      persistOnceForIngestion: async (_input) =>
        err({ code: 'internal', message: 'adapter deferred' }),
    };
    void metadata.findById('org', 'sbom');
    void ingestions.findById('org', 'ingestion');
    expect(metadata.findById.length).toBe(2);
    expect(ingestions.findById.length).toBe(2);
    expect(graph.persistOnceForIngestion.length).toBe(1);
    const source = readFileSync(join(packageRoot, 'sbom/ports.ts'), 'utf8');
    expect(source).not.toMatch(/rawBody|uploadBody|originalBytes|filename|originalFilename/);
  });
});
