import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SCOPE = 'c'.repeat(64);
const SCHEMA_COMMIT = 'f3f826310aeca8e324baabd195632f2229952abe';
const NOW = new Date('2026-09-04T12:00:00.000Z');

const GENERATION_PINS = {
  scopeFingerprint: SCOPE,
  providerIdentifier: 'osv',
  inventoryScope: 'osv_gcs_six_prefix_public_export_v1',
  eligibleBodyScope: 'osv_eligible_body_scope_registry_v1',
  sourceLicenseRegistry: 'osv_source_license_registry_v1',
  listingProtocol: 'osv_gcs_json_objects_list_v1',
  transportPolicy: 'osv_transport_policy_v1',
  parserProtocol: 'osv_advisory_parser_protocol_v1',
  parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
  schemaRevision: 'v1.9.0',
  schemaCommit: SCHEMA_COMMIT,
  metadataPolicy: 'osv_metadata_policy_v1',
  syncAlgorithm: 'osv_catalog_sync_algorithm_v1',
} as const;

describe('session 11 OSV acquisition SQL constraints', { timeout: 90_000 }, () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('does not seed an active OSV catalog or pointer', async () => {
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
    expect(await prisma.osvActivationRecord.count()).toBe(0);
    expect(await prisma.osvCatalogGeneration.count({ where: { lifecycleState: 'active' } })).toBe(
      0,
    );
  });

  it('rejects a duplicate provider object natural key', async () => {
    const created = await prisma.osvProviderObject.create({
      data: {
        providerIdentifier: 'osv',
        providerObjectKey: 'npm/GHSA-aaaa-bbbb-cccc.json',
        providerObjectKeyDigest: SHA_A,
        providerPrefix: 'npm/',
        familyKind: 'known',
        familyValue: 'GHSA',
      },
    });
    await expect(
      prisma.osvProviderObject.create({
        data: {
          providerIdentifier: 'osv',
          providerObjectKey: 'npm/GHSA-aaaa-bbbb-cccc.json',
          providerObjectKeyDigest: SHA_B,
          providerPrefix: 'npm/',
          familyKind: 'known',
          familyValue: 'GHSA',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvProviderObject.create({
        data: {
          providerIdentifier: 'osv',
          providerObjectKey: 'npm/GHSA-dddd-eeee-ffff.json',
          providerObjectKeyDigest: SHA_A,
          providerPrefix: 'npm/',
          familyKind: 'known',
          familyValue: 'GHSA',
        },
      }),
    ).rejects.toThrow();
    expect(created.providerObjectKey).not.toMatch(/^intelligence\//);
  });

  it('rejects a duplicate provider generation identity', async () => {
    const object = await prisma.osvProviderObject.create({
      data: {
        providerIdentifier: 'osv',
        providerObjectKey: 'npm/GHSA-1111-2222-3333.json',
        providerObjectKeyDigest: 'd'.repeat(64),
        providerPrefix: 'npm/',
        familyKind: 'known',
        familyValue: 'GHSA',
      },
    });
    await prisma.osvProviderGeneration.create({
      data: {
        providerObjectId: object.id,
        providerObjectKeyDigest: object.providerObjectKeyDigest,
        providerGeneration: '1',
      },
    });
    await expect(
      prisma.osvProviderGeneration.create({
        data: {
          providerObjectId: object.id,
          providerObjectKeyDigest: object.providerObjectKeyDigest,
          providerGeneration: '1',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects malformed provider generations and SHA-256 values', async () => {
    const object = await prisma.osvProviderObject.create({
      data: {
        providerIdentifier: 'osv',
        providerObjectKey: 'npm/MAL-2026-1.json',
        providerObjectKeyDigest: 'e'.repeat(64),
        providerPrefix: 'npm/',
        familyKind: 'known',
        familyValue: 'MAL',
      },
    });
    for (const providerGeneration of ['0', '01', '-1', '1.0', '1e2', ' 1']) {
      await expect(
        prisma.osvProviderGeneration.create({
          data: {
            providerObjectId: object.id,
            providerObjectKeyDigest: object.providerObjectKeyDigest,
            providerGeneration,
          },
        }),
      ).rejects.toThrow();
    }
    await expect(
      prisma.osvProviderObject.create({
        data: {
          providerIdentifier: 'osv',
          providerObjectKey: 'npm/MAL-2026-2.json',
          providerObjectKeyDigest: 'A'.repeat(64),
          providerPrefix: 'npm/',
          familyKind: 'known',
          familyValue: 'MAL',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects negative inventory counts and accepts a valid complete run', async () => {
    const generation = await prisma.osvCatalogGeneration.create({ data: GENERATION_PINS });
    await expect(
      prisma.osvInventoryRun.create({
        data: {
          catalogGenerationId: generation.id,
          state: 'running',
          inventoryScope: GENERATION_PINS.inventoryScope,
          listingProtocol: GENERATION_PINS.listingProtocol,
          transportPolicy: GENERATION_PINS.transportPolicy,
          sourceLicenseRegistry: GENERATION_PINS.sourceLicenseRegistry,
          passCount: 2,
          startedAt: NOW,
          acceptedListedCount: -1,
          listingRejectedCount: 0,
          eligibleCount: 0,
          ineligibleCount: 0,
          legalReviewCount: 0,
          unknownCount: 0,
          ambiguousCount: 0,
          convergence: 'not_comparable',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvInventoryRun.create({
        data: {
          catalogGenerationId: generation.id,
          state: 'complete',
          inventoryScope: GENERATION_PINS.inventoryScope,
          listingProtocol: GENERATION_PINS.listingProtocol,
          transportPolicy: GENERATION_PINS.transportPolicy,
          sourceLicenseRegistry: GENERATION_PINS.sourceLicenseRegistry,
          passCount: 2,
          startedAt: NOW,
          completedAt: NOW,
          acceptedListedCount: 1,
          listingRejectedCount: 0,
          eligibleCount: 1,
          ineligibleCount: 0,
          legalReviewCount: 0,
          unknownCount: 0,
          ambiguousCount: 0,
          convergence: 'converged',
        },
      }),
    ).resolves.toMatchObject({ state: 'complete' });
  });

  it('rejects invalid attachment state and locator combinations', async () => {
    await expect(
      prisma.osvObjectAttachment.create({
        data: {
          storageKind: 'advisory_body',
          role: 'final',
          objectKey: `intelligence/osv/advisory_body/sha256/${SHA_A}`,
          locatorContentSha256: SHA_A,
          contentSha256: SHA_A,
          byteCount: 12,
          contentType: 'application/json',
          contentEncoding: 'identity',
          state: 'staged',
          cleanupEligible: false,
        },
      }),
    ).rejects.toThrow();
    const uploadId = randomUUID();
    await expect(
      prisma.osvObjectAttachment.create({
        data: {
          storageKind: 'advisory_body',
          role: 'temporary',
          objectKey: `intelligence/osv/advisory_body/tmp/${uploadId}`,
          uploadId,
          contentSha256: SHA_A,
          byteCount: 12,
          contentType: 'application/json',
          contentEncoding: 'identity',
          state: 'staged',
          cleanupEligible: false,
        },
      }),
    ).resolves.toMatchObject({ state: 'staged' });
  });

  it('rejects a second snapshot for the same provider generation', async () => {
    const object = await prisma.osvProviderObject.create({
      data: {
        providerIdentifier: 'osv',
        providerObjectKey: 'npm/GHSA-snap-0000-0000.json',
        providerObjectKeyDigest: '1'.repeat(64),
        providerPrefix: 'npm/',
        familyKind: 'known',
        familyValue: 'GHSA',
      },
    });
    const generation = await prisma.osvProviderGeneration.create({
      data: {
        providerObjectId: object.id,
        providerObjectKeyDigest: object.providerObjectKeyDigest,
        providerGeneration: '42',
      },
    });
    const firstAttachment = await prisma.osvObjectAttachment.create({
      data: {
        storageKind: 'advisory_body',
        role: 'final',
        objectKey: `intelligence/osv/advisory_body/sha256/${SHA_A}`,
        locatorContentSha256: SHA_A,
        contentSha256: SHA_A,
        byteCount: 16,
        contentType: 'application/json',
        contentEncoding: 'identity',
        state: 'attached',
        cleanupEligible: false,
      },
    });
    await prisma.osvProviderBodySnapshot.create({
      data: {
        providerGenerationId: generation.id,
        attachmentId: firstAttachment.id,
        contentSha256: SHA_A,
        receivedByteCount: 16,
        declaredByteCount: 16,
        contentType: 'application/json',
        contentEncoding: 'identity',
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
        eligibleBodyScope: GENERATION_PINS.eligibleBodyScope,
        transportPolicy: GENERATION_PINS.transportPolicy,
        retrievedAt: NOW,
        classificationStatus: 'eligible',
      },
    });
    const secondAttachment = await prisma.osvObjectAttachment.create({
      data: {
        storageKind: 'advisory_body',
        role: 'final',
        objectKey: `intelligence/osv/advisory_body/sha256/${SHA_B}`,
        locatorContentSha256: SHA_B,
        contentSha256: SHA_B,
        byteCount: 16,
        contentType: 'application/json',
        contentEncoding: 'identity',
        state: 'attached',
        cleanupEligible: false,
      },
    });
    await expect(
      prisma.osvProviderBodySnapshot.create({
        data: {
          providerGenerationId: generation.id,
          attachmentId: secondAttachment.id,
          contentSha256: SHA_B,
          receivedByteCount: 16,
          declaredByteCount: 16,
          contentType: 'application/json',
          contentEncoding: 'identity',
          sourceIdentifier: 'github_advisory_database',
          registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
          eligibleBodyScope: GENERATION_PINS.eligibleBodyScope,
          transportPolicy: GENERATION_PINS.transportPolicy,
          retrievedAt: NOW,
          classificationStatus: 'eligible',
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid parser success and failure combinations', async () => {
    const object = await prisma.osvProviderObject.create({
      data: {
        providerIdentifier: 'osv',
        providerObjectKey: 'npm/GHSA-parse-0000-0000.json',
        providerObjectKeyDigest: '2'.repeat(64),
        providerPrefix: 'npm/',
        familyKind: 'known',
        familyValue: 'GHSA',
      },
    });
    const generation = await prisma.osvProviderGeneration.create({
      data: {
        providerObjectId: object.id,
        providerObjectKeyDigest: object.providerObjectKeyDigest,
        providerGeneration: '7',
      },
    });
    const attachment = await prisma.osvObjectAttachment.create({
      data: {
        storageKind: 'advisory_body',
        role: 'final',
        objectKey: `intelligence/osv/advisory_body/sha256/${'3'.repeat(64)}`,
        locatorContentSha256: '3'.repeat(64),
        contentSha256: '3'.repeat(64),
        byteCount: 24,
        contentType: 'application/json',
        contentEncoding: 'identity',
        state: 'attached',
        cleanupEligible: false,
      },
    });
    const snapshot = await prisma.osvProviderBodySnapshot.create({
      data: {
        providerGenerationId: generation.id,
        attachmentId: attachment.id,
        contentSha256: '3'.repeat(64),
        receivedByteCount: 24,
        declaredByteCount: 24,
        contentType: 'application/json',
        contentEncoding: 'identity',
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
        eligibleBodyScope: GENERATION_PINS.eligibleBodyScope,
        transportPolicy: GENERATION_PINS.transportPolicy,
        retrievedAt: NOW,
        classificationStatus: 'eligible',
      },
    });
    await expect(
      prisma.osvParserAttempt.create({
        data: {
          snapshotId: snapshot.id,
          protocolIdentifier: GENERATION_PINS.parserProtocol,
          schemaRevision: GENERATION_PINS.schemaRevision,
          schemaCommit: SCHEMA_COMMIT,
          resourcePolicy: GENERATION_PINS.parserResourcePolicy,
          registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
          sourceIdentifier: 'github_advisory_database',
          inputSha256: '3'.repeat(64),
          inputByteCount: 24,
          attemptNumber: 1,
          resultState: 'succeeded',
          failureKind: 'timeout',
          retryability: 'orchestration_retryable',
          phase: 'execution',
          terminationRequired: false,
          workerLifecycleOutcome: 'reused',
          correlationId: randomUUID(),
          startedAt: NOW,
          completedAt: NOW,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvParserAttempt.create({
        data: {
          snapshotId: snapshot.id,
          protocolIdentifier: GENERATION_PINS.parserProtocol,
          schemaRevision: GENERATION_PINS.schemaRevision,
          schemaCommit: SCHEMA_COMMIT,
          resourcePolicy: GENERATION_PINS.parserResourcePolicy,
          registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
          sourceIdentifier: 'github_advisory_database',
          inputSha256: '3'.repeat(64),
          inputByteCount: 24,
          attemptNumber: 1,
          resultState: 'failed',
          failureKind: 'timeout',
          retryability: 'orchestration_retryable',
          phase: 'execution',
          terminationRequired: true,
          workerLifecycleOutcome: 'terminated',
          correlationId: randomUUID(),
          startedAt: NOW,
          completedAt: NOW,
        },
      }),
    ).resolves.toMatchObject({ resultState: 'failed', parsedRevisionId: null });
  });

  it('rejects non-blocking quarantine and enforces one pointer per scope', async () => {
    const generation = await prisma.osvCatalogGeneration.create({
      data: { ...GENERATION_PINS, scopeFingerprint: '4'.repeat(64) },
    });
    await expect(
      prisma.osvQuarantineRecord.create({
        data: {
          catalogGenerationId: generation.id,
          reasonCode: 'listing_rejected_key',
          originatingPhase: 'inventory',
          diagnosticCode: 'listing_rejected_key',
          recordedAt: NOW,
          blocksActivation: false,
        },
      }),
    ).rejects.toThrow();
    await prisma.osvQuarantineRecord.create({
      data: {
        catalogGenerationId: generation.id,
        reasonCode: 'listing_rejected_key',
        originatingPhase: 'inventory',
        diagnosticCode: 'listing_rejected_key',
        recordedAt: NOW,
        blocksActivation: true,
      },
    });
    await prisma.osvActiveCatalogPointer.create({
      data: {
        scopeFingerprint: generation.scopeFingerprint,
        generationId: null,
        version: 1,
        updatedAt: NOW,
      },
    });
    await expect(
      prisma.osvActiveCatalogPointer.create({
        data: {
          scopeFingerprint: generation.scopeFingerprint,
          generationId: null,
          version: 2,
          updatedAt: NOW,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.osvActiveCatalogPointer.create({
        data: {
          scopeFingerprint: '5'.repeat(64),
          generationId: null,
          version: 0,
          updatedAt: NOW,
        },
      }),
    ).rejects.toThrow();
  });

  it('restricts deletion of catalog generation evidence', async () => {
    const generation = await prisma.osvCatalogGeneration.create({
      data: { ...GENERATION_PINS, scopeFingerprint: '6'.repeat(64) },
    });
    await prisma.osvAcquisitionRun.create({
      data: {
        catalogGenerationId: generation.id,
        scopeFingerprint: generation.scopeFingerprint,
        state: 'requested',
        attemptNumber: 1,
        correlationId: randomUUID(),
        requestedAt: NOW,
      },
    });
    await expect(
      prisma.osvCatalogGeneration.delete({ where: { id: generation.id } }),
    ).rejects.toThrow();
  });

  it('keeps OSV models free of tenant and Finding columns in Prisma schema', () => {
    const schemaPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../prisma/schema.prisma',
    );
    const schema = readFileSync(schemaPath, 'utf8');
    const start = schema.indexOf('model OsvCatalogGeneration');
    const end = schema.indexOf('\nmodel Integration {');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const osvBlock = schema.slice(start, end);
    expect(osvBlock).toContain('model OsvActiveCatalogPointer');
    expect(osvBlock).not.toContain('organizationId');
    expect(osvBlock).not.toContain('findingId');
    expect(osvBlock).not.toContain('Bytes');
    expect(osvBlock).not.toContain('pageToken');
    expect(osvBlock).not.toContain('@db.Json');
  });

  it('does not seed an active catalog and keeps adapter files Prisma-schema-free', () => {
    const srcDir = path.dirname(fileURLToPath(import.meta.url));
    expect(existsSync(path.join(srcDir, 'osv-acquisition-persistence.ts'))).toBe(true);
    const schemaPath = path.join(srcDir, '../prisma/schema.prisma');
    const schema = readFileSync(schemaPath, 'utf8');
    expect(schema).not.toContain('createOsvAcquisitionPersistence');
  });

  it('records that frozen Batch 5C SQL still contains the unsatisfiable POSIX quantifier', async () => {
    const sql = readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        '../prisma/migrations/20260904120000_osv_acquisition_persistence_foundation/migration.sql',
      ),
      'utf8',
    );
    expect(sql).toContain('osv_parsed_advisory_revision_osv_id_chk');
    expect(sql).toContain('[A-Z0-9._+-]{0,511}');
    await expect(
      prisma.$queryRawUnsafe(`SELECT 'SYNTH0' ~ '^[A-Z0-9][A-Z0-9._+-]{0,511}$'`),
    ).rejects.toThrow(/invalid regular expression|2201B|repetition count/i);
    const live = await prisma.$queryRaw<Array<{ definition: string }>>`
      SELECT pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      WHERE conname = 'osv_parsed_advisory_revision_osv_id_chk'
    `;
    expect(live[0]?.definition).toContain('char_length');
    expect(live[0]?.definition).not.toContain('{0,511}');
  });
});
