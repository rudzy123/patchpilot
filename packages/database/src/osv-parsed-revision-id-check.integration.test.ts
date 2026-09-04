import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Prisma, PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SCHEMA_COMMIT = 'f3f826310aeca8e324baabd195632f2229952abe';
const NOW = new Date('2026-09-04T18:00:00.000Z');
const DOCUMENT_IDENTIFIER = 'osv_parsed_advisory_document_v1';
const CYRILLIC_A = '\u0410';

const GENERATION_PINS = {
  providerIdentifier: 'osv',
  eligibleBodyScope: 'osv_eligible_body_scope_registry_v1',
  sourceLicenseRegistry: 'osv_source_license_registry_v1',
  transportPolicy: 'osv_transport_policy_v1',
  parserProtocol: 'osv_advisory_parser_protocol_v1',
  parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
  schemaRevision: 'v1.9.0',
  schemaCommit: SCHEMA_COMMIT,
} as const;

describe('session 11 OSV parsed-revision ID CHECK correction', { timeout: 90_000 }, () => {
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
    await prisma.$disconnect();
    await dropEphemeralDatabase(admin, databaseName);
  });

  it('keeps the frozen Batch 5C SQL defective while replacing the live CHECK', async () => {
    const frozenSql = readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        '../prisma/migrations/20260904120000_osv_acquisition_persistence_foundation/migration.sql',
      ),
      'utf8',
    );
    expect(frozenSql).toContain('osv_parsed_advisory_revision_osv_id_chk');
    expect(frozenSql).toContain('[A-Z0-9._+-]{0,511}');
    const definition = await prisma.$queryRaw<Array<{ definition: string }>>`
      SELECT pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      WHERE conname = 'osv_parsed_advisory_revision_osv_id_chk'
    `;
    expect(definition[0]?.definition).toContain('char_length');
    expect(definition[0]?.definition).toContain('^[A-Z0-9][A-Z0-9._+-]*$');
    expect(definition[0]?.definition).not.toContain('{0,511}');
  });

  it('accepts the committed identifier grammar and rejects malformed identifiers', async () => {
    const accepted = ['A', 'SYNTH0', '0SYNTH', 'SYNTH.A_B+C-D', `A${'0'.repeat(511)}`];
    await prisma.$transaction(async (tx) => {
      await createParsedOsvIdCheckTable(tx);
      for (const identifier of accepted) {
        await tx.$executeRaw`INSERT INTO parsed_osv_id_check_only VALUES (${identifier})`;
      }
    });
    const rejected = [
      '',
      `A${'0'.repeat(512)}`,
      'synth0',
      '-SYNTH0',
      '.SYNTH0',
      '_SYNTH0',
      '+SYNTH0',
      'SYNTH 0',
      'SYNTH\t0',
      'SYNTH\n0',
      'SYNTH\u00010',
      `${CYRILLIC_A}SYNTH0`,
      'SYNTH/0',
      'SYNTH\\0',
      'SYNTH:0',
      'SYNTH%0',
      'SYNTH@0',
    ];
    for (const identifier of rejected) {
      await expect(
        prisma.$transaction(async (tx) => {
          await createParsedOsvIdCheckTable(tx);
          await tx.$executeRaw`INSERT INTO parsed_osv_id_check_only VALUES (${identifier})`;
        }),
      ).rejects.toThrow();
    }
  });

  it('inserts a valid parsed revision and keeps failed attempts from referencing it', async () => {
    const fixture = await seedRevisionGraph(prisma, 'npm/SYNTH-rev-0000-0000.json');
    const revision = await prisma.osvParsedAdvisoryRevision.create({
      data: revisionData(fixture, 'SYNTH0'),
    });
    expect(revision.parsedTopLevelOsvId).toBe('SYNTH0');
    const linked = await prisma.osvParserAttempt.update({
      where: { id: fixture.successAttemptId },
      data: { parsedRevisionId: revision.id },
    });
    expect(linked.parsedRevisionId).toBe(revision.id);
    await expect(
      prisma.$executeRaw`UPDATE "osv_parsed_advisory_revision"
        SET "parsed_top_level_osv_id" = ${'synth0'}
        WHERE id = ${revision.id}::uuid`,
    ).rejects.toThrow();
    const unchanged = await prisma.osvParsedAdvisoryRevision.findUniqueOrThrow({
      where: { id: revision.id },
    });
    expect(unchanged.parsedTopLevelOsvId).toBe('SYNTH0');

    await expect(
      prisma.osvParsedAdvisoryRevision.create({
        data: revisionData(
          { ...fixture, documentAttachmentId: fixture.duplicateDocumentAttachmentId },
          'SYNTH0',
        ),
      }),
    ).rejects.toThrow();

    await expect(
      prisma.osvParserAttempt.create({
        data: {
          snapshotId: fixture.snapshotId,
          protocolIdentifier: GENERATION_PINS.parserProtocol,
          schemaRevision: GENERATION_PINS.schemaRevision,
          schemaCommit: SCHEMA_COMMIT,
          resourcePolicy: GENERATION_PINS.parserResourcePolicy,
          registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
          sourceIdentifier: 'github_advisory_database',
          inputSha256: SHA_A,
          inputByteCount: 24,
          attemptNumber: 2,
          resultState: 'failed',
          failureKind: 'timeout',
          retryability: 'orchestration_retryable',
          phase: 'execution',
          terminationRequired: true,
          workerLifecycleOutcome: 'terminated',
          parsedRevisionId: revision.id,
          correlationId: randomUUID(),
          startedAt: NOW,
          completedAt: NOW,
        },
      }),
    ).rejects.toThrow();
  });
});

async function createParsedOsvIdCheckTable(tx: Prisma.TransactionClient): Promise<void> {
  await tx.$executeRawUnsafe(`
    CREATE TEMP TABLE parsed_osv_id_check_only (
      parsed_top_level_osv_id TEXT NOT NULL,
      CONSTRAINT osv_parsed_advisory_revision_osv_id_chk CHECK (
        char_length(parsed_top_level_osv_id) BETWEEN 1 AND 512
        AND parsed_top_level_osv_id ~ '^[A-Z0-9][A-Z0-9._+-]*$'
      )
    )
  `);
}

async function seedRevisionGraph(
  prisma: PrismaClient,
  providerObjectKey: string,
): Promise<{
  snapshotId: string;
  successAttemptId: string;
  providerGenerationId: string;
  documentAttachmentId: string;
  duplicateDocumentAttachmentId: string;
}> {
  const object = await prisma.osvProviderObject.create({
    data: {
      providerIdentifier: 'osv',
      providerObjectKey,
      providerObjectKeyDigest: SHA_A,
      providerPrefix: 'npm/',
      familyKind: 'known',
      familyValue: 'SYNTH',
    },
  });
  const generation = await prisma.osvProviderGeneration.create({
    data: {
      providerObjectId: object.id,
      providerObjectKeyDigest: object.providerObjectKeyDigest,
      providerGeneration: '1',
    },
  });
  const bodyAttachment = await prisma.osvObjectAttachment.create({
    data: {
      storageKind: 'advisory_body',
      role: 'final',
      objectKey: `intelligence/osv/advisory_body/sha256/${SHA_A}`,
      locatorContentSha256: SHA_A,
      contentSha256: SHA_A,
      byteCount: 24,
      contentType: 'application/json',
      contentEncoding: 'identity',
      state: 'attached',
      cleanupEligible: false,
    },
  });
  const documentAttachment = await prisma.osvObjectAttachment.create({
    data: {
      storageKind: 'parsed_advisory',
      role: 'final',
      objectKey: `intelligence/osv/parsed_advisory/sha256/${SHA_B}`,
      locatorContentSha256: SHA_B,
      contentSha256: SHA_B,
      byteCount: 32,
      contentType: 'application/json',
      contentEncoding: 'identity',
      state: 'attached',
      cleanupEligible: false,
    },
  });
  const duplicateDocument = await prisma.osvObjectAttachment.create({
    data: {
      storageKind: 'parsed_advisory',
      role: 'final',
      objectKey: `intelligence/osv/parsed_advisory/sha256/${'c'.repeat(64)}`,
      locatorContentSha256: 'c'.repeat(64),
      contentSha256: 'c'.repeat(64),
      byteCount: 32,
      contentType: 'application/json',
      contentEncoding: 'identity',
      state: 'attached',
      cleanupEligible: false,
    },
  });
  const snapshot = await prisma.osvProviderBodySnapshot.create({
    data: {
      providerGenerationId: generation.id,
      attachmentId: bodyAttachment.id,
      contentSha256: SHA_A,
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
  const successAttempt = await prisma.osvParserAttempt.create({
    data: {
      snapshotId: snapshot.id,
      protocolIdentifier: GENERATION_PINS.parserProtocol,
      schemaRevision: GENERATION_PINS.schemaRevision,
      schemaCommit: SCHEMA_COMMIT,
      resourcePolicy: GENERATION_PINS.parserResourcePolicy,
      registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
      sourceIdentifier: 'github_advisory_database',
      inputSha256: SHA_A,
      inputByteCount: 24,
      attemptNumber: 1,
      resultState: 'succeeded',
      failureKind: null,
      retryability: null,
      phase: null,
      terminationRequired: false,
      workerLifecycleOutcome: 'reused',
      parsedRevisionId: null,
      correlationId: randomUUID(),
      startedAt: NOW,
      completedAt: NOW,
    },
  });
  return {
    snapshotId: snapshot.id,
    successAttemptId: successAttempt.id,
    providerGenerationId: generation.id,
    documentAttachmentId: documentAttachment.id,
    duplicateDocumentAttachmentId: duplicateDocument.id,
  };
}

function revisionData(
  fixture: {
    snapshotId: string;
    successAttemptId: string;
    providerGenerationId: string;
    documentAttachmentId: string;
  },
  parsedTopLevelOsvId: string,
): {
  snapshotId: string;
  parserAttemptId: string;
  providerGenerationId: string;
  documentAttachmentId: string;
  documentIdentifier: string;
  protocolIdentifier: string;
  schemaRevision: string;
  schemaCommit: string;
  resourcePolicy: string;
  registryIdentifier: string;
  sourceIdentifier: 'github_advisory_database';
  contentSha256: string;
  parsedOutputSha256: string;
  parsedTopLevelOsvId: string;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  withdrawnAt: Date | null;
  withdrawn: boolean;
  aliasCount: number;
  relatedCount: number;
  affectedPackageCount: number;
  rangeCount: number;
  eventCount: number;
  explicitVersionCount: number;
  referenceCount: number;
  creditCount: number;
  severityCount: number;
  normalizationState: string;
} {
  return {
    snapshotId: fixture.snapshotId,
    parserAttemptId: fixture.successAttemptId,
    providerGenerationId: fixture.providerGenerationId,
    documentAttachmentId: fixture.documentAttachmentId,
    documentIdentifier: DOCUMENT_IDENTIFIER,
    protocolIdentifier: GENERATION_PINS.parserProtocol,
    schemaRevision: GENERATION_PINS.schemaRevision,
    schemaCommit: SCHEMA_COMMIT,
    resourcePolicy: GENERATION_PINS.parserResourcePolicy,
    registryIdentifier: GENERATION_PINS.sourceLicenseRegistry,
    sourceIdentifier: 'github_advisory_database',
    contentSha256: SHA_B,
    parsedOutputSha256: SHA_B,
    parsedTopLevelOsvId,
    publishedAt: null,
    modifiedAt: null,
    withdrawnAt: null,
    withdrawn: false,
    aliasCount: 0,
    relatedCount: 0,
    affectedPackageCount: 0,
    rangeCount: 0,
    eventCount: 0,
    explicitVersionCount: 0,
    referenceCount: 0,
    creditCount: 0,
    severityCount: 0,
    normalizationState: 'uninterpreted_structural',
  };
}
