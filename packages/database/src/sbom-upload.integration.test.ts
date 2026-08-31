import { createHash, randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createUploadSbomUseCase,
  hashIdempotencyKey,
  wrapRawIdempotencyKey,
  type ObjectByteStream,
  type SbomObjectStoragePort,
  type SbomUploadActor,
  type StorageFailureCategory,
} from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createSbomPersistence } from './sbom-persistence.js';
import { createSbomUploadUnitOfWork } from './sbom-upload-unit-of-work.js';
import { createRepositories } from './repositories.js';

const BODY = Buffer.from('{"bomFormat":"CycloneDX","specVersion":"1.6"}');
const SHA = createHash('sha256').update(BODY).digest('hex');
const PARSER_VERSION = '0.1.0';
const NORMALIZATION_VERSION = '1';

describe('session 8 sbom upload workflow persistence', () => {
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

  it('commits new evidence atomically and keeps the raw key and body out of PostgreSQL', async () => {
    const fixture = await seedTenant(prisma, 'new');
    const storage = memoryStorage();
    const upload = workflow(prisma, storage);
    const rawKey = `raw-secret-${randomUUID()}`;
    const result = await upload.execute(
      input(fixture, {
        idempotencyKey: wrapRawIdempotencyKey(rawKey),
        body: streamOf(BODY),
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value).not.toHaveProperty('objectKey');
    const sbom = await prisma.sbom.findFirst({ where: { id: result.value.sbomId } });
    const ingestion = await prisma.sbomIngestion.findFirst({
      where: { id: result.value.ingestionId },
    });
    const audit = await prisma.auditEvent.findFirst({
      where: { organizationId: fixture.organizationId, action: 'sbom.uploaded' },
    });
    const outbox = await prisma.outboxEvent.findFirst({
      where: { organizationId: fixture.organizationId, eventType: 'sbom.ingestion.requested.v1' },
    });
    const idempotency = await prisma.idempotencyRecord.findFirst({
      where: { organizationId: fixture.organizationId },
    });
    expect(sbom?.sha256).toBe(SHA);
    expect(sbom?.originalFilename).toBeNull();
    expect(ingestion?.state).toBe('accepted');
    expect(ingestion?.idempotencyKey).toBeNull();
    expect(JSON.stringify(sbom)).not.toContain(BODY.toString('utf8'));
    expect(JSON.stringify(idempotency)).not.toContain(rawKey);
    expect(JSON.stringify(audit?.payload)).not.toMatch(/objectKey|filename|bucket/);
    expect(JSON.stringify(outbox?.payload)).not.toMatch(/objectKey|filename/);
    expect(outbox?.status).toBe('pending');
  });

  it('rolls back the finalization transaction when audit append fails', async () => {
    const fixture = await seedTenant(prisma, 'audit-fail');
    const storage = memoryStorage();
    const unitOfWork = createSbomUploadUnitOfWork(prisma);
    const wrapped: typeof unitOfWork = {
      async runInTransaction(work) {
        return unitOfWork.runInTransaction(async (repos) => {
          const failingAudit = {
            ...repos.auditEvents,
            async append() {
              throw new Error('audit append failed');
            },
          };
          return work({ ...repos, auditEvents: failingAudit });
        });
      },
    };
    const persistence = createSbomPersistence(prisma);
    const repos = createRepositories(prisma);
    const upload = createUploadSbomUseCase({
      clock: { now: () => new Date('2026-08-31T12:00:00.000Z') },
      createId: () => randomUUID(),
      assets: repos.assets,
      uploadIdempotency: persistence.uploadIdempotency,
      sbomMetadata: persistence.sbomMetadata,
      ingestions: persistence.ingestions,
      storage,
      unitOfWork: wrapped,
    });
    const result = await upload.execute(input(fixture, { body: streamOf(BODY) }));
    expect(result.ok).toBe(false);
    expect(await prisma.sbom.count({ where: { organizationId: fixture.organizationId } })).toBe(0);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: fixture.organizationId, action: 'sbom.uploaded' },
      }),
    ).toBe(0);
    expect(
      await prisma.outboxEvent.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(0);
  });

  it('reuses duplicate evidence under the unique organization/asset/sha256 constraint', async () => {
    const fixture = await seedTenant(prisma, 'dup');
    const storage = memoryStorage();
    const upload = workflow(prisma, storage);
    const first = await upload.execute(
      input(fixture, { idempotencyKey: hashIdempotencyKey('one'), body: streamOf(BODY) }),
    );
    const second = await upload.execute(
      input(fixture, {
        idempotencyKey: hashIdempotencyKey('two'),
        correlationId: randomUUID(),
        body: streamOf(BODY),
      }),
    );
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) {
      return;
    }
    expect(second.value.sbomId).toBe(first.value.sbomId);
    expect(second.value.ingestionId).toBe(first.value.ingestionId);
    expect(await prisma.sbom.count({ where: { organizationId: fixture.organizationId } })).toBe(1);
    expect(
      await prisma.sbomIngestion.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(1);
    expect(
      await prisma.outboxEvent.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: fixture.organizationId, action: 'sbom.duplicate' },
      }),
    ).toBe(1);
  });

  it('allows one concurrent reservation winner for the same hashed key', async () => {
    const fixture = await seedTenant(prisma, 'race');
    const storage = memoryStorage();
    const persistence = createSbomPersistence(prisma);
    const keyHash = hashIdempotencyKey('shared').keyHash;
    const reservationFingerprint = 'a'.repeat(64);
    const expiresAt = new Date(Date.now() + 60_000);
    const args = {
      organizationId: fixture.organizationId,
      scope: `sbom.upload:${fixture.assetId}`,
      keyHash,
      reservationFingerprint,
      expiresAt,
    };
    const results = await Promise.all([
      persistence.uploadIdempotency.reserveStarted(args),
      persistence.uploadIdempotency.reserveStarted(args),
    ]);
    expect(results.filter((result) => result.kind === 'acquired')).toHaveLength(1);
    expect(results.filter((result) => result.kind === 'unexpired_started')).toHaveLength(1);
    void storage;
  });

  it('rolls back the finalization transaction when outbox create fails', async () => {
    const fixture = await seedTenant(prisma, 'outbox-fail');
    const storage = memoryStorage();
    const unitOfWork = createSbomUploadUnitOfWork(prisma);
    const wrapped: typeof unitOfWork = {
      async runInTransaction(work) {
        return unitOfWork.runInTransaction(async (repos) => {
          const failingOutbox = {
            ...repos.outboxEvents,
            async create() {
              throw new Error('outbox create failed');
            },
          };
          return work({ ...repos, outboxEvents: failingOutbox });
        });
      },
    };
    const persistence = createSbomPersistence(prisma);
    const repos = createRepositories(prisma);
    const upload = createUploadSbomUseCase({
      clock: { now: () => new Date('2026-08-31T12:00:00.000Z') },
      createId: () => randomUUID(),
      assets: repos.assets,
      uploadIdempotency: persistence.uploadIdempotency,
      sbomMetadata: persistence.sbomMetadata,
      ingestions: persistence.ingestions,
      storage,
      unitOfWork: wrapped,
    });
    const result = await upload.execute(input(fixture, { body: streamOf(BODY) }));
    expect(result.ok).toBe(false);
    expect(await prisma.sbom.count({ where: { organizationId: fixture.organizationId } })).toBe(0);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: fixture.organizationId, action: 'sbom.uploaded' },
      }),
    ).toBe(0);
    expect(
      await prisma.outboxEvent.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(0);
  });

  it('handles a unique evidence insert race without a second outbox', async () => {
    const fixture = await seedTenant(prisma, 'insert-race');
    const storage = memoryStorage();
    const upload = workflow(prisma, storage);
    const [first, second] = await Promise.all([
      upload.execute(
        input(fixture, { idempotencyKey: hashIdempotencyKey('race-a'), body: streamOf(BODY) }),
      ),
      upload.execute(
        input(fixture, {
          idempotencyKey: hashIdempotencyKey('race-b'),
          correlationId: randomUUID(),
          body: streamOf(BODY),
        }),
      ),
    ]);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(await prisma.sbom.count({ where: { organizationId: fixture.organizationId } })).toBe(1);
    expect(
      await prisma.sbomIngestion.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(1);
    expect(
      await prisma.outboxEvent.count({ where: { organizationId: fixture.organizationId } }),
    ).toBe(1);
    const actions = (
      await prisma.auditEvent.findMany({
        where: { organizationId: fixture.organizationId },
        select: { action: true },
      })
    ).map((event) => event.action);
    expect(actions.sort()).toEqual(['sbom.duplicate', 'sbom.uploaded']);
  });
});

function workflow(prisma: PrismaClient, storage: SbomObjectStoragePort) {
  const persistence = createSbomPersistence(prisma);
  const repos = createRepositories(prisma);
  return createUploadSbomUseCase({
    clock: { now: () => new Date('2026-08-31T12:00:00.000Z') },
    createId: () => randomUUID(),
    assets: repos.assets,
    uploadIdempotency: persistence.uploadIdempotency,
    sbomMetadata: persistence.sbomMetadata,
    ingestions: persistence.ingestions,
    storage,
    unitOfWork: createSbomUploadUnitOfWork(prisma),
  });
}

function input(
  fixture: Awaited<ReturnType<typeof seedTenant>>,
  overrides: {
    idempotencyKey?:
      ReturnType<typeof hashIdempotencyKey> | ReturnType<typeof wrapRawIdempotencyKey>;
    body: ObjectByteStream;
    correlationId?: string;
  },
) {
  const actor: SbomUploadActor = {
    userId: fixture.userId,
    sessionId: randomUUID(),
    organizationId: fixture.organizationId,
    membershipId: fixture.membershipId,
    permissions: ['sbom:upload'],
  };
  return {
    actor,
    assetId: fixture.assetId,
    idempotencyKey: overrides.idempotencyKey ?? hashIdempotencyKey(randomUUID()),
    contentType: 'application/json' as const,
    body: overrides.body,
    maxBytes: 1024,
    parserVersion: PARSER_VERSION,
    normalizationVersion: NORMALIZATION_VERSION,
    idempotencyTtlMs: 86_400_000,
    correlationId: overrides.correlationId ?? randomUUID(),
    requestId: randomUUID(),
  };
}

function streamOf(body: Buffer): ObjectByteStream {
  return (async function* () {
    yield new Uint8Array(body);
  })();
}

function memoryStorage(): SbomObjectStoragePort & { failPut?: StorageFailureCategory } {
  const objects = new Map<string, Uint8Array>();
  return {
    async verifyBucketAvailability() {
      return {
        ok: true,
        value: { bucketPrivate: true, publicAccessDisabled: true, signedUrlsDisabled: true },
      };
    },
    async initializeDevelopmentBucket() {
      return { ok: true, value: undefined };
    },
    async putTemporaryObject(input) {
      const chunks: Uint8Array[] = [];
      for await (const chunk of input.body) {
        chunks.push(chunk);
      }
      const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      objects.set(input.temporaryObjectKey, bytes);
      return {
        ok: true,
        value: {
          sha256: createHash('sha256').update(bytes).digest('hex'),
          observedByteLength: bytes.byteLength,
        },
      };
    },
    async promoteTemporaryObject(input) {
      const bytes = objects.get(input.temporaryObjectKey);
      if (bytes === undefined) {
        return { ok: false, error: { category: 'object_missing' } };
      }
      objects.set(input.finalObjectKey, bytes);
      return { ok: true, value: undefined };
    },
    async headFinalObject() {
      return { ok: true, value: { exists: false } };
    },
    async deleteTemporaryObject(input) {
      objects.delete(input.temporaryObjectKey);
      return { ok: true, value: undefined };
    },
    async getObject() {
      return { ok: false, error: { category: 'internal' } };
    },
  };
}

async function seedTenant(prisma: PrismaClient, label: string) {
  const organization = await prisma.organization.create({
    data: { slug: `${label}-${randomUUID().slice(0, 8)}`, name: `Org ${label}` },
  });
  const user = await prisma.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: organization.id, userId: user.id, role: 'member' },
  });
  const asset = await prisma.asset.create({
    data: { organizationId: organization.id, name: `Asset ${label}`, assetType: 'application' },
  });
  return {
    organizationId: organization.id,
    userId: user.id,
    membershipId: membership.id,
    assetId: asset.id,
  };
}
