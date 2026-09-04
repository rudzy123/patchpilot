import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
  OSV_PROVIDER_IDENTIFIER,
  OSV_SNAPSHOT_CONTENT_ENCODING,
  OSV_SNAPSHOT_CONTENT_TYPE,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  OSV_TRANSPORT_POLICY_VERSION,
  createOsvFinalObjectLocator,
  createOsvObjectAttachment,
  createOsvProviderBodySnapshot,
  createOsvProviderGenerationIdentity,
  createOsvProviderObjectIdentity,
  createOsvTemporaryObjectLocator,
  type OsvIdempotencyResult,
  type OsvPersistenceResult,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvAcquisitionPersistence } from './osv-acquisition-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const TS = '2026-09-04T18:00:00.000Z';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

type Adapters = ReturnType<typeof createOsvAcquisitionPersistence>;

function requireValue<T>(result: OsvPersistenceResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function requireIdem(result: OsvPersistenceResult<OsvIdempotencyResult>, label: string) {
  return requireValue(result, label);
}

describe('Session 11 Batch 5E PostgreSQL attachment coordination', () => {
  let prisma: PrismaClient;
  let adapters: Adapters;
  let admin: PrismaClient | undefined;
  let databaseName: string | undefined;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    adapters = createOsvAcquisitionPersistence(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function reservedGeneration(keySuffix: string) {
    const identity = requireValue(
      createOsvProviderObjectIdentity({
        providerIdentifier: OSV_PROVIDER_IDENTIFIER,
        providerObjectKey: `npm/GHSA-aaae-${keySuffix
          .replace(/[^a-z]/g, '')
          .padEnd(4, 'a')
          .slice(0, 4)}-cccc.json`,
      }),
      'object',
    );
    requireIdem(await adapters.providerObjects.insertOnce(identity), 'insert object');
    const stored = await prisma.osvProviderObject.findUniqueOrThrow({
      where: {
        providerIdentifier_providerObjectKeyDigest: {
          providerIdentifier: OSV_PROVIDER_IDENTIFIER,
          providerObjectKeyDigest: identity.providerObjectKeyDigest,
        },
      },
    });
    const generation = requireValue(
      createOsvProviderGenerationIdentity({
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '7',
      }),
      'generation',
    );
    requireIdem(await adapters.bodySnapshots.reserveImmutableGeneration(generation), 'reserve');
    return { stored, generation };
  }

  it('reserves staged metadata, inspects it, and finalizes attached without body bytes', async () => {
    const { stored, generation } = await reservedGeneration('stage-final');
    const uploadId = randomUUID();
    const stagedLocator = requireValue(
      createOsvTemporaryObjectLocator({ storageKind: 'advisory_body', uploadId }),
      'tmp locator',
    );
    const stagedAttachment = requireValue(
      createOsvObjectAttachment({
        id: uploadId,
        locator: stagedLocator,
        contentSha256: SHA_A,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'staged',
      }),
      'staged attachment',
    );
    const snapshotId = randomUUID();
    const staged = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: stored.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_A,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: stagedAttachment,
        classificationStatus: 'eligible',
      }),
      'staged snapshot',
    );
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(staged), 'stage').status,
    ).toBe('created');
    const inspected = requireValue(await adapters.attachments.inspect(uploadId), 'inspect');
    expect(inspected?.state).toBe('staged');
    const loadedStaged = requireValue(
      await adapters.bodySnapshots.loadByGeneration(generation),
      'load staged',
    );
    expect(loadedStaged?.attachment.state).toBe('staged');
    const finalLocator = requireValue(
      createOsvFinalObjectLocator({ storageKind: 'advisory_body', contentSha256: SHA_A }),
      'final locator',
    );
    const attached = requireValue(
      createOsvObjectAttachment({
        id: uploadId,
        locator: finalLocator,
        contentSha256: SHA_A,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'attached',
    );
    const finalized = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: stored.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_A,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: attached,
        classificationStatus: 'eligible',
      }),
      'final snapshot',
    );
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(finalized), 'attach').status,
    ).toBe('created');
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(finalized), 'repeat').status,
    ).toBe('already_applied');
    const conflictLocator = requireValue(
      createOsvFinalObjectLocator({ storageKind: 'advisory_body', contentSha256: SHA_B }),
      'conflict locator',
    );
    const conflictAttachment = requireValue(
      createOsvObjectAttachment({
        id: uploadId,
        locator: conflictLocator,
        contentSha256: SHA_B,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'conflict attached',
    );
    const conflicting = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: stored.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_B,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: conflictAttachment,
        classificationStatus: 'eligible',
      }),
      'conflict snapshot',
    );
    const conflict = await adapters.bodySnapshots.attachImmutableSnapshot(conflicting);
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
    const loaded = requireValue(await adapters.bodySnapshots.loadByGeneration(generation), 'load');
    expect(loaded?.attachment.state).toBe('attached');
    expect(loaded?.contentSha256).toBe(SHA_A);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
  });

  it('marks staged attachments orphaned or rejected and refuses attached mutation', async () => {
    const { stored } = await reservedGeneration('orphan');
    const uploadId = randomUUID();
    const stagedLocator = requireValue(
      createOsvTemporaryObjectLocator({ storageKind: 'advisory_body', uploadId }),
      'tmp locator',
    );
    const stagedAttachment = requireValue(
      createOsvObjectAttachment({
        id: uploadId,
        locator: stagedLocator,
        contentSha256: SHA_A,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'staged',
      }),
      'staged attachment',
    );
    const staged = requireValue(
      createOsvProviderBodySnapshot({
        id: randomUUID(),
        providerObjectId: stored.id,
        providerObjectKeyDigest: stored.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_A,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: stagedAttachment,
        classificationStatus: 'eligible',
      }),
      'staged snapshot',
    );
    requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(staged), 'stage');
    expect(requireIdem(await adapters.attachments.markOrphaned(uploadId), 'orphan').status).toBe(
      'created',
    );
    expect(
      requireIdem(await adapters.attachments.markOrphaned(uploadId), 'orphan repeat').status,
    ).toBe('already_applied');
    const attachedMutation = await adapters.attachments.markRejected(uploadId);
    expect(attachedMutation.ok).toBe(false);

    const rejectedId = randomUUID();
    const { stored: storedRejected } = await reservedGeneration('reject');
    const rejectedLocator = requireValue(
      createOsvTemporaryObjectLocator({ storageKind: 'advisory_body', uploadId: rejectedId }),
      'reject locator',
    );
    const rejectedAttachment = requireValue(
      createOsvObjectAttachment({
        id: rejectedId,
        locator: rejectedLocator,
        contentSha256: SHA_B,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'staged',
      }),
      'rejected attachment',
    );
    const rejectedSnapshot = requireValue(
      createOsvProviderBodySnapshot({
        id: randomUUID(),
        providerObjectId: storedRejected.id,
        providerObjectKeyDigest: storedRejected.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_B,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: rejectedAttachment,
        classificationStatus: 'eligible',
      }),
      'rejected snapshot',
    );
    requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(rejectedSnapshot), 'stage 2');
    expect(requireIdem(await adapters.attachments.markRejected(rejectedId), 'reject').status).toBe(
      'created',
    );
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.findingObservation.count()).toBe(0);
    expect(await prisma.evidence.count()).toBe(0);
    expect(await prisma.riskCalculation.count()).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
  });
});
