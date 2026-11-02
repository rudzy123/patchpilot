/**
 * Disposable PostgreSQL proof for one offline npm GHSA file transaction.
 * Synthetic documents only. No real GHSA body is stored.
 */

import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
  EXACT_MAPPING_METHOD,
  OFFLINE_NPM_ADVISORY_FILE_PERSISTENCE_COMMAND_SCHEMA_VERSION,
  OFFLINE_NPM_OSV_NORMALIZATION_IDENTITY,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  VULNERABILITY_MAPPING_POLICY_ID,
  normalizeOfflineNpmGhsaBytes,
  parseAdvisoryRevisionCommand,
  type OfflineNpmGhsaNormalization,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createAdvisoryRevisionPersistence } from './advisory-revision-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const RETRIEVED_AT = '2026-11-02T18:00:00.000Z';

type AcceptedNormalization = Extract<OfflineNpmGhsaNormalization, { accepted: true }>;

function bytesOf(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function affectedPackage(
  name: string,
  extras: Record<string, unknown> = {},
  packageExtras: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    package: { ecosystem: 'npm', name, ...packageExtras },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }],
    ...extras,
  };
}

function document(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    modified: '2026-01-01T00:00:00Z',
    published: '2025-12-01T00:00:00Z',
    affected: [affectedPackage('left-pad')],
    ...overrides,
  };
}

function acceptDocument(value: Record<string, unknown>): {
  readonly bytes: Uint8Array;
  readonly normalized: AcceptedNormalization;
} {
  const bytes = bytesOf(value);
  const normalized = normalizeOfflineNpmGhsaBytes(bytes);
  if (!normalized.accepted) {
    throw new Error(normalized.reason);
  }
  return { bytes, normalized };
}

function fileCommand(input: {
  readonly batchId: string;
  readonly correlationId: string;
  readonly bytes: Uint8Array;
  readonly normalized: AcceptedNormalization;
  readonly revisions?: readonly {
    readonly command: unknown;
    readonly purl: string | null;
  }[];
}): Record<string, unknown> {
  const revisions =
    input.revisions ??
    input.normalized.revisions.map((revision) => ({
      command: revision.persistenceCommand,
      purl: revision.purl,
    }));
  return {
    commandSchemaVersion: OFFLINE_NPM_ADVISORY_FILE_PERSISTENCE_COMMAND_SCHEMA_VERSION,
    batchId: input.batchId,
    correlationId: input.correlationId,
    byteLength: input.bytes.byteLength,
    revisions,
  };
}

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

describe('offline npm advisory file persistence', () => {
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let port: ReturnType<typeof createAdvisoryRevisionPersistence>;
  let batchId = '';

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'osvfile' });
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    port = createAdvisoryRevisionPersistence(prisma);
    const batch = await prisma.offlineAdvisoryImportBatch.create({
      data: {
        manifestSha256: digest('offline-file-batch'),
        sourceLicenseRegistryVersion: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        retrievedAt: new Date(RETRIEVED_AT),
      },
      select: { id: true },
    });
    batchId = batch.id;
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    if (databaseName !== '') {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('stores ranges, explicit versions, provenance, and one file audit', async () => {
    const value = document('GHSA-SYN0-FILE-0001', {
      aliases: ['CVE-2099-4001'],
      affected: [
        affectedPackage(
          'left-pad',
          {
            ranges: [
              { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] },
              { type: 'SEMVER', events: [{ introduced: '0.1.0' }] },
            ],
            versions: ['1.2.3', '1.0.0'],
          },
          { purl: 'pkg:npm/left-pad@1.2.3' },
        ),
      ],
    });
    const accepted = acceptDocument(value);
    const correlationId = randomUUID();
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    expect(recorded.auditEventAdded).toBe(true);
    expect(recorded.projections).toHaveLength(1);
    const projection = recorded.projections[0];
    if (projection === undefined) {
      throw new Error('expected one projection');
    }
    expect(projection.retrievalClassification).toBe('local_not_retrieved');
    expect(projection.productEligibilityStored).toBe(false);
    expect(projection.catalogActivationStored).toBe(false);
    expect(projection.aliasCount).toBe(1);
    const revision = accepted.normalized.revisions[0];
    if (revision === undefined) {
      throw new Error('expected one normalized revision');
    }
    const events = await prisma.advisoryRevisionRangeEvent.findMany({
      where: { advisoryRevisionId: projection.revisionId },
      orderBy: [{ rangeOrdinal: 'asc' }, { eventOrdinal: 'asc' }],
    });
    expect(
      events.map((event) => ({
        rangeOrdinal: event.rangeOrdinal,
        eventOrdinal: event.eventOrdinal,
        name: event.eventName,
        value: event.eventValue,
      })),
    ).toEqual(
      revision.command.rangeRows.flatMap((range) =>
        range.events.map((event) => ({
          rangeOrdinal: range.rangeOrdinal,
          eventOrdinal: event.eventOrdinal,
          name: event.name,
          value: event.value,
        })),
      ),
    );
    const versions = await prisma.advisoryRevisionExplicitVersion.findMany({
      where: { advisoryRevisionId: projection.revisionId },
      orderBy: { ordinal: 'asc' },
    });
    expect(versions.map((version) => version.versionText)).toEqual(['1.0.0', '1.2.3']);
    const provenance = await prisma.advisoryRevisionSourceProvenance.findUniqueOrThrow({
      where: { advisoryRevisionId: projection.revisionId },
    });
    expect(provenance.retrievedAt.toISOString()).toBe(RETRIEVED_AT);
    expect(provenance.modifiedAt.toISOString()).toBe(accepted.normalized.modifiedAt);
    expect(provenance.publishedAt?.toISOString()).toBe(accepted.normalized.publishedAt);
    expect(provenance.withdrawnAt).toBeNull();
    expect(provenance.rawContentSha256).toBe(accepted.normalized.rawContentSha256);
    expect(provenance.purl).toBe('pkg:npm/left-pad@1.2.3');
    expect(provenance.licenseAdmissionReason).toBe('approved_source_license');
    expect(provenance.normalizationIdentity).toBe(OFFLINE_NPM_OSV_NORMALIZATION_IDENTITY);
    expect(provenance.offlineAdvisoryImportBatchId).toBe(batchId);
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        action: 'intelligence.offline_npm_osv_file_imported',
        subjectId: projection.familyId,
      },
    });
    expect(audit.actorType).toBe('system');
    expect(audit.organizationId).toBeNull();
    expect(audit.actorUserId).toBeNull();
    expect(audit.actorMembershipId).toBeNull();
    expect(audit.correlationId).toBe(correlationId);
    expect(audit.schemaVersion).toBe(1);
    expect(audit.payload).toEqual({
      schemaVersion: 1,
      registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
      rawContentSha256: accepted.normalized.rawContentSha256,
      byteLength: accepted.bytes.byteLength,
      advisoryIds: ['GHSA-SYN0-FILE-0001'],
      reasonCodes: ['recorded'],
      counts: { accepted: 1, skipped: 0, rejected: 0, failed: 0 },
    });
    expect(JSON.stringify(audit.payload)).not.toContain('left-pad');
    expect(JSON.stringify(audit.payload)).not.toContain('pkg:');
    const inspected = await port.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionId: projection.revisionId,
    });
    expect(inspected.kind).toBe('found');
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(0);
    expect(await prisma.outboxEvent.count()).toBe(0);
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(0);

    const replay = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(replay.kind).toBe('already_applied');
    if (replay.kind === 'already_applied') {
      expect(replay.auditEventAdded).toBe(false);
      expect(replay.projections[0]?.revisionId).toBe(projection.revisionId);
    }
    expect(
      await prisma.advisoryRevisionSourceProvenance.count({
        where: { advisoryRevisionId: projection.revisionId },
      }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: {
          action: 'intelligence.offline_npm_osv_file_imported',
          subjectId: projection.familyId,
        },
      }),
    ).toBe(1);
  });

  it('rejects a direct offline revision command and a client organization id', async () => {
    const accepted = acceptDocument(document('GHSA-SYN0-FILE-0002'));
    const revision = accepted.normalized.revisions[0];
    if (revision === undefined) {
      throw new Error('expected one revision');
    }
    const direct = await port.persistImmutableAdvisoryRevision(revision.persistenceCommand);
    expect(direct.kind).toBe('rejected');
    if (direct.kind === 'rejected') {
      expect(direct.code).toBe('invalid_command');
    }
    const scoped = {
      ...fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
      organizationId: '11111111-1111-4111-8111-111111111111',
    };
    const rejected = await port.persistOfflineNpmAdvisoryFile(scoped);
    expect(rejected.kind).toBe('rejected');
    if (rejected.kind === 'rejected') {
      expect(rejected.code).toBe('invalid_command');
    }
    expect(
      await prisma.advisoryFamily.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0002' } }),
    ).toBe(0);
  });

  it('replays a changed purl as an immutable conflict', async () => {
    const accepted = acceptDocument(document('GHSA-SYN0-FILE-0003'));
    const first = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(first.kind).toBe('recorded');
    const revision = accepted.normalized.revisions[0];
    if (revision === undefined || first.kind !== 'recorded') {
      return;
    }
    const conflict = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId: randomUUID(),
        revisions: [{ command: revision.persistenceCommand, purl: 'pkg:npm/left-pad@9.9.9' }],
      }),
    );
    expect(conflict.kind).toBe('immutable_conflict');
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0003' } }),
    ).toBe(1);
    expect(
      await prisma.advisoryRevisionSourceProvenance.count({
        where: { advisoryId: 'GHSA-SYN0-FILE-0003' },
      }),
    ).toBe(1);
  });

  it('supersedes only the same-package tip when modified changes', async () => {
    const accepted = acceptDocument(document('GHSA-SYN0-FILE-0004'));
    const correlationId = randomUUID();
    const first = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId }),
    );
    expect(first.kind).toBe('recorded');
    const revision = accepted.normalized.revisions[0];
    const projection = first.kind === 'recorded' ? first.projections[0] : undefined;
    if (revision === undefined || projection === undefined) {
      return;
    }
    const successor = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId: randomUUID(),
        revisions: [
          {
            command: {
              ...revision.persistenceCommand,
              modifiedAt: '2026-06-01T00:00:00.000Z',
              supersedesRevisionDigest: projection.revisionDigest,
            },
            purl: null,
          },
        ],
      }),
    );
    expect(successor.kind).toBe('recorded');
    if (successor.kind !== 'recorded') {
      return;
    }
    const next = successor.projections[0];
    if (next === undefined) {
      throw new Error('expected the successor projection');
    }
    expect(next.revisionDisposition).toBe('superseding');
    expect(next.supersedesRevisionDigest).toBe(projection.revisionDigest);
    const stored = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: next.revisionId },
      select: { supersedesAdvisoryRevisionId: true, packageIdentityKey: true },
    });
    expect(stored.supersedesAdvisoryRevisionId).toBe(projection.revisionId);
    expect(stored.packageIdentityKey).toBe(projection.packageIdentityKey);
    const prior = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: projection.revisionId },
      select: { revisionDisposition: true, withdrawalClassification: true },
    });
    expect(prior.revisionDisposition).toBe('recorded');
    expect(prior.withdrawalClassification).toBe('not_withdrawn');
    const older = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(older.kind).toBe('already_applied');
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0004' } }),
    ).toBe(2);
    const tip = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: next.revisionId },
      select: { supersedesAdvisoryRevisionId: true },
    });
    expect(tip.supersedesAdvisoryRevisionId).toBe(projection.revisionId);
    const sameCorrelation = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId,
        revisions: [
          {
            command: {
              ...revision.persistenceCommand,
              modifiedAt: '2026-07-01T00:00:00.000Z',
              supersedesRevisionDigest: next.revisionDigest,
            },
            purl: null,
          },
        ],
      }),
    );
    expect(sameCorrelation.kind).toBe('recorded');
    if (sameCorrelation.kind !== 'recorded') {
      return;
    }
    expect(sameCorrelation.auditEventAdded).toBe(false);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0004' } }),
    ).toBe(3);
    expect(
      await prisma.auditEvent.count({
        where: {
          action: 'intelligence.offline_npm_osv_file_imported',
          correlationId,
          subjectId: projection.familyId,
        },
      }),
    ).toBe(1);
  });

  it('rolls back every package revision in a rejected file', async () => {
    const value = document('GHSA-SYN0-FILE-0005', {
      affected: [affectedPackage('aaa'), affectedPackage('zzz')],
    });
    const accepted = acceptDocument(value);
    const parsed = accepted.normalized.revisions.map((revision) => revision.persistenceCommand);
    const first = parsed[0];
    const second = parsed[1];
    if (first === undefined || second === undefined) {
      throw new Error('expected two packages');
    }
    const identity = parseAdvisoryRevisionCommand(first);
    if (!identity.accepted) {
      throw new Error(identity.code);
    }
    const rejected = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId: randomUUID(),
        revisions: [
          { command: first, purl: null },
          {
            command: { ...second, supersedesRevisionDigest: identity.command.revisionDigest },
            purl: null,
          },
        ],
      }),
    );
    expect(rejected.kind).toBe('rejected');
    if (rejected.kind === 'rejected') {
      expect(rejected.code).toBe('supersession_rejected');
    }
    expect(
      await prisma.advisoryFamily.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0005' } }),
    ).toBe(0);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0005' } }),
    ).toBe(0);
  });

  it('keeps an earlier file when a later file transaction rolls back', async () => {
    const earlierId = 'GHSA-SYN0-FILE-0011';
    const laterId = 'GHSA-SYN0-FILE-0012';
    const earlier = acceptDocument(document(earlierId));
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...earlier, batchId, correlationId: randomUUID() }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    const earlierRevisionId = recorded.projections[0]?.revisionId;
    if (earlierRevisionId === undefined) {
      throw new Error('expected the earlier revision');
    }

    const value = document(laterId, {
      affected: [affectedPackage('aaa'), affectedPackage('zzz')],
    });
    const accepted = acceptDocument(value);
    const parsed = accepted.normalized.revisions.map((revision) => revision.persistenceCommand);
    const first = parsed[0];
    const second = parsed[1];
    if (first === undefined || second === undefined) {
      throw new Error('expected two packages');
    }
    const identity = parseAdvisoryRevisionCommand(first);
    if (!identity.accepted) {
      throw new Error(identity.code);
    }
    const auditsBefore = await prisma.auditEvent.count();
    const rejected = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId: randomUUID(),
        revisions: [
          { command: first, purl: null },
          {
            command: { ...second, supersedesRevisionDigest: identity.command.revisionDigest },
            purl: null,
          },
        ],
      }),
    );
    expect(rejected.kind).toBe('rejected');
    if (rejected.kind === 'rejected') {
      expect(rejected.code).toBe('supersession_rejected');
    }
    expect(await prisma.auditEvent.count()).toBe(auditsBefore);
    expect(await prisma.advisoryRevision.count({ where: { advisoryId: earlierId } })).toBe(1);
    expect(
      await prisma.advisoryRevisionRangeEvent.count({
        where: { advisoryRevisionId: earlierRevisionId },
      }),
    ).toBe(2);
    expect(
      await prisma.advisoryRevisionSourceProvenance.count({
        where: { advisoryRevisionId: earlierRevisionId },
      }),
    ).toBe(1);
    expect(await prisma.advisoryFamily.count({ where: { advisoryId: laterId } })).toBe(0);
    expect(await prisma.advisoryRevision.count({ where: { advisoryId: laterId } })).toBe(0);
    expect(
      await prisma.advisoryRevisionSourceProvenance.count({ where: { advisoryId: laterId } }),
    ).toBe(0);
    expect(
      await prisma.advisoryRevisionExplicitVersion.count({
        where: { revision: { advisoryId: laterId } },
      }),
    ).toBe(0);
    expect(await prisma.finding.count()).toBe(0);
  });

  it('commits every package revision from one file under one family', async () => {
    const value = document('GHSA-SYN0-FILE-0006', {
      affected: [
        affectedPackage('zzz'),
        affectedPackage('aaa', { versions: ['1.0.0'] }, { purl: 'pkg:npm/aaa@9.9.9' }),
      ],
    });
    const accepted = acceptDocument(value);
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    expect(recorded.projections.map((projection) => projection.packageName)).toEqual([
      'aaa',
      'zzz',
    ]);
    expect(
      await prisma.advisoryFamily.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0006' } }),
    ).toBe(1);
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0006' } }),
    ).toBe(2);
    expect(
      await prisma.auditEvent.count({
        where: {
          action: 'intelligence.offline_npm_osv_file_imported',
          subjectId: recorded.familyId,
        },
      }),
    ).toBe(1);
    const firstProjection = recorded.projections[0];
    if (firstProjection === undefined) {
      throw new Error('expected the first package projection');
    }
    const aaa = await prisma.advisoryRevisionSourceProvenance.findFirstOrThrow({
      where: {
        advisoryId: 'GHSA-SYN0-FILE-0006',
        packageIdentityKey: firstProjection.packageIdentityKey,
      },
    });
    expect(aaa.purl).toBe('pkg:npm/aaa@9.9.9');
  });

  it('keeps a withdrawn timestamp on provenance', async () => {
    const accepted = acceptDocument(
      document('GHSA-SYN0-FILE-0007', {
        withdrawn: '2026-02-01T00:00:00Z',
      }),
    );
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    expect(recorded.projections[0]?.revisionDisposition).toBe('withdrawn');
    const provenance = await prisma.advisoryRevisionSourceProvenance.findFirstOrThrow({
      where: { advisoryId: 'GHSA-SYN0-FILE-0007' },
    });
    expect(provenance.withdrawnAt?.toISOString()).toBe('2026-02-01T00:00:00.000Z');
  });

  it('fails closed when one package has two tips', async () => {
    const accepted = acceptDocument(document('GHSA-SYN0-FILE-0008'));
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(recorded.kind).toBe('recorded');
    const projection = recorded.kind === 'recorded' ? recorded.projections[0] : undefined;
    const revision = accepted.normalized.revisions[0];
    if (projection === undefined || revision === undefined) {
      return;
    }
    const real = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: projection.revisionId },
    });
    const batch = await prisma.offlineAdvisoryImportBatch.findUniqueOrThrow({
      where: { id: batchId },
    });
    await prisma.$transaction(async (tx) => {
      await tx.advisoryRevision.create({
        data: {
          id: '20000000-0000-4000-8000-0000000000a1',
          revisionSchemaVersion: real.revisionSchemaVersion,
          advisoryFamilyId: real.advisoryFamilyId,
          source: real.source,
          advisoryId: real.advisoryId,
          familyDigest: real.familyDigest,
          revisionDigest: digest('second-tip-digest'),
          providerGeneration: real.providerGeneration,
          contentFingerprint: real.contentFingerprint,
          session14RangeFingerprint: real.session14RangeFingerprint,
          productRangeFingerprint: real.productRangeFingerprint,
          parserId: real.parserId,
          parserResourcePolicy: real.parserResourcePolicy,
          advisorySchemaVersion: real.advisorySchemaVersion,
          advisorySchemaCommit: real.advisorySchemaCommit,
          sourceLicenseRegistryVersion: real.sourceLicenseRegistryVersion,
          sourceLicensePolicyVersion: real.sourceLicensePolicyVersion,
          spdxLicenseId: real.spdxLicenseId,
          origin: real.origin,
          trustClassification: real.trustClassification,
          revisionDisposition: 'recorded',
          withdrawalClassification: 'not_withdrawn',
          quarantineClassification: real.quarantineClassification,
          supersedesRevisionDigest: 'none',
          retrievalClassification: real.retrievalClassification,
          retrievalEvidenceId: real.retrievalEvidenceId,
          retrievalPolicyId: real.retrievalPolicyId,
          ecosystem: real.ecosystem,
          packageNamespace: real.packageNamespace,
          packageName: real.packageName,
          packageIdentityKey: real.packageIdentityKey,
          evaluatorVersion: real.evaluatorVersion,
          matchingPolicyId: real.matchingPolicyId,
          aliasCount: real.aliasCount,
          cveAliasCount: real.cveAliasCount,
          aliasSetDigest: real.aliasSetDigest,
          replayFingerprint: digest('second-tip-replay'),
          rangeEvents: {
            create: [
              {
                rangeOrdinal: 0,
                eventOrdinal: 0,
                eventName: 'introduced',
                eventValue: '0',
              },
            ],
          },
          sourceProvenance: {
            create: {
              source: real.source,
              sourceLicenseRegistryVersion: real.sourceLicenseRegistryVersion,
              advisoryId: real.advisoryId,
              packageIdentityKey: real.packageIdentityKey,
              rawContentSha256: digest('second-tip-raw'),
              parserId: real.parserId,
              parserResourcePolicy: real.parserResourcePolicy,
              advisorySchemaVersion: real.advisorySchemaVersion,
              advisorySchemaCommit: real.advisorySchemaCommit,
              normalizationIdentity: OFFLINE_NPM_OSV_NORMALIZATION_IDENTITY,
              retrievedAt: batch.retrievedAt,
              modifiedAt: new Date('2026-01-01T00:00:00.000Z'),
              licenseAdmissionReason: 'approved_source_license',
              offlineAdvisoryImportBatchId: batch.id,
            },
          },
        },
      });
    });
    const blocked = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...accepted,
        batchId,
        correlationId: randomUUID(),
        revisions: [
          {
            command: {
              ...revision.persistenceCommand,
              modifiedAt: '2026-08-01T00:00:00.000Z',
              supersedesRevisionDigest: projection.revisionDigest,
            },
            purl: null,
          },
        ],
      }),
    );
    expect(blocked.kind).toBe('rejected');
    if (blocked.kind === 'rejected') {
      expect(blocked.code).toBe('malformed_persisted_state');
    }
    expect(
      await prisma.advisoryRevision.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0008' } }),
    ).toBe(2);
  });

  it('does not bind an offline revision or accept a missing batch', async () => {
    const accepted = acceptDocument(document('GHSA-SYN0-FILE-0009'));
    const recorded = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({ ...accepted, batchId, correlationId: randomUUID() }),
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    const storedRevision = recorded.projections[0];
    if (storedRevision === undefined) {
      throw new Error('expected one projection');
    }
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: 'SYNTHETIC-OFFLINE-FILE-UNBOUND' },
      select: { id: true },
    });
    const denied = await port.persistReviewedAdvisoryVulnerabilityBinding({
      commandSchemaVersion: ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
      revisionDigest: storedRevision.revisionDigest,
      advisoryId: 'GHSA-SYN0-FILE-0009',
      vulnerabilityId: vulnerability.id,
      mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
      mappingMethod: EXACT_MAPPING_METHOD,
    });
    expect(denied.kind).toBe('rejected');
    if (denied.kind === 'rejected') {
      expect(denied.code).toBe('unreviewed_revision');
    }
    const missingBatch = await port.persistOfflineNpmAdvisoryFile(
      fileCommand({
        ...acceptDocument(document('GHSA-SYN0-FILE-0010')),
        batchId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        correlationId: randomUUID(),
      }),
    );
    expect(missingBatch.kind).toBe('rejected');
    if (missingBatch.kind === 'rejected') {
      expect(missingBatch.code).toBe('foreign_key_violation');
    }
    expect(
      await prisma.advisoryFamily.count({ where: { advisoryId: 'GHSA-SYN0-FILE-0010' } }),
    ).toBe(0);
    expect(await prisma.finding.count()).toBe(0);
  });
});
