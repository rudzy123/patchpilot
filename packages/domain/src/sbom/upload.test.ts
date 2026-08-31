import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { Clock } from '../clock.js';
import type {
  AppendAuditEventInput,
  AssetRepository,
  AuditAppendRepository,
  CreateOutboxEventInput,
  OutboxRepository,
} from '../ports.js';
import type {
  AssetRecord,
  AuditEventRecord,
  OutboxEventRecord,
  SbomIngestionRecord,
  SbomRecord,
} from '../records.js';
import {
  ASSET_ARCHIVED,
  ASSET_NOT_FOUND,
  ORGANIZATION_CONTEXT_REQUIRED,
  PERMISSION_DENIED,
} from '../assets/errors.js';
import {
  SBOM_INGESTION_REQUESTED_EVENT_TYPE,
  SBOM_UPLOAD_CLIENT_ABORTED,
  SBOM_UPLOAD_IDEMPOTENCY_CONFLICT,
  SBOM_UPLOAD_IN_PROGRESS,
  SBOM_UPLOAD_MISSING_INGESTION,
  SBOM_UPLOAD_POSSIBLE_ORPHAN,
  SbomEvidenceConflictError,
  createUploadSbomUseCase,
  hashFinalFingerprint,
  hashIdempotencyKey,
  hashReservationFingerprint,
  wrapRawIdempotencyKey,
  type IdempotencyReservationRecord,
  type ObjectByteStream,
  type SbomObjectStoragePort,
  type SbomUploadActor,
  type SbomUploadIdempotencyPort,
  type SbomUploadLogger,
  type SbomUploadRepositories,
  type SbomUploadUnitOfWork,
  type StorageFailureCategory,
  type UploadSbomInput,
} from './index.js';

const NOW = new Date('2026-08-31T12:00:00.000Z');
const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const USER_A = '11111111-1111-4111-8111-111111111111';
const SESSION_A = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP_A = '33333333-3333-4333-8333-333333333333';
const ASSET_A = '44444444-4444-4444-8444-444444444444';
const ASSET_B = '55555555-5555-4555-8555-555555555555';
const ARCHIVED_ASSET = '66666666-6666-4666-8666-666666666666';
const FOREIGN_ASSET = '77777777-7777-4777-8777-777777777777';
const CORRELATION = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const REQUEST = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const RAW_KEY = 'idempotency-secret-raw-key';
const BODY_TEXT = '{"bomFormat":"CycloneDX","specVersion":"1.6"}';
const BODY_BYTES = new TextEncoder().encode(BODY_TEXT);
const BODY_SHA = createHash('sha256').update(BODY_BYTES).digest('hex');
const ALT_TEXT = '{"bomFormat":"CycloneDX","specVersion":"1.5"}';
const PARSER_VERSION = '0.1.0';
const NORMALIZATION_VERSION = '1';
const JSON_TYPE = 'application/json' as const;
const MAX_BYTES = 1024;
const TTL_MS = 86_400_000;
const UPLOAD_ID = '99999999-9999-4999-8999-999999999999';

describe('SBOM upload use case', () => {
  it('requires organization context before checking permissions', async () => {
    const harness = createHarness();
    const result = await harness.upload.execute(baseInput({ actor: actorWithoutOrganization() }));
    expect(result).toEqual({
      ok: false,
      error: { ...ORGANIZATION_CONTEXT_REQUIRED, outcome: 'forbidden' },
    });
    expect(harness.storage.putCalls).toBe(0);
  });

  it('does not hash or consume the idempotency key before organization context is required', async () => {
    const harness = createHarness();
    const wrapper = wrapRawIdempotencyKey(RAW_KEY);
    const missingOrg = await harness.upload.execute(
      baseInput({
        actor: actorWithoutOrganization(),
        idempotencyKey: wrapper,
      }),
    );
    expect(missingOrg).toEqual({
      ok: false,
      error: { ...ORGANIZATION_CONTEXT_REQUIRED, outcome: 'forbidden' },
    });
    expect(wrapper.consume().keyHash).toMatch(/^[a-f0-9]{64}$/);

    const invalidHash = await harness.upload.execute(
      baseInput({
        actor: actorWithoutOrganization(),
        idempotencyKey: { keyHash: 'not-a-sha256-digest' },
      }),
    );
    expect(invalidHash).toEqual({
      ok: false,
      error: { ...ORGANIZATION_CONTEXT_REQUIRED, outcome: 'forbidden' },
    });
  });

  it('denies viewer and allows member, admin, and owner', async () => {
    const viewer = await uploadAs(actorWithPermissions(['sbom:read']));
    expect(viewer).toEqual({ ok: false, error: { ...PERMISSION_DENIED, outcome: 'forbidden' } });

    for (const permissions of [
      ['sbom:upload'],
      ['sbom:read', 'sbom:upload', 'asset:manage'],
      ['sbom:upload', 'organization:manage'],
    ]) {
      const result = await uploadAs(actorWithPermissions(permissions));
      expect(result.ok).toBe(true);
    }
  });

  it('hides a missing or cross-tenant asset behind tenant-safe not-found', async () => {
    const harness = createHarness();
    const missing = await harness.upload.execute(baseInput({ assetId: randomUUID() }));
    const foreign = await harness.upload.execute(baseInput({ assetId: FOREIGN_ASSET }));
    expect(missing).toEqual({ ok: false, error: { ...ASSET_NOT_FOUND, outcome: 'not_found' } });
    expect(foreign).toEqual({ ok: false, error: { ...ASSET_NOT_FOUND, outcome: 'not_found' } });
    expect(harness.storage.putCalls).toBe(0);
  });

  it('returns the stable archived conflict', async () => {
    const harness = createHarness();
    const result = await harness.upload.execute(baseInput({ assetId: ARCHIVED_ASSET }));
    expect(result).toEqual({ ok: false, error: { ...ASSET_ARCHIVED, outcome: 'archived' } });
    expect(harness.storage.putCalls).toBe(0);
  });

  it('acquires a reservation then streams outside the unit of work', async () => {
    const harness = createHarness();
    const result = await harness.upload.execute(baseInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.state).toBe('accepted');
    expect(result.value.sha256).toBe(BODY_SHA);
    expect(result.value.byteLength).toBe(BODY_BYTES.byteLength);
    expect(result.value).not.toHaveProperty('objectKey');
    expect(harness.uow.storageCallsDuringTransaction).toBe(0);
    expect(harness.storage.putCalls).toBe(1);
    expect(harness.storage.promoteCalls).toBe(1);
    expect(harness.audit.events).toHaveLength(1);
    expect(harness.outbox.events).toHaveLength(1);
    expect(harness.outbox.events[0]?.eventType).toBe(SBOM_INGESTION_REQUESTED_EVENT_TYPE);
  });

  it('returns in-progress for an unexpired started reservation without reading the body', async () => {
    const harness = createHarness();
    const reserved = await harness.idempotency.reserveStarted({
      organizationId: ORG_A,
      scope: `sbom.upload:${ASSET_A}`,
      keyHash: hashIdempotencyKey(RAW_KEY).keyHash,
      reservationFingerprint: hashReservationFingerprint({
        assetId: ASSET_A,
        contentType: JSON_TYPE,
      }),
      expiresAt: new Date(NOW.getTime() + TTL_MS),
    });
    expect(reserved.kind).toBe('acquired');
    const second = await harness.upload.execute(baseInput({ body: explodingBody() }));
    expect(second).toEqual({ ok: false, error: SBOM_UPLOAD_IN_PROGRESS });
    expect(harness.storage.putCalls).toBe(0);
  });

  it('returns a stable conflict when an unexpired reservation fingerprint does not match', async () => {
    const harness = createHarness();
    const reserved = await harness.idempotency.reserveStarted({
      organizationId: ORG_A,
      scope: `sbom.upload:${ASSET_A}`,
      keyHash: hashIdempotencyKey(RAW_KEY).keyHash,
      reservationFingerprint: hashReservationFingerprint({
        assetId: ASSET_A,
        contentType: 'application/vnd.cyclonedx+json',
      }),
      expiresAt: new Date(NOW.getTime() + TTL_MS),
    });
    expect(reserved.kind).toBe('acquired');
    const second = await harness.upload.execute(baseInput({ body: explodingBody() }));
    expect(second).toEqual({ ok: false, error: SBOM_UPLOAD_IDEMPOTENCY_CONFLICT });
    expect(harness.storage.putCalls).toBe(0);
  });

  it('reclaims an expired started reservation for a single winner', async () => {
    const harness = createHarness({ now: new Date('2026-08-31T12:00:00.000Z') });
    await harness.upload.execute(baseInput());
    const records = [...harness.idempotency.records.values()];
    const started = records[0];
    if (started === undefined) {
      return;
    }
    started.status = 'started';
    started.expiresAt = new Date('2026-08-31T11:00:00.000Z');
    started.response = null;
    started.finalFingerprint = null;
    harness.clock.now = () => new Date('2026-08-31T12:30:00.000Z');
    harness.storage.objects.clear();
    harness.sboms.clear();
    harness.ingestions.clear();
    harness.audit.events = [];
    harness.outbox.events = [];

    const first = harness.upload.execute(baseInput({ correlationId: randomUUID() }));
    const second = harness.upload.execute(baseInput({ correlationId: randomUUID() }));
    const results = await Promise.all([first, second]);
    const wins = results.filter((result) => result.ok);
    const losses = results.filter((result) => !result.ok);
    expect(wins).toHaveLength(1);
    expect(losses).toHaveLength(1);
    expect(losses[0]).toEqual({ ok: false, error: SBOM_UPLOAD_IN_PROGRESS });
  });

  it('replays an identical completed request without another audit or outbox', async () => {
    const harness = createHarness();
    const first = await harness.upload.execute(baseInput());
    expect(first.ok).toBe(true);
    const second = await harness.upload.execute(baseInput());
    expect(second).toEqual(first);
    expect(harness.audit.events).toHaveLength(1);
    expect(harness.outbox.events).toHaveLength(1);
    expect(harness.ingestions.size).toBe(1);
  });

  it('returns a stable conflict for a mismatched completed replay', async () => {
    const harness = createHarness();
    await harness.upload.execute(baseInput());
    const mismatched = await harness.upload.execute(baseInput({ body: streamOf(ALT_TEXT) }));
    expect(mismatched).toEqual({ ok: false, error: SBOM_UPLOAD_IDEMPOTENCY_CONFLICT });
    expect(harness.ingestions.size).toBe(1);
    expect(harness.outbox.events).toHaveLength(1);
  });

  it('reloads completed response IDs under the trusted organization and asset', async () => {
    const harness = createHarness();
    const first = await harness.upload.execute(baseInput());
    expect(first.ok).toBe(true);
    if (!first.ok) {
      return;
    }
    const stolen = harness.sboms.get(first.value.sbomId);
    if (stolen === undefined) {
      return;
    }
    stolen.assetId = ASSET_B;
    const replay = await harness.upload.execute(baseInput());
    expect(replay.ok).toBe(false);
    if (replay.ok) {
      return;
    }
    expect(replay.error.outcome).toBe('internal');
  });

  it('maps storage failures, aborts, and copy failures without finalizing metadata', async () => {
    await expectStorageFailure('aborted', SBOM_UPLOAD_CLIENT_ABORTED.outcome);
    await expectStorageFailure('size_limit', 'storage_failed');
    await expectStorageFailure('invalid_content', 'storage_failed');
    await expectStorageFailure('timeout', 'storage_failed');
    await expectStorageFailure('storage_unavailable', 'storage_failed');

    const harness = createHarness();
    harness.storage.failPromote = 'copy_failed';
    const copy = await harness.upload.execute(baseInput());
    expect(copy.ok).toBe(false);
    if (copy.ok) {
      return;
    }
    expect(copy.error.outcome).toBe('storage_failed');
    expect(harness.sboms.size).toBe(0);
    expect(harness.audit.events).toHaveLength(0);
    expect(harness.outbox.events).toHaveLength(0);
    expect(harness.storage.deleteTempCalls).toBeGreaterThan(0);
    expect(harness.storage.deletedFinal).toHaveLength(0);
  });

  it('best-effort temp cleanup ignores a client abort signal and never deletes the final object', async () => {
    const harness = createHarness();
    const controller = new AbortController();
    controller.abort();
    harness.storage.failPut = 'aborted';
    const result = await harness.upload.execute(baseInput({ signal: controller.signal }));
    expect(result).toEqual({ ok: false, error: SBOM_UPLOAD_CLIENT_ABORTED });
    expect(harness.storage.deleteTempCalls).toBe(1);
    expect(harness.storage.lastDeleteHadSignal).toBe(false);
    expect(harness.storage.deletedFinal).toHaveLength(0);
    expect(harness.sboms.size).toBe(0);
    expect(harness.audit.events).toHaveLength(0);
    expect(harness.outbox.events).toHaveLength(0);
  });

  it('treats temporary cleanup failure after promotion as success', async () => {
    const harness = createHarness();
    harness.storage.failDeleteTemp = true;
    const result = await harness.upload.execute(baseInput());
    expect(result.ok).toBe(true);
    expect(harness.logger.messages.some((line) => line.includes('cleanup failed'))).toBe(true);
    expect(harness.logger.serialized()).not.toContain('org/');
    expect(harness.logger.serialized()).not.toContain(RAW_KEY);
  });

  it('leaves a possible orphan when the database fails after promotion and never deletes the final object', async () => {
    const harness = createHarness();
    harness.audit.failNextAppend = true;
    const result = await harness.upload.execute(baseInput());
    expect(result).toEqual({ ok: false, error: SBOM_UPLOAD_POSSIBLE_ORPHAN });
    expect(harness.sboms.size).toBe(0);
    expect(harness.audit.events).toHaveLength(0);
    expect(harness.outbox.events).toHaveLength(0);
    expect(harness.storage.promotedFinalKeys).toHaveLength(1);
    expect(harness.storage.deletedFinal).toHaveLength(0);
  });

  it.each([
    'accepted',
    'queued',
    'processing',
    'completed',
    'rejected',
    'quarantined',
    'failed',
  ] as const)(
    'reuses existing evidence while ingestion is %s without a second outbox',
    async (state) => {
      const harness = createHarness();
      const first = await harness.upload.execute(
        baseInput({ idempotencyKey: hashIdempotencyKey('first') }),
      );
      expect(first.ok).toBe(true);
      if (!first.ok) {
        return;
      }
      const ingestion = harness.ingestions.get(first.value.ingestionId);
      if (ingestion === undefined) {
        return;
      }
      ingestion.state = state;
      const second = await harness.upload.execute(
        baseInput({ idempotencyKey: hashIdempotencyKey('second'), correlationId: randomUUID() }),
      );
      expect(second.ok).toBe(true);
      if (!second.ok) {
        return;
      }
      expect(second.value.sbomId).toBe(first.value.sbomId);
      expect(second.value.ingestionId).toBe(first.value.ingestionId);
      expect(second.value.state).toBe(state);
      expect(harness.ingestions.size).toBe(1);
      expect(harness.outbox.events).toHaveLength(1);
      expect(harness.audit.events.map((event) => event.action)).toEqual([
        'sbom.uploaded',
        'sbom.duplicate',
      ]);
    },
  );

  it('fails safely when existing evidence has no current ingestion', async () => {
    const harness = createHarness();
    const first = await harness.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('first') }),
    );
    expect(first.ok).toBe(true);
    if (!first.ok) {
      return;
    }
    harness.ingestions.clear();
    const second = await harness.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('second'), correlationId: randomUUID() }),
    );
    expect(second).toEqual({ ok: false, error: SBOM_UPLOAD_MISSING_INGESTION });
    expect(harness.outbox.events).toHaveLength(1);
  });

  it('treats the same hash under another asset or organization as independent', async () => {
    const harness = createHarness();
    const first = await harness.upload.execute(baseInput());
    const otherAsset = await harness.upload.execute(
      baseInput({
        assetId: ASSET_B,
        idempotencyKey: hashIdempotencyKey(RAW_KEY),
        correlationId: randomUUID(),
      }),
    );
    expect(first.ok).toBe(true);
    expect(otherAsset.ok).toBe(true);
    if (!first.ok || !otherAsset.ok) {
      return;
    }
    expect(otherAsset.value.sbomId).not.toBe(first.value.sbomId);
    expect(harness.outbox.events).toHaveLength(2);

    const otherOrgActor = actorWithPermissions(['sbom:upload'], ORG_B, MEMBERSHIP_A);
    const otherOrg = await harness.upload.execute(
      baseInput({
        actor: otherOrgActor,
        assetId: FOREIGN_ASSET,
        idempotencyKey: hashIdempotencyKey(RAW_KEY),
        correlationId: randomUUID(),
      }),
    );
    expect(otherOrg.ok).toBe(true);
    expect(harness.outbox.events).toHaveLength(3);
  });

  it('commits new-evidence rows together and rolls them back on audit, finalization, or outbox failure', async () => {
    const committed = createHarness();
    const created = await committed.upload.execute(baseInput());
    expect(created.ok).toBe(true);
    expect(committed.sboms.size).toBe(1);
    expect(committed.ingestions.size).toBe(1);
    expect(committed.audit.events).toHaveLength(1);
    expect(committed.outbox.events).toHaveLength(1);
    const reservation = [...committed.idempotency.records.values()][0];
    expect(reservation?.status).toBe('completed');

    const auditFail = createHarness();
    auditFail.audit.failNextAppend = true;
    await auditFail.upload.execute(baseInput());
    expect(auditFail.sboms.size).toBe(0);
    expect(auditFail.ingestions.size).toBe(0);
    expect(auditFail.audit.events).toHaveLength(0);
    expect(auditFail.outbox.events).toHaveLength(0);

    const finalizeFail = createHarness();
    finalizeFail.idempotency.failFinalize = true;
    await finalizeFail.upload.execute(baseInput());
    expect(finalizeFail.sboms.size).toBe(0);
    expect(finalizeFail.audit.events).toHaveLength(0);
    expect(finalizeFail.outbox.events).toHaveLength(0);

    const outboxFail = createHarness();
    outboxFail.outbox.failNextCreate = true;
    await outboxFail.upload.execute(baseInput());
    expect(outboxFail.sboms.size).toBe(0);
    expect(outboxFail.audit.events).toHaveLength(0);
    expect(outboxFail.outbox.events).toHaveLength(0);

    const duplicateAuditFail = createHarness();
    await duplicateAuditFail.upload.execute(baseInput({ idempotencyKey: hashIdempotencyKey('a') }));
    duplicateAuditFail.audit.failNextAppend = true;
    const duplicate = await duplicateAuditFail.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('b'), correlationId: randomUUID() }),
    );
    expect(duplicate.ok).toBe(false);
    expect(duplicateAuditFail.audit.events).toHaveLength(1);
    expect(duplicateAuditFail.outbox.events).toHaveLength(1);

    const duplicateFinalizeFail = createHarness();
    await duplicateFinalizeFail.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('dup-a') }),
    );
    duplicateFinalizeFail.idempotency.failFinalize = true;
    const lostDuplicate = await duplicateFinalizeFail.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('dup-b'), correlationId: randomUUID() }),
    );
    expect(lostDuplicate).toEqual({ ok: false, error: SBOM_UPLOAD_POSSIBLE_ORPHAN });
    expect(duplicateFinalizeFail.audit.events).toHaveLength(1);
    expect(duplicateFinalizeFail.outbox.events).toHaveLength(1);
    expect(duplicateFinalizeFail.storage.deletedFinal).toHaveLength(0);
  });

  it('reloads duplicate evidence when another request wins the unique insert race', async () => {
    const harness = createHarness();
    const seed = await harness.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('seed') }),
    );
    expect(seed.ok).toBe(true);
    harness.sbomMetadata.hideExistingOnLookup = true;
    harness.audit.events = [];
    const raced = await harness.upload.execute(
      baseInput({ idempotencyKey: hashIdempotencyKey('racer'), correlationId: randomUUID() }),
    );
    expect(raced.ok).toBe(true);
    expect(harness.outbox.events).toHaveLength(1);
    expect(harness.audit.events.map((event) => event.action)).toEqual(['sbom.duplicate']);
  });

  it('keeps two simultaneous reservations to a single winner', async () => {
    const harness = createHarness();
    let releasePut: (() => void) | undefined;
    const holdPut = new Promise<void>((resolve) => {
      releasePut = resolve;
    });
    let sawPut: (() => void) | undefined;
    const putStarted = new Promise<void>((resolve) => {
      sawPut = resolve;
    });
    harness.storage.onPut = async () => {
      sawPut?.();
      await holdPut;
    };
    const first = harness.upload.execute(baseInput({ body: streamOf(BODY_TEXT) }));
    await putStarted;
    const second = await harness.upload.execute(baseInput({ body: streamOf(BODY_TEXT) }));
    releasePut?.();
    const firstResult = await first;
    expect(firstResult.ok).toBe(true);
    expect(second).toEqual({ ok: false, error: SBOM_UPLOAD_IN_PROGRESS });
  });

  it('finalization matches the still-started reservation and cannot overwrite completed state', async () => {
    const harness = createHarness();
    const first = await harness.upload.execute(baseInput());
    expect(first.ok).toBe(true);
    const completed = [...harness.idempotency.records.values()][0];
    if (completed === undefined || completed.response === null) {
      return;
    }
    const original = { ...completed.response };
    const lost = await harness.idempotency.finalizeCompleted({
      organizationId: ORG_A,
      scope: `sbom.upload:${ASSET_A}`,
      keyHash: hashIdempotencyKey(RAW_KEY).keyHash,
      reservationFingerprint: hashReservationFingerprint({
        assetId: ASSET_A,
        contentType: JSON_TYPE,
      }),
      finalFingerprint: hashFinalFingerprint({
        assetId: ASSET_A,
        contentType: JSON_TYPE,
        sha256: BODY_SHA,
        byteLength: BODY_BYTES.byteLength,
      }),
      responseStatus: 202,
      response: {
        schemaVersion: 1,
        sbomId: randomUUID(),
        ingestionId: randomUUID(),
      },
    });
    expect(lost.ok).toBe(false);
    expect(completed.status).toBe('completed');
    expect(completed.response).toEqual(original);
  });

  it('omits the raw body, raw key, and object key from PostgreSQL rows, public results, logs, and audit metadata', async () => {
    const harness = createHarness();
    const result = await harness.upload.execute(
      baseInput({ idempotencyKey: wrapRawIdempotencyKey(RAW_KEY) }),
    );
    expect(result.ok).toBe(true);
    const sbom = [...harness.sboms.values()][0];
    const audit = harness.audit.events[0];
    const outbox = harness.outbox.events[0];
    const reservation = [...harness.idempotency.records.values()][0];
    expect(JSON.stringify(sbom)).not.toContain(BODY_TEXT);
    expect(JSON.stringify(reservation)).not.toContain(RAW_KEY);
    expect(JSON.stringify(result)).not.toContain('objectKey');
    expect(JSON.stringify(audit?.payload.metadata)).not.toMatch(
      /objectKey|bucket|endpoint|filename/,
    );
    expect(JSON.stringify(audit?.payload.metadata)).not.toContain(RAW_KEY);
    expect(JSON.stringify(outbox?.payload)).not.toMatch(/objectKey|filename|signed/);
    expect(harness.logger.serialized()).not.toContain(RAW_KEY);
    expect(harness.logger.serialized()).not.toContain('org/');
  });

  it('never opens a unit of work while request bytes are streamed', async () => {
    const harness = createHarness();
    harness.storage.onPut = () => {
      expect(harness.uow.active).toBe(false);
    };
    await harness.upload.execute(baseInput());
    expect(harness.uow.storageCallsDuringTransaction).toBe(0);
    expect(harness.uow.auditCallsOutsideTransaction).toBe(0);
  });

  it('keeps Redis, BullMQ, and AWS SDK types out of the upload use case', () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'upload.ts'), 'utf8');
    expect(source).not.toMatch(/bullmq|ioredis|Redis|@aws-sdk|S3Client|Queue|Worker/);
    expect(source).toContain('SbomObjectStoragePort');
    expect(source).not.toContain('rawKey');
    expect(source).not.toContain('organizationId?:');
  });
});

async function uploadAs(actor: SbomUploadActor) {
  const harness = createHarness();
  return harness.upload.execute(baseInput({ actor }));
}

async function expectStorageFailure(category: StorageFailureCategory, outcome: string) {
  const harness = createHarness();
  harness.storage.failPut = category;
  const result = await harness.upload.execute(baseInput());
  expect(result.ok).toBe(false);
  if (result.ok) {
    return;
  }
  expect(result.error.outcome).toBe(outcome);
  expect(harness.sboms.size).toBe(0);
  expect(harness.audit.events).toHaveLength(0);
  expect(harness.outbox.events).toHaveLength(0);
}

function actorWithoutOrganization(): SbomUploadActor {
  return {
    userId: USER_A,
    sessionId: SESSION_A,
    organizationId: null,
    membershipId: null,
    permissions: ['sbom:upload'],
  };
}

function actorWithPermissions(
  permissions: readonly string[],
  organizationId = ORG_A,
  membershipId = MEMBERSHIP_A,
): SbomUploadActor {
  return {
    userId: USER_A,
    sessionId: SESSION_A,
    organizationId,
    membershipId,
    permissions,
  };
}

function baseInput(overrides: Partial<UploadSbomInput> = {}): UploadSbomInput {
  const declaredByteLength = overrides.declaredByteLength;
  const requestId = overrides.requestId;
  const signal = overrides.signal;
  return {
    actor: overrides.actor ?? actorWithPermissions(['sbom:upload']),
    assetId: overrides.assetId ?? ASSET_A,
    idempotencyKey: overrides.idempotencyKey ?? hashIdempotencyKey(RAW_KEY),
    contentType: overrides.contentType ?? JSON_TYPE,
    body: overrides.body ?? streamOf(BODY_TEXT),
    maxBytes: overrides.maxBytes ?? MAX_BYTES,
    parserVersion: overrides.parserVersion ?? PARSER_VERSION,
    normalizationVersion: overrides.normalizationVersion ?? NORMALIZATION_VERSION,
    idempotencyTtlMs: overrides.idempotencyTtlMs ?? TTL_MS,
    correlationId: overrides.correlationId ?? CORRELATION,
    ...(declaredByteLength === undefined ? {} : { declaredByteLength }),
    ...(requestId === undefined ? { requestId: REQUEST } : { requestId }),
    ...(signal === undefined ? {} : { signal }),
  };
}

function streamOf(text: string): ObjectByteStream {
  return (async function* () {
    yield new TextEncoder().encode(text);
  })();
}

function explodingBody(): ObjectByteStream {
  return {
    [Symbol.asyncIterator]() {
      return {
        next() {
          throw new Error('body should not be read');
        },
      };
    },
  };
}

function createHarness(options: { now?: Date } = {}) {
  const now = options.now ?? NOW;
  const clock: Clock & { now: () => Date } = {
    now: () => now,
  };
  const assets = createAssetRepo();
  const logger = createLogger();
  const storage = createStorage(() => uow.active);
  const idempotency = createIdempotency();
  const sboms = new Map<string, SbomRecord>();
  const ingestions = new Map<string, SbomIngestionRecord>();
  const audit = createAudit(() => uow.active);
  const outbox = createOutbox();
  const sbomMetadata = createSbomMetadata(sboms, ingestions);
  const ingestionPort = createIngestionPort(ingestions, sboms);
  const uow = createUnitOfWork({
    assets,
    sbomMetadata,
    ingestions: ingestionPort,
    uploadIdempotency: idempotency,
    auditEvents: audit,
    outboxEvents: outbox,
    sboms,
    ingestionsMap: ingestions,
    audit,
    outbox,
    idempotency,
  });

  const upload = createUploadSbomUseCase({
    clock,
    createId: () => UPLOAD_ID,
    assets,
    uploadIdempotency: idempotency,
    sbomMetadata,
    ingestions: ingestionPort,
    storage,
    unitOfWork: uow,
    logger,
  });

  return {
    clock,
    upload,
    storage,
    idempotency,
    sboms,
    ingestions,
    audit,
    outbox,
    uow,
    logger,
    sbomMetadata,
  };
}

function createAssetRepo(): Pick<AssetRepository, 'findById'> {
  const rows = new Map<string, AssetRecord>([
    [assetKey(ORG_A, ASSET_A), assetRecord(ORG_A, ASSET_A, 'active')],
    [assetKey(ORG_A, ASSET_B), assetRecord(ORG_A, ASSET_B, 'active')],
    [assetKey(ORG_A, ARCHIVED_ASSET), assetRecord(ORG_A, ARCHIVED_ASSET, 'archived')],
    [assetKey(ORG_B, FOREIGN_ASSET), assetRecord(ORG_B, FOREIGN_ASSET, 'active')],
  ]);
  return {
    async findById(organizationId, id) {
      return rows.get(assetKey(organizationId, id));
    },
  };
}

function assetKey(organizationId: string, id: string): string {
  return `${organizationId}:${id}`;
}

function assetRecord(
  organizationId: string,
  id: string,
  lifecycleStatus: 'active' | 'archived',
): AssetRecord {
  return {
    id,
    organizationId,
    name: id,
    description: null,
    assetType: 'application',
    lifecycleStatus,
    environmentId: null,
    owningTeamId: null,
    businessCriticality: 'unspecified',
    internetExposure: 'unknown',
    dataClassification: 'unspecified',
    repositoryUrl: null,
    deploymentContext: null,
    lastObservedAt: null,
    lastSuccessfulSbomIngestionId: null,
    lastSuccessfulSbomIngestionAt: null,
    archivedAt: lifecycleStatus === 'archived' ? NOW : null,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function createLogger(): SbomUploadLogger & { messages: string[]; serialized: () => string } {
  const messages: string[] = [];
  return {
    messages,
    warn(bindings, message) {
      messages.push(`${JSON.stringify(bindings)} ${message}`);
    },
    serialized: () => messages.join('\n'),
  };
}

function createStorage(inTransaction: () => boolean): SbomObjectStoragePort & {
  putCalls: number;
  promoteCalls: number;
  deleteTempCalls: number;
  lastDeleteHadSignal: boolean | undefined;
  failPut?: StorageFailureCategory;
  failPromote?: StorageFailureCategory;
  failDeleteTemp: boolean;
  objects: Map<string, Uint8Array>;
  promotedFinalKeys: string[];
  deletedFinal: string[];
  onPut?: () => void | Promise<void>;
} {
  const objects = new Map<string, Uint8Array>();
  const promotedFinalKeys: string[] = [];
  const deletedFinal: string[] = [];
  const storage: SbomObjectStoragePort & {
    putCalls: number;
    promoteCalls: number;
    deleteTempCalls: number;
    lastDeleteHadSignal: boolean | undefined;
    failPut?: StorageFailureCategory;
    failPromote?: StorageFailureCategory;
    failDeleteTemp: boolean;
    objects: Map<string, Uint8Array>;
    promotedFinalKeys: string[];
    deletedFinal: string[];
    onPut?: () => void | Promise<void>;
  } = {
    putCalls: 0,
    promoteCalls: 0,
    deleteTempCalls: 0,
    lastDeleteHadSignal: undefined,
    failDeleteTemp: false,
    objects,
    promotedFinalKeys,
    deletedFinal,
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
      if (inTransaction()) {
        throw new Error('storage called inside unit of work');
      }
      storage.putCalls += 1;
      await storage.onPut?.();
      if (storage.failPut !== undefined) {
        return { ok: false, error: { category: storage.failPut } };
      }
      const chunks: Uint8Array[] = [];
      for await (const chunk of input.body) {
        chunks.push(chunk);
      }
      const bytes = concat(chunks);
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
      if (inTransaction()) {
        throw new Error('storage called inside unit of work');
      }
      storage.promoteCalls += 1;
      if (storage.failPromote !== undefined) {
        return { ok: false, error: { category: storage.failPromote } };
      }
      const bytes = objects.get(input.temporaryObjectKey);
      if (bytes === undefined) {
        return { ok: false, error: { category: 'object_missing' } };
      }
      objects.set(input.finalObjectKey, bytes);
      promotedFinalKeys.push(input.finalObjectKey);
      return { ok: true, value: undefined };
    },
    async headFinalObject() {
      return { ok: true, value: { exists: false } };
    },
    async deleteTemporaryObject(input) {
      if (inTransaction()) {
        throw new Error('storage called inside unit of work');
      }
      storage.deleteTempCalls += 1;
      storage.lastDeleteHadSignal = input.signal !== undefined;
      if (storage.failDeleteTemp) {
        return { ok: false, error: { category: 'storage_unavailable' } };
      }
      objects.delete(input.temporaryObjectKey);
      return { ok: true, value: undefined };
    },
    async getObject() {
      return { ok: false, error: { category: 'internal' } };
    },
  };
  return storage;
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function createIdempotency(): SbomUploadIdempotencyPort & {
  records: Map<string, IdempotencyReservationRecord>;
  failFinalize: boolean;
  chain: Promise<void>;
} {
  const records = new Map<string, IdempotencyReservationRecord>();
  const port: SbomUploadIdempotencyPort & {
    records: Map<string, IdempotencyReservationRecord>;
    failFinalize: boolean;
    chain: Promise<void>;
  } = {
    records,
    failFinalize: false,
    chain: Promise.resolve(),
    async reserveStarted(input) {
      const run = port.chain.then(() => {
        const key = reservationKey(input);
        const existing = records.get(key);
        if (existing === undefined) {
          const record: IdempotencyReservationRecord = {
            id: randomUUID(),
            organizationId: input.organizationId,
            scope: input.scope,
            keyHash: input.keyHash,
            reservationFingerprint: input.reservationFingerprint,
            status: 'started',
            expiresAt: input.expiresAt,
            completedAt: null,
            response: null,
            finalFingerprint: null,
          };
          records.set(key, record);
          return { kind: 'acquired' as const, record };
        }
        const now = NOW;
        if (existing.status === 'completed') {
          return { kind: 'completed' as const, record: existing };
        }
        if (existing.status === 'conflict') {
          return { kind: 'conflict' as const, record: existing };
        }
        if (existing.status === 'started' && existing.expiresAt > now) {
          if (existing.reservationFingerprint !== input.reservationFingerprint) {
            return { kind: 'conflict' as const, record: existing };
          }
          return { kind: 'unexpired_started' as const, record: existing };
        }
        if (existing.status === 'started' && existing.expiresAt <= now) {
          return { kind: 'reclaimable_expired' as const, record: existing };
        }
        return { kind: 'conflict' as const, record: existing };
      });
      port.chain = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
    async findUnexpiredStarted(input) {
      const existing = records.get(reservationKey(input));
      if (existing?.status === 'started' && existing.expiresAt > NOW) {
        return existing;
      }
      return undefined;
    },
    async reclaimExpiredStarted(input) {
      const run = port.chain.then(() => {
        const existing = records.get(reservationKey(input));
        if (existing === undefined || existing.status !== 'started' || existing.expiresAt > NOW) {
          return {
            ok: false as const,
            error: { code: 'conflict' as const, message: 'not reclaimed' },
          };
        }
        existing.reservationFingerprint = input.reservationFingerprint;
        existing.expiresAt = input.expiresAt;
        existing.response = null;
        existing.finalFingerprint = null;
        existing.completedAt = null;
        return { ok: true as const, value: existing };
      });
      port.chain = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
    async finalizeCompleted(input) {
      if (port.failFinalize) {
        return {
          ok: false,
          error: { code: 'conflict', message: 'Idempotency reservation could not be finalized.' },
        };
      }
      const existing = records.get(reservationKey(input));
      if (
        existing === undefined ||
        existing.status !== 'started' ||
        existing.reservationFingerprint !== input.reservationFingerprint
      ) {
        return {
          ok: false,
          error: { code: 'conflict', message: 'Idempotency reservation could not be finalized.' },
        };
      }
      existing.status = 'completed';
      existing.finalFingerprint = input.finalFingerprint;
      existing.reservationFingerprint = input.finalFingerprint;
      existing.completedAt = NOW;
      existing.response = input.response;
      return { ok: true, value: existing };
    },
    async resolveCompletedReplay(input) {
      const existing = records.get(`${input.organizationId}:${input.scope}:${input.keyHash}`);
      if (existing === undefined || existing.status !== 'completed' || existing.response === null) {
        return { ok: false, error: { code: 'not_found', message: 'not found' } };
      }
      if (existing.finalFingerprint !== input.finalFingerprint) {
        return { ok: true, value: { kind: 'fingerprint_mismatch' } };
      }
      return {
        ok: true,
        value: { kind: 'replay', response: existing.response, responseStatus: 202 },
      };
    },
  };
  return port;
}

function reservationKey(input: { organizationId: string; scope: string; keyHash: string }): string {
  return `${input.organizationId}:${input.scope}:${input.keyHash}`;
}

function createSbomMetadata(
  sboms: Map<string, SbomRecord>,
  ingestions: Map<string, SbomIngestionRecord>,
) {
  return {
    conflictNextInsert: false,
    hideExistingOnLookup: false,
    async insert(input: {
      organizationId: string;
      assetId: string;
      objectKey: string;
      sha256: string;
      byteLength: number;
      declaredContentType: string;
      specificationType: 'cyclonedx';
      source: 'upload' | 'reprocess';
      uploadedByMembershipId: string | null;
      capturedAt: Date | null;
      receivedAt: Date;
    }): Promise<SbomRecord> {
      const existing = [...sboms.values()].find(
        (row) =>
          row.organizationId === input.organizationId &&
          row.assetId === input.assetId &&
          row.sha256 === input.sha256,
      );
      if (existing !== undefined || this.conflictNextInsert) {
        this.conflictNextInsert = false;
        if (existing === undefined) {
          throw new SbomEvidenceConflictError();
        }
        throw new SbomEvidenceConflictError();
      }
      const record: SbomRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        assetId: input.assetId,
        objectKey: input.objectKey,
        sha256: input.sha256,
        byteLength: input.byteLength,
        declaredContentType: input.declaredContentType,
        specificationType: input.specificationType,
        specificationVersion: null,
        source: input.source,
        originalFilename: null,
        uploadedByMembershipId: input.uploadedByMembershipId,
        capturedAt: input.capturedAt,
        receivedAt: input.receivedAt,
        parserVersionLastSucceeded: null,
        createdAt: NOW,
      };
      sboms.set(record.id, record);
      return record;
    },
    async findById(organizationId: string, sbomId: string) {
      const row = sboms.get(sbomId);
      return row?.organizationId === organizationId ? row : undefined;
    },
    async findByAssetAndId(organizationId: string, assetId: string, sbomId: string) {
      const row = sboms.get(sbomId);
      return row?.organizationId === organizationId && row.assetId === assetId ? row : undefined;
    },
    async findByAssetAndHash(organizationId: string, assetId: string, sha256: string) {
      if (this.hideExistingOnLookup) {
        this.hideExistingOnLookup = false;
        return undefined;
      }
      return [...sboms.values()].find(
        (row) =>
          row.organizationId === organizationId && row.assetId === assetId && row.sha256 === sha256,
      );
    },
    async listForAsset() {
      return { items: [], nextCursor: undefined };
    },
    async recordSuccessfulParser() {
      return { ok: false as const, error: { code: 'internal' as const, message: 'unused' } };
    },
    ingestions,
  };
}

function createIngestionPort(
  ingestions: Map<string, SbomIngestionRecord>,
  sboms: Map<string, SbomRecord>,
) {
  return {
    async createAccepted(input: {
      organizationId: string;
      sbomId: string;
      assetId: string;
      parserVersion: string;
      normalizationVersion: string;
    }) {
      const record: SbomIngestionRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        sbomId: input.sbomId,
        assetId: input.assetId,
        state: 'accepted',
        stage: 'validate',
        attemptNumber: 1,
        parserVersion: input.parserVersion,
        normalizationVersion: input.normalizationVersion,
        idempotencyKey: null,
        startedAt: null,
        completedAt: null,
        graphCompleteness: null,
        componentCount: null,
        dependencyEdgeCount: null,
        warningCount: null,
        failureCategory: null,
        failureCode: null,
        quarantineReason: null,
        leaseExpiresAt: null,
        version: 1,
        createdAt: NOW,
        updatedAt: NOW,
      };
      ingestions.set(record.id, record);
      return { ok: true as const, value: record };
    },
    async findById(organizationId: string, ingestionId: string) {
      const row = ingestions.get(ingestionId);
      return row?.organizationId === organizationId ? row : undefined;
    },
    async findByAssetAndId(organizationId: string, assetId: string, ingestionId: string) {
      const row = ingestions.get(ingestionId);
      return row?.organizationId === organizationId && row.assetId === assetId ? row : undefined;
    },
    async findCurrentForSbom(organizationId: string, sbomId: string) {
      const matches = [...ingestions.values()]
        .filter((row) => row.organizationId === organizationId && row.sbomId === sbomId)
        .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
      return matches[0];
    },
    async applyTransition() {
      return { ok: false as const, error: { code: 'conflict' as const, message: 'unused' } };
    },
    sboms,
  };
}

function createAudit(inTransaction: () => boolean): AuditAppendRepository & {
  events: AuditEventRecord[];
  failNextAppend: boolean;
  callsOutsideTransaction: number;
} {
  const audit: AuditAppendRepository & {
    events: AuditEventRecord[];
    failNextAppend: boolean;
    callsOutsideTransaction: number;
  } = {
    events: [],
    failNextAppend: false,
    callsOutsideTransaction: 0,
    async append(input: AppendAuditEventInput) {
      if (!inTransaction()) {
        audit.callsOutsideTransaction += 1;
      }
      if (audit.failNextAppend) {
        audit.failNextAppend = false;
        throw new Error('audit append failed');
      }
      const record: AuditEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        actorUserId: input.actorUserId ?? null,
        actorMembershipId: input.actorMembershipId ?? null,
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? NOW,
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        sourceIp: input.sourceIp ?? null,
        userAgent: input.userAgent ?? null,
        payload: input.payload,
        schemaVersion: input.schemaVersion ?? 1,
        retentionCategory: input.retentionCategory ?? 'security',
      };
      audit.events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };
  return audit;
}

function createOutbox(): OutboxRepository & {
  events: OutboxEventRecord[];
  failNextCreate: boolean;
} {
  const outbox: OutboxRepository & { events: OutboxEventRecord[]; failNextCreate: boolean } = {
    events: [],
    failNextCreate: false,
    async create(input: CreateOutboxEventInput) {
      if (outbox.failNextCreate) {
        outbox.failNextCreate = false;
        throw new Error('outbox create failed');
      }
      const record: OutboxEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        aggregateType: input.aggregateType,
        aggregateId: input.aggregateId,
        eventType: input.eventType,
        eventSchemaVersion: input.eventSchemaVersion ?? 1,
        payload: input.payload,
        dedupeKey: input.dedupeKey,
        occurredAt: input.occurredAt ?? NOW,
        availableAt: input.availableAt ?? NOW,
        claimedAt: null,
        leaseExpiresAt: null,
        processedAt: null,
        attemptCount: 0,
        lastFailureCategory: null,
        lastFailureCode: null,
        status: input.status ?? 'pending',
        createdAt: NOW,
      };
      outbox.events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };
  return outbox;
}

function createUnitOfWork(state: {
  assets: Pick<AssetRepository, 'findById'>;
  sbomMetadata: ReturnType<typeof createSbomMetadata>;
  ingestions: ReturnType<typeof createIngestionPort>;
  uploadIdempotency: ReturnType<typeof createIdempotency>;
  auditEvents: ReturnType<typeof createAudit>;
  outboxEvents: ReturnType<typeof createOutbox>;
  sboms: Map<string, SbomRecord>;
  ingestionsMap: Map<string, SbomIngestionRecord>;
  audit: ReturnType<typeof createAudit>;
  outbox: ReturnType<typeof createOutbox>;
  idempotency: ReturnType<typeof createIdempotency>;
}): SbomUploadUnitOfWork & {
  active: boolean;
  storageCallsDuringTransaction: number;
  auditCallsOutsideTransaction: number;
} {
  const uow = {
    active: false,
    storageCallsDuringTransaction: 0,
    auditCallsOutsideTransaction: 0,
    async runInTransaction<T>(work: (repos: SbomUploadRepositories) => Promise<T>): Promise<T> {
      const snapshot = {
        sboms: [...state.sboms.entries()],
        ingestions: [...state.ingestionsMap.entries()],
        audit: [...state.audit.events],
        outbox: [...state.outbox.events],
        reservations: [...state.idempotency.records.entries()].map(
          ([key, value]) => [key, { ...value }] as const,
        ),
      };
      uow.active = true;
      try {
        return await work({
          assets: state.assets,
          sbomMetadata: state.sbomMetadata,
          ingestions: state.ingestions,
          uploadIdempotency: state.uploadIdempotency,
          auditEvents: state.auditEvents,
          outboxEvents: state.outboxEvents,
        });
      } catch (error) {
        state.sboms.clear();
        for (const [id, row] of snapshot.sboms) {
          state.sboms.set(id, row);
        }
        state.ingestionsMap.clear();
        for (const [id, row] of snapshot.ingestions) {
          state.ingestionsMap.set(id, row);
        }
        state.audit.events.splice(0, state.audit.events.length, ...snapshot.audit);
        state.outbox.events.splice(0, state.outbox.events.length, ...snapshot.outbox);
        state.idempotency.records.clear();
        for (const [key, value] of snapshot.reservations) {
          state.idempotency.records.set(key, value);
        }
        throw error;
      } finally {
        uow.active = false;
        uow.auditCallsOutsideTransaction = state.audit.callsOutsideTransaction;
      }
    },
  };
  return uow;
}
