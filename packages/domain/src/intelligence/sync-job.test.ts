import { describe, expect, it } from 'vitest';

import { parseIntelligenceSyncJobPayload } from './sync-job.js';

const VALID = {
  organizationId: null,
  outboxEventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  aggregateType: 'intelligence_sync_run',
  aggregateId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  eventType: 'intelligence.sync.requested.v1',
  dedupeKey:
    'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
};

describe('parseIntelligenceSyncJobPayload', () => {
  it('accepts the locator envelope with organizationId null', () => {
    expect(parseIntelligenceSyncJobPayload(VALID)).toEqual({ ok: true, value: VALID });
  });

  it('rejects extra provider, tenant, and retry fields', () => {
    expect(
      parseIntelligenceSyncJobPayload({ ...VALID, providerUrl: 'https://example.invalid' }).ok,
    ).toBe(false);
    expect(parseIntelligenceSyncJobPayload({ ...VALID, objectKey: 'k' }).ok).toBe(false);
    expect(parseIntelligenceSyncJobPayload({ ...VALID, etag: 'W/"1"' }).ok).toBe(false);
    expect(parseIntelligenceSyncJobPayload({ ...VALID, findingId: VALID.aggregateId }).ok).toBe(
      false,
    );
    expect(parseIntelligenceSyncJobPayload({ ...VALID, attempts: 1 }).ok).toBe(false);
    expect(
      parseIntelligenceSyncJobPayload({
        ...VALID,
        organizationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      }).ok,
    ).toBe(false);
  });

  it('rejects mismatched event and aggregate types', () => {
    expect(
      parseIntelligenceSyncJobPayload({ ...VALID, eventType: 'sbom.ingestion.requested.v1' }).ok,
    ).toBe(false);
    expect(parseIntelligenceSyncJobPayload({ ...VALID, aggregateType: 'sbom_ingestion' }).ok).toBe(
      false,
    );
    expect(parseIntelligenceSyncJobPayload({ ...VALID, outboxEventId: 'not-a-uuid' }).ok).toBe(
      false,
    );
  });
});
