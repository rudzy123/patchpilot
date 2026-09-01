import { describe, expect, it } from 'vitest';

import {
  buildIntelligenceSyncDedupeKey,
  createIntelligenceSyncRequestedOutboxEvent,
  parseIntelligenceSyncRequestedOutboxPayload,
  parsePersistedIntelligenceSyncRequestedOutboxPayload,
  toIntelligenceOutboxPayloadJson,
} from './outbox.js';

const SYNC_RUN_ID = '99999999-9999-4999-8999-999999999999';

const validPayload = {
  schemaVersion: 1 as const,
  syncRunId: SYNC_RUN_ID,
  provider: 'cisa_kev' as const,
  sourceIdentifier: 'cisa_kev_json_catalog' as const,
};

describe('intelligence sync requested outbox payload', () => {
  it('accepts the exact safe field set', () => {
    expect(parseIntelligenceSyncRequestedOutboxPayload(validPayload)).toEqual({
      ok: true,
      value: validPayload,
    });
    expect(
      parsePersistedIntelligenceSyncRequestedOutboxPayload(
        toIntelligenceOutboxPayloadJson(validPayload),
      ),
    ).toEqual({
      ok: true,
      value: validPayload,
    });
  });

  it('rejects unknown fields, URLs, object keys, tenant IDs, and Finding IDs', () => {
    const forbidden = {
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      objectKey: 'opaque-key',
      organizationId: '11111111-1111-4111-8111-111111111111',
      findingId: '22222222-2222-4222-8222-222222222222',
      etag: '"abc"',
      workerId: 'worker-1',
    };
    for (const [key, value] of Object.entries(forbidden)) {
      expect(
        parseIntelligenceSyncRequestedOutboxPayload({ ...validPayload, [key]: value }).ok,
        key,
      ).toBe(false);
    }
  });

  it('builds a deterministic instance-owned dedupe key without finalizing window policy', () => {
    const windowKey = buildIntelligenceSyncDedupeKey({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      scheduleWindow: '2026-08-31T16',
    });
    const tokenKey = buildIntelligenceSyncDedupeKey({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      requestToken: 'manual-replay-1',
    });
    expect(windowKey.ok).toBe(true);
    expect(tokenKey.ok).toBe(true);
    if (windowKey.ok && tokenKey.ok) {
      expect(windowKey.value).toContain('cisa_kev');
      expect(windowKey.value).not.toEqual(tokenKey.value);
      expect(windowKey.value).not.toContain('https://');
    }
    expect(
      buildIntelligenceSyncDedupeKey({
        provider: 'osv',
        sourceIdentifier: 'cisa_kev_json_catalog',
        requestToken: 'x',
      }).ok,
    ).toBe(false);
  });

  it('sets availableAt to the request instant so frozen clocks can relay immediately', () => {
    const occurredAt = new Date('2026-09-01T12:00:00.000Z');
    const event = createIntelligenceSyncRequestedOutboxEvent({
      syncRunId: SYNC_RUN_ID,
      payload: validPayload,
      dedupeKey:
        'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z',
      occurredAt,
    });
    expect(event.occurredAt).toEqual(occurredAt);
    expect(event.availableAt).toEqual(occurredAt);
  });
});
