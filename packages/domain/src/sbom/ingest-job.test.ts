import { describe, expect, it } from 'vitest';

import { SBOM_INGESTION_REQUESTED_EVENT_TYPE } from './constants.js';
import { parseSbomIngestJobPayload } from './ingest-job.js';

const VALID = {
  organizationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  outboxEventId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  aggregateType: 'sbom_ingestion' as const,
  aggregateId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
  dedupeKey: 'org:sbom.ingest:sbom:0.1.0',
};

describe('parseSbomIngestJobPayload', () => {
  it('accepts an ids-only ingestion requested payload', () => {
    const parsed = parseSbomIngestJobPayload(VALID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) {
      return;
    }
    expect(parsed.value).toEqual(VALID);
  });

  it('rejects extra fields, including object keys', () => {
    const parsed = parseSbomIngestJobPayload({
      ...VALID,
      objectKey: 'org/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/assets/x/sboms/sha256/aa',
    });
    expect(parsed.ok).toBe(false);
  });

  it('rejects missing keys and non-UUID identifiers', () => {
    expect(parseSbomIngestJobPayload({ ...VALID, organizationId: 'not-a-uuid' }).ok).toBe(false);
    expect(parseSbomIngestJobPayload({ ...VALID, aggregateType: 'sbom' }).ok).toBe(false);
    expect(parseSbomIngestJobPayload('payload').ok).toBe(false);
  });
});
