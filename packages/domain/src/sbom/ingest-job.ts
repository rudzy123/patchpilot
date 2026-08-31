import { err, ok, type Result } from '../result.js';
import { UUID_PATTERN, SBOM_INGESTION_REQUESTED_EVENT_TYPE } from './constants.js';

export type SbomIngestJobPayload = {
  organizationId: string;
  outboxEventId: string;
  aggregateType: 'sbom_ingestion';
  aggregateId: string;
  eventType: typeof SBOM_INGESTION_REQUESTED_EVENT_TYPE;
  dedupeKey: string;
};

const PAYLOAD_KEYS = [
  'organizationId',
  'outboxEventId',
  'aggregateType',
  'aggregateId',
  'eventType',
  'dedupeKey',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asUuid(value: unknown): string | undefined {
  return typeof value === 'string' && UUID_PATTERN.test(value) ? value : undefined;
}

/**
 * Validate an ids-only BullMQ job payload. Organization ids in the payload are
 * not authorization; the processor reloads tenant rows from persistence.
 */
export function parseSbomIngestJobPayload(value: unknown): Result<SbomIngestJobPayload> {
  if (!isRecord(value)) {
    return err({ code: 'validation', message: 'SBOM ingest job payload must be an object.' });
  }

  const keys = Object.keys(value);
  if (keys.length !== PAYLOAD_KEYS.length || PAYLOAD_KEYS.some((key) => !keys.includes(key))) {
    return err({
      code: 'validation',
      message: 'SBOM ingest job payload must contain only ids and job identity fields.',
    });
  }

  const organizationId = asUuid(value['organizationId']);
  const outboxEventId = asUuid(value['outboxEventId']);
  const aggregateId = asUuid(value['aggregateId']);
  const aggregateType = value['aggregateType'];
  const eventType = value['eventType'];
  const dedupeKey = value['dedupeKey'];

  if (organizationId === undefined || outboxEventId === undefined || aggregateId === undefined) {
    return err({ code: 'validation', message: 'SBOM ingest job payload ids must be UUIDs.' });
  }
  if (aggregateType !== 'sbom_ingestion') {
    return err({ code: 'validation', message: 'SBOM ingest job aggregate type is not valid.' });
  }
  if (eventType !== SBOM_INGESTION_REQUESTED_EVENT_TYPE) {
    return err({ code: 'validation', message: 'SBOM ingest job event type is not valid.' });
  }
  if (typeof dedupeKey !== 'string' || dedupeKey.length === 0) {
    return err({ code: 'validation', message: 'SBOM ingest job dedupe key is required.' });
  }

  return ok({
    organizationId,
    outboxEventId,
    aggregateType,
    aggregateId,
    eventType,
    dedupeKey,
  });
}
