import { err, ok, type Result } from '../result.js';
import {
  INTELLIGENCE_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH,
  INTELLIGENCE_DEDUPE_KEY_PATTERN,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  UUID_PATTERN,
} from './constants.js';
import { intelligenceValidationError } from './errors.js';

export type IntelligenceSyncJobPayload = {
  organizationId: null;
  outboxEventId: string;
  aggregateType: typeof INTELLIGENCE_AUDIT_SUBJECT_TYPE;
  aggregateId: string;
  eventType: typeof INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE;
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
 * Validate an ids-only intelligence.sync queue envelope. Every field is a
 * locator. The processor reloads OutboxEvent, BackgroundJob, and SyncRun from
 * PostgreSQL and does not trust provider, source, URL, or attempt from Redis.
 */
export function parseIntelligenceSyncJobPayload(
  value: unknown,
): Result<IntelligenceSyncJobPayload> {
  if (!isRecord(value)) {
    return err(intelligenceValidationError('Intelligence sync job payload must be an object.'));
  }

  const keys = Object.keys(value);
  if (keys.length !== PAYLOAD_KEYS.length || PAYLOAD_KEYS.some((key) => !keys.includes(key))) {
    return err(
      intelligenceValidationError(
        'Intelligence sync job payload must contain only locator identity fields.',
      ),
    );
  }

  if (value['organizationId'] !== null) {
    return err(
      intelligenceValidationError('Intelligence sync job organizationId must be exactly null.'),
    );
  }
  const outboxEventId = asUuid(value['outboxEventId']);
  const aggregateId = asUuid(value['aggregateId']);
  const aggregateType = value['aggregateType'];
  const eventType = value['eventType'];
  const dedupeKey = value['dedupeKey'];

  if (outboxEventId === undefined || aggregateId === undefined) {
    return err(intelligenceValidationError('Intelligence sync job locators must be UUIDs.'));
  }
  if (aggregateType !== INTELLIGENCE_AUDIT_SUBJECT_TYPE) {
    return err(intelligenceValidationError('Intelligence sync job aggregate type is not valid.'));
  }
  if (eventType !== INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE) {
    return err(intelligenceValidationError('Intelligence sync job event type is not valid.'));
  }
  if (
    typeof dedupeKey !== 'string' ||
    dedupeKey.length === 0 ||
    dedupeKey.length > INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH ||
    !INTELLIGENCE_DEDUPE_KEY_PATTERN.test(dedupeKey)
  ) {
    return err(intelligenceValidationError('Intelligence sync job dedupe key is not valid.'));
  }

  return ok({
    organizationId: null,
    outboxEventId,
    aggregateType,
    aggregateId,
    eventType,
    dedupeKey,
  });
}
