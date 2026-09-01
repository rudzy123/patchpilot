import { JSON_SCHEMA_VERSION_V1, type OutboxPayloadJson } from '../json-documents.js';
import type { CreateOutboxEventInput } from '../ports.js';
import { err, ok, type Result } from '../result.js';
import { UUID_PATTERN } from '../sbom/constants.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH,
  INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION,
  INTELLIGENCE_REQUEST_TOKEN_MAX_LENGTH,
  INTELLIGENCE_SCHEDULE_WINDOW_MAX_LENGTH,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  intelligenceProviders,
  intelligenceSourceIdentifiers,
  type IntelligenceProvider,
  type IntelligenceSourceIdentifier,
} from './constants.js';
import { intelligenceValidationError } from './errors.js';

const OUTBOX_PAYLOAD_KEYS = ['schemaVersion', 'syncRunId', 'provider', 'sourceIdentifier'] as const;

export type IntelligenceSyncRequestedOutboxPayload = {
  schemaVersion: typeof INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION;
  syncRunId: string;
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
};

export type IntelligenceSyncDedupeKeyInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  scheduleWindow?: string;
  requestToken?: string;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseIntelligenceSyncRequestedOutboxPayload(
  value: unknown,
): Result<IntelligenceSyncRequestedOutboxPayload> {
  if (!isPlainObject(value)) {
    return err(intelligenceValidationError('Outbox payload must be an object.'));
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !(OUTBOX_PAYLOAD_KEYS as readonly string[]).includes(key))) {
    return err(intelligenceValidationError('Outbox payload rejects unknown fields.'));
  }
  for (const required of OUTBOX_PAYLOAD_KEYS) {
    if (!(required in value)) {
      return err(intelligenceValidationError('Outbox payload is missing a required field.'));
    }
  }
  if (
    value['schemaVersion'] !== INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION ||
    typeof value['syncRunId'] !== 'string' ||
    !UUID_PATTERN.test(value['syncRunId']) ||
    typeof value['provider'] !== 'string' ||
    !(intelligenceProviders as readonly string[]).includes(value['provider']) ||
    typeof value['sourceIdentifier'] !== 'string' ||
    !(intelligenceSourceIdentifiers as readonly string[]).includes(value['sourceIdentifier'])
  ) {
    return err(intelligenceValidationError('Outbox payload fields are not valid.'));
  }
  if (value['provider'] === 'osv') {
    return err(
      intelligenceValidationError('OSV cannot appear in a Session 9 sync-requested payload.'),
    );
  }
  return ok({
    schemaVersion: INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION,
    syncRunId: value['syncRunId'],
    provider: value['provider'] as IntelligenceProvider,
    sourceIdentifier: value['sourceIdentifier'] as IntelligenceSourceIdentifier,
  });
}

export function toIntelligenceOutboxPayloadJson(
  payload: IntelligenceSyncRequestedOutboxPayload,
): OutboxPayloadJson {
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    ids: {
      syncRunId: payload.syncRunId,
    },
    metadata: {
      provider: payload.provider,
      sourceIdentifier: payload.sourceIdentifier,
    },
  };
}

export function buildIntelligenceSyncDedupeKey(
  input: IntelligenceSyncDedupeKeyInput,
): Result<string> {
  if (
    !(intelligenceProviders as readonly string[]).includes(input.provider) ||
    !(intelligenceSourceIdentifiers as readonly string[]).includes(input.sourceIdentifier)
  ) {
    return err(intelligenceValidationError('Dedupe key requires a closed provider and source.'));
  }
  if (input.provider === 'osv' || input.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
    return err(intelligenceValidationError('Session 9 dedupe keys are KEV-only.'));
  }
  const window = input.scheduleWindow;
  const token = input.requestToken;
  if (window === undefined && token === undefined) {
    return err(
      intelligenceValidationError(
        'Dedupe key requires a schedule window or an explicit request token.',
      ),
    );
  }
  if (
    window !== undefined &&
    (window.length === 0 || window.length > INTELLIGENCE_SCHEDULE_WINDOW_MAX_LENGTH)
  ) {
    return err(intelligenceValidationError('Schedule window exceeds the bounded length.'));
  }
  if (
    token !== undefined &&
    (token.length === 0 || token.length > INTELLIGENCE_REQUEST_TOKEN_MAX_LENGTH)
  ) {
    return err(intelligenceValidationError('Request token exceeds the bounded length.'));
  }
  const parts = [
    INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
    input.provider,
    input.sourceIdentifier,
    window === undefined ? '' : `window:${window}`,
    token === undefined ? '' : `token:${token}`,
  ];
  const key = parts.filter((part) => part.length > 0).join('|');
  if (key.length > INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH) {
    return err(intelligenceValidationError('Dedupe key exceeds the bounded length.'));
  }
  return ok(key);
}

export function createIntelligenceSyncRequestedOutboxEvent(input: {
  syncRunId: string;
  payload: IntelligenceSyncRequestedOutboxPayload;
  dedupeKey: string;
  occurredAt: Date;
}): CreateOutboxEventInput {
  return {
    aggregateType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    aggregateId: input.syncRunId,
    eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
    eventSchemaVersion: INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION,
    payload: toIntelligenceOutboxPayloadJson(input.payload),
    dedupeKey: input.dedupeKey,
    occurredAt: input.occurredAt,
  };
}
