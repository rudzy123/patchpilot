import type { AppendAuditEventInput, CreateOutboxEventInput } from '../ports.js';
import { err, ok, type Result } from '../result.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_CORRELATION_ID_PATTERN,
  intelligenceProviders,
  intelligenceSourceIdentifiers,
  type IntelligenceProvider,
  type IntelligenceSourceIdentifier,
} from './constants.js';
import { INTELLIGENCE_OSV_RUNTIME_FORBIDDEN, intelligenceValidationError } from './errors.js';
import { intelligenceSyncRequestedAudit } from './audit.js';
import {
  buildIntelligenceSyncDedupeKey,
  createIntelligenceSyncRequestedOutboxEvent,
  parseIntelligenceSyncRequestedOutboxPayload,
  type IntelligenceSyncDedupeKeyInput,
} from './outbox.js';
import {
  createRequestedIntelligenceSyncRunRecord,
  type IntelligenceSyncRunRecord,
} from './records.js';

export type RequestIntelligenceSyncInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  requestedAt: Date;
  correlationId: string;
  syncRunId: string;
  parserVersion: string;
  normalizationVersion: string;
  scheduleWindow?: string;
  requestToken?: string;
};

export type RequestIntelligenceSyncCommands = {
  syncRun: IntelligenceSyncRunRecord;
  audit: AppendAuditEventInput;
  outbox: CreateOutboxEventInput;
};

/**
 * Framework-neutral scheduler/use-case boundary. Builds one requested SyncRun,
 * one system audit command, and one pending outbox command. Does not persist
 * and does not open a unit of work.
 */
export type IntelligenceSyncRequestPort = {
  requestSync(
    input: RequestIntelligenceSyncInput,
  ): Promise<Result<RequestIntelligenceSyncCommands>>;
};

export function buildIntelligenceSyncRequestCommands(
  input: RequestIntelligenceSyncInput,
): Result<RequestIntelligenceSyncCommands> {
  if (!(intelligenceProviders as readonly string[]).includes(input.provider)) {
    return err(intelligenceValidationError('Provider is not in the Session 9 closed set.'));
  }
  if (!(intelligenceSourceIdentifiers as readonly string[]).includes(input.sourceIdentifier)) {
    return err(
      intelligenceValidationError('Source identifier is not in the Session 9 closed set.'),
    );
  }
  if (input.provider === 'osv') {
    return err(INTELLIGENCE_OSV_RUNTIME_FORBIDDEN);
  }
  if (input.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
    return err(intelligenceValidationError('Session 9 synchronization is KEV JSON catalog only.'));
  }
  if (!INTELLIGENCE_CORRELATION_ID_PATTERN.test(input.correlationId)) {
    return err(intelligenceValidationError('Correlation ID is not a bounded safe identifier.'));
  }
  const dedupeInput: IntelligenceSyncDedupeKeyInput = {
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
    ...(input.scheduleWindow === undefined ? {} : { scheduleWindow: input.scheduleWindow }),
    ...(input.requestToken === undefined ? {} : { requestToken: input.requestToken }),
  };
  const dedupeKey = buildIntelligenceSyncDedupeKey(dedupeInput);
  if (!dedupeKey.ok) {
    return dedupeKey;
  }
  const payloadResult = parseIntelligenceSyncRequestedOutboxPayload({
    schemaVersion: 1,
    syncRunId: input.syncRunId,
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
  });
  if (!payloadResult.ok) {
    return payloadResult;
  }
  const syncRun = createRequestedIntelligenceSyncRunRecord({
    id: input.syncRunId,
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
    requestedAt: input.requestedAt,
    correlationId: input.correlationId,
    parserVersion: input.parserVersion,
    normalizationVersion: input.normalizationVersion,
  });
  if (!syncRun.ok) {
    return syncRun;
  }
  return ok({
    syncRun: syncRun.value,
    audit: intelligenceSyncRequestedAudit(
      {
        provider: input.provider,
        sourceIdentifier: input.sourceIdentifier,
        syncRunId: input.syncRunId,
      },
      input.correlationId,
      input.requestedAt,
    ),
    outbox: createIntelligenceSyncRequestedOutboxEvent({
      syncRunId: input.syncRunId,
      payload: payloadResult.value,
      dedupeKey: dedupeKey.value,
      occurredAt: input.requestedAt,
    }),
  });
}
