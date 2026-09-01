import { describe, expect, it } from 'vitest';

import { INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE } from './constants.js';
import {
  intelligenceInitialQueueJobId,
  intelligenceRedispatchJobId,
  intelligenceRetryQueueJobId,
} from './retry-redelivery.js';

const EVENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('intelligence retry job ids', () => {
  it('uses the original Outbox job id for first delivery', () => {
    expect(intelligenceInitialQueueJobId(EVENT)).toEqual({
      ok: true,
      value: `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${EVENT}`,
    });
    expect(intelligenceRedispatchJobId({ outboxEventId: EVENT, jobAttempt: 0 })).toEqual({
      ok: true,
      value: `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${EVENT}`,
    });
  });

  it('uses a deterministic retry id after a persisted attempt', () => {
    expect(intelligenceRetryQueueJobId({ outboxEventId: EVENT, attempt: 1 })).toEqual({
      ok: true,
      value: `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${EVENT}__retry__1`,
    });
    expect(intelligenceRedispatchJobId({ outboxEventId: EVENT, jobAttempt: 2 })).toEqual({
      ok: true,
      value: `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${EVENT}__retry__2`,
    });
  });

  it('rejects unbounded or random suffixes', () => {
    expect(intelligenceRetryQueueJobId({ outboxEventId: EVENT, attempt: 0 }).ok).toBe(false);
    expect(intelligenceInitialQueueJobId('not-a-uuid').ok).toBe(false);
  });
});
