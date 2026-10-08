import { describe, expect, it } from 'vitest';

import {
  EVIDENCE_A,
  EVIDENCE_B,
  acknowledgementFixture,
  eligibleCandidate,
  replayCandidate,
} from '../test/finding-fixtures';

import {
  classifyCreationFailure,
  confirmationActionLabel,
  discoveryExplanationText,
  readCreationCsrf,
  snapshotAcknowledgement,
} from './finding-workflow';

describe('controlled Finding workflow helpers', () => {
  it('treats a missing CSRF token as session expiry', () => {
    expect(readCreationCsrf(null)).toBe('session_expired');
    expect(readCreationCsrf('')).toBe('session_expired');
    expect(readCreationCsrf('csrf-memory-only-token')).toBe('csrf-memory-only-token');
  });

  it('classifies confirmed refusals and unconfirmed creation results', () => {
    expect(classifyCreationFailure(new Error('truncated'))).toBe('uncertain');
    expect(classifyCreationFailure({ status: 0, code: 'internal', message: 'down' })).toBe(
      'uncertain',
    );
    expect(classifyCreationFailure({ status: 500, code: 'internal', message: 'down' })).toBe(
      'uncertain',
    );
    expect(classifyCreationFailure({ status: 503, code: 'internal', message: 'down' })).toBe(
      'uncertain',
    );
    expect(
      classifyCreationFailure({ status: 409, code: 'internal', message: 'unparsed body' }),
    ).toBe('uncertain');
    expect(
      classifyCreationFailure({
        status: 409,
        code: 'conflict',
        message: 'The request conflicts with the current evidence.',
        requestId: 'req-1',
        correlationId: 'corr-1',
      }),
    ).toBe('stale');
    expect(
      classifyCreationFailure({
        status: 422,
        code: 'unprocessable_evidence',
        message: 'The evidence cannot be used for this request.',
        requestId: 'req-1',
        correlationId: 'corr-1',
      }),
    ).toBe('unprocessable');
    expect(classifyCreationFailure({ status: 401, code: 'unauthorized', message: 'no' })).toBe(
      'expired',
    );
    expect(classifyCreationFailure({ status: 403, code: 'forbidden', message: 'no' })).toBe(
      'unavailable',
    );
    expect(classifyCreationFailure({ status: 429, code: 'rate_limited', message: 'no' })).toBe(
      'rate_limited',
    );
  });

  it('names creation and exact replay without treating replay as an error', () => {
    expect(confirmationActionLabel(eligibleCandidate('CVE-2024-0001'))).toBe(
      'Create Finding for CVE-2024-0001',
    );
    expect(confirmationActionLabel(replayCandidate('CVE-2024-0099'))).toBe(
      'Submit exact replay acknowledgement for CVE-2024-0099',
    );
  });

  it('snapshots the reviewed acknowledgement without sorting or copying extra fields', () => {
    const source = {
      ...acknowledgementFixture,
      expectedProductMatchEvidenceIds: [EVIDENCE_B, EVIDENCE_A],
      organizationId: 'should-not-copy',
    };
    const snapshot = snapshotAcknowledgement(source);
    source.expectedProductMatchEvidenceIds.reverse();
    expect(snapshot.expectedProductMatchEvidenceIds).toEqual([EVIDENCE_B, EVIDENCE_A]);
    expect(snapshot).not.toHaveProperty('organizationId');
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.expectedProductMatchEvidenceIds)).toBe(true);
  });

  it('renders unknown explanation codes as text', () => {
    expect(discoveryExplanationText('several_affected_occurrences')).toContain('Several affected');
    expect(discoveryExplanationText('<b>unknown</b>')).toBe('<b>unknown</b>');
  });
});
