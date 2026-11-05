import { describe, expect, it, vi } from 'vitest';

import {
  FINDING_PRIORITY_REVIEW_NONE,
  createRecordPriorityReviewUseCase,
  normalizePriorityReviewReason,
  priorityReviewAuditPayload,
  projectFindingPriorityReview,
  projectPriorityReviewMarker,
  type RecordPriorityReviewPersistenceResult,
} from './priority-review.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const FINDING = '44444444-4444-4444-8444-444444444444';
const CALCULATION = '55555555-5555-4555-8555-555555555555';
const REVIEW = '66666666-6666-4666-8666-666666666666';
const CORRELATION = '77777777-7777-4777-8777-777777777777';
const AS_OF = new Date('2026-11-04T18:00:00.000Z');
const EXPIRES = new Date('2026-12-04T18:00:00.000Z');

const actor = {
  userId: ACTOR,
  sessionId: 'session',
  organizationId: ORG,
  membershipId: MEMBERSHIP,
  role: 'owner' as const,
};

function command(overrides: Record<string, unknown> = {}) {
  return {
    findingId: FINDING,
    riskCalculationId: CALCULATION,
    supersedesReviewId: null,
    decision: 'accepted',
    correctedBand: null,
    expiresAt: null,
    reason: null,
    correlationId: CORRELATION,
    ...overrides,
  };
}

describe('priority review', () => {
  it('normalizes a reason and rejects an empty, overlong, or NUL reason', () => {
    expect(normalizePriorityReviewReason('e\u0301')).toBe('\u00e9');
    expect(normalizePriorityReviewReason('')).toBeNull();
    expect(normalizePriorityReviewReason('x'.repeat(2001))).toBeNull();
    expect(normalizePriorityReviewReason('hidden\u0000reason')).toBeNull();
  });

  it('projects the closed review markers', () => {
    expect(projectPriorityReviewMarker({ asOf: AS_OF, priorReviewExists: false, head: null })).toBe(
      FINDING_PRIORITY_REVIEW_NONE,
    );
    expect(
      projectFindingPriorityReview({ asOf: AS_OF, priorReviewExists: true, head: null }),
    ).toEqual({ status: 'none_for_current_calculation', priorReviewExists: true });
    expect(
      projectFindingPriorityReview({
        asOf: AS_OF,
        priorReviewExists: false,
        reason: 'kept',
        head: {
          reviewId: REVIEW,
          decision: 'accepted',
          correctedBand: null,
          expiresAt: null,
        },
      }),
    ).toEqual({
      status: 'accepted',
      priorReviewExists: false,
      reviewId: REVIEW,
      reason: 'kept',
    });
    expect(
      projectPriorityReviewMarker({
        asOf: AS_OF,
        priorReviewExists: false,
        head: {
          reviewId: REVIEW,
          decision: 'corrected',
          correctedBand: 'P1',
          expiresAt: EXPIRES,
        },
      }),
    ).toEqual({
      status: 'corrected',
      priorReviewExists: false,
      reviewId: REVIEW,
      correctedBand: 'P1',
      expiresAt: EXPIRES.toISOString(),
    });
    expect(
      projectPriorityReviewMarker({
        asOf: new Date('2027-01-01T00:00:00.000Z'),
        priorReviewExists: true,
        head: {
          reviewId: REVIEW,
          decision: 'corrected',
          correctedBand: 'P1',
          expiresAt: EXPIRES,
        },
      })?.status,
    ).toBe('expired');
  });

  it('keeps the reason text out of the audit payload', () => {
    const payload = priorityReviewAuditPayload({
      reviewId: REVIEW,
      findingId: FINDING,
      riskCalculationId: CALCULATION,
      decision: 'corrected',
      correctedBand: 'P1',
      expiresAt: EXPIRES.toISOString(),
      supersedesReviewId: null,
      reasonLength: 11,
    });
    expect(payload).toEqual({
      schemaVersion: 1,
      reviewId: REVIEW,
      findingId: FINDING,
      riskCalculationId: CALCULATION,
      decision: 'corrected',
      correctedBand: 'P1',
      expiresAt: EXPIRES.toISOString(),
      supersedesReviewId: null,
      reasonLength: 11,
    });
    expect(JSON.stringify(payload)).not.toContain('working band');
    expect(Object.keys(payload ?? {})).not.toContain('reason');
  });

  it('records an owner review and replays the same command', async () => {
    const recordPriorityReview = vi.fn(
      async (): Promise<RecordPriorityReviewPersistenceResult> => ({
        kind: 'recorded',
        reviewId: REVIEW,
        findingId: FINDING,
        riskCalculationId: CALCULATION,
      }),
    );
    const useCase = createRecordPriorityReviewUseCase({ persistence: { recordPriorityReview } });
    const recorded = await useCase.execute({ actor, command: command() });
    expect(recorded).toEqual({
      kind: 'recorded',
      reviewId: REVIEW,
      findingId: FINDING,
      riskCalculationId: CALCULATION,
    });
    expect(recordPriorityReview).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: ORG, reason: null, decision: 'accepted' }),
    );
    recordPriorityReview.mockResolvedValueOnce({
      kind: 'already_applied',
      reviewId: REVIEW,
      findingId: FINDING,
      riskCalculationId: CALCULATION,
    });
    expect(await useCase.execute({ actor, command: command() })).toMatchObject({
      kind: 'already_applied',
    });
  });

  it('fails closed for another role, a client organization, and a stale review', async () => {
    const recordPriorityReview = vi.fn(
      async (): Promise<RecordPriorityReviewPersistenceResult> => ({
        kind: 'review_not_current',
      }),
    );
    const useCase = createRecordPriorityReviewUseCase({ persistence: { recordPriorityReview } });
    expect(
      await useCase.execute({
        actor: { ...actor, role: 'admin' },
        command: command(),
      }),
    ).toEqual({ kind: 'unauthorized' });
    expect(
      await useCase.execute({
        actor,
        organizationId: ORG,
        command: command(),
      }),
    ).toEqual({ kind: 'unauthorized' });
    expect(await useCase.execute({ actor, command: command() })).toEqual({
      kind: 'review_not_current',
    });
    expect(recordPriorityReview).toHaveBeenCalledTimes(1);
  });

  it('rejects a corrected review without a different band and a reason', async () => {
    const recordPriorityReview = vi.fn();
    const useCase = createRecordPriorityReviewUseCase({ persistence: { recordPriorityReview } });
    expect(
      await useCase.execute({
        actor,
        command: command({
          decision: 'corrected',
          correctedBand: 'P2',
          expiresAt: EXPIRES.toISOString(),
          reason: null,
        }),
      }),
    ).toEqual({ kind: 'invalid_command' });
    expect(recordPriorityReview).not.toHaveBeenCalled();
  });
});
