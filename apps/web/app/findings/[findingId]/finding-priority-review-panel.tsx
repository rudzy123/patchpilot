'use client';

import { useState, type ReactElement } from 'react';

import type { FindingPriorityResponse } from '@patchpilot/contracts';

import { isAuthRequestError } from '../../../lib/auth-api';
import {
  PRIORITY_REVIEW_HEADING,
  PRIORITY_REVIEW_NOTE,
  PRIORITY_REVIEW_RECORDED,
  PRIORITY_REVIEW_STALE,
  PRIORITY_REVIEW_UNAVAILABLE,
} from '../../../lib/finding-priority';

type CalculatedPriority = Extract<FindingPriorityResponse, { status: 'calculated' }>;

type ReviewPanelProps = {
  readonly findingId: string;
  readonly priority: CalculatedPriority;
  readonly canSubmit: boolean;
  readonly getCsrfToken: () => string | null;
  readonly record: (
    findingId: string,
    csrfToken: string,
    body: {
      riskCalculationId: string;
      supersedesReviewId: string | null;
      decision: 'accepted' | 'corrected' | 'withdrawn';
      correctedBand?: 'P1' | 'P2' | 'P3' | 'P4';
      expiresAt?: string;
      reason?: string;
    },
  ) => Promise<unknown>;
  readonly onRecorded: () => Promise<void>;
};

export function FindingPriorityReviewPanel({
  findingId,
  priority,
  canSubmit,
  getCsrfToken,
  record,
  onRecorded,
}: ReviewPanelProps): ReactElement {
  const review = priority.review;
  const supersedesReviewId = 'reviewId' in review ? review.reviewId : null;
  const [decision, setDecision] = useState<'accepted' | 'corrected' | 'withdrawn'>('accepted');
  const [correctedBand, setCorrectedBand] = useState<'P1' | 'P2' | 'P3' | 'P4'>('P1');
  const [expiresAt, setExpiresAt] = useState('');
  const [reason, setReason] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const withdrawnAvailable = supersedesReviewId !== null;

  return (
    <section aria-labelledby="finding-priority-review-heading">
      <h3 id="finding-priority-review-heading">{PRIORITY_REVIEW_HEADING}</h3>
      <p>{PRIORITY_REVIEW_NOTE}</p>
      <ReviewText review={review} />
      {canSubmit ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (submitting) {
              return;
            }
            const csrfToken = getCsrfToken();
            if (csrfToken === null) {
              setMessage(PRIORITY_REVIEW_UNAVAILABLE);
              return;
            }
            setSubmitting(true);
            setMessage(null);
            void record(findingId, csrfToken, {
              riskCalculationId: priority.calculation.riskCalculationId,
              supersedesReviewId,
              decision,
              ...(decision === 'corrected' ? { correctedBand, expiresAt } : {}),
              ...(reason.length > 0 ? { reason } : {}),
            })
              .then(async () => {
                setMessage(PRIORITY_REVIEW_RECORDED);
                await onRecorded();
              })
              .catch(async (error: unknown) => {
                if (isAuthRequestError(error) && error.status === 409) {
                  setMessage(PRIORITY_REVIEW_STALE);
                  await onRecorded();
                  return;
                }
                setMessage(isAuthRequestError(error) ? error.message : PRIORITY_REVIEW_UNAVAILABLE);
              })
              .finally(() => {
                setSubmitting(false);
              });
          }}
        >
          <label>
            Decision
            <select
              value={decision}
              onChange={(event) => {
                const next = event.target.value;
                if (next === 'accepted' || next === 'corrected' || next === 'withdrawn') {
                  setDecision(next);
                }
              }}
            >
              <option value="accepted">Accepted</option>
              <option value="corrected">Corrected</option>
              {withdrawnAvailable ? <option value="withdrawn">Withdrawn</option> : null}
            </select>
          </label>
          {decision === 'corrected' ? (
            <>
              <label>
                Working band
                <select
                  value={correctedBand}
                  onChange={(event) => {
                    const next = event.target.value;
                    if (next === 'P1' || next === 'P2' || next === 'P3' || next === 'P4') {
                      setCorrectedBand(next);
                    }
                  }}
                >
                  <option value="P1">P1</option>
                  <option value="P2">P2</option>
                  <option value="P3">P3</option>
                  <option value="P4">P4</option>
                </select>
              </label>
              <label>
                Expires at
                <input
                  value={expiresAt}
                  onChange={(event) => {
                    setExpiresAt(event.target.value);
                  }}
                  placeholder="2026-12-01T00:00:00.000Z"
                />
              </label>
            </>
          ) : null}
          <label>
            Reason
            <textarea
              value={reason}
              onChange={(event) => {
                setReason(event.target.value);
              }}
            />
          </label>
          <button type="submit" disabled={submitting || !formReady(decision, expiresAt, reason)}>
            {submitting ? 'Recording review.' : 'Record review'}
          </button>
        </form>
      ) : null}
      {message !== null ? <p role="alert">{message}</p> : null}
    </section>
  );
}

function formReady(
  decision: 'accepted' | 'corrected' | 'withdrawn',
  expiresAt: string,
  reason: string,
): boolean {
  if (decision === 'accepted') {
    return true;
  }
  if (reason.trim().length === 0) {
    return false;
  }
  return decision === 'withdrawn' || expiresAt.trim().length > 0;
}

function ReviewText({ review }: { review: CalculatedPriority['review'] }): ReactElement {
  if (review.status === 'none') {
    return <p>No priority review is recorded for this calculation.</p>;
  }
  if (review.status === 'none_for_current_calculation') {
    return <p>No review is recorded for the current calculation.</p>;
  }
  if (review.status === 'accepted') {
    return (
      <p>
        Accepted as the working priority.
        {review.reason === null ? '' : ` ${review.reason}`}
      </p>
    );
  }
  if (review.status === 'withdrawn') {
    return <p>The review was withdrawn. {review.reason}</p>;
  }
  if (review.status === 'expired') {
    return (
      <p>
        The recorded correction expired at {review.expiresAt}. The calculated band is unchanged.{' '}
        {review.reason}
      </p>
    );
  }
  return (
    <p>
      Working band {review.correctedBand} until {review.expiresAt}. The calculated band is
      unchanged. {review.reason}
    </p>
  );
}
