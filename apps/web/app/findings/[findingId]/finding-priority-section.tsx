'use client';

import { useEffect, useLayoutEffect, useRef, useState, type ReactElement } from 'react';

import type { FindingPriorityResponse } from '@patchpilot/contracts';

import { useAuth } from '../../../components/auth-provider';
import { isAuthRequestError } from '../../../lib/auth-api';
import {
  PRIORITY_CALCULATE,
  PRIORITY_CALCULATING,
  PRIORITY_DUE_DATE_LABEL,
  PRIORITY_DUE_DATE_NOTE,
  PRIORITY_FORBIDDEN,
  PRIORITY_HEADING,
  PRIORITY_INCOMPARABLE,
  PRIORITY_INPUTS_DETECTED,
  PRIORITY_INPUTS_NONE,
  PRIORITY_LOADING,
  PRIORITY_NOT_CALCULATED,
  PRIORITY_NOT_FOUND,
  PRIORITY_POLICY_UNAVAILABLE,
  PRIORITY_RATE_LIMITED,
  PRIORITY_REFERENCE,
  PRIORITY_UNAVAILABLE,
} from '../../../lib/finding-priority';
import {
  canPresentFindingPriority,
  canPresentFindingPriorityCalculation,
} from '../../../lib/finding-permissions';
import { isCanonicalUuid } from '../../../lib/resource-id';

type PriorityView =
  | { status: 'loading' }
  | { status: 'ready'; priority: FindingPriorityResponse }
  | { status: 'not_found' }
  | { status: 'forbidden' }
  | { status: 'rate_limited' }
  | { status: 'policy_unavailable' }
  | { status: 'unavailable' }
  | { status: 'calculating'; priority: FindingPriorityResponse | null };

/**
 * Independent priority section. A failure here does not replace creation
 * inspection or the latest-observation section. The section keeps no durable copy.
 */
export function FindingPrioritySection({ findingId }: { findingId: string }): ReactElement | null {
  const { organization, api, getCsrfToken } = useAuth();
  const organizationId = organization?.id ?? null;
  const role = organization?.role;
  const canRead = organization !== null && canPresentFindingPriority(role);
  const canCalculate = canPresentFindingPriorityCalculation(role);
  const findingIdValid = isCanonicalUuid(findingId);
  const organizationIdRef = useRef(organizationId);
  const findingIdRef = useRef(findingId);
  const generationRef = useRef(0);
  const [trackedOrganizationId, setTrackedOrganizationId] = useState(organizationId);
  const [trackedFindingId, setTrackedFindingId] = useState(findingId);
  const [view, setView] = useState<PriorityView>({ status: 'loading' });

  if (organizationId !== trackedOrganizationId || findingId !== trackedFindingId) {
    setTrackedOrganizationId(organizationId);
    setTrackedFindingId(findingId);
    setView({ status: 'loading' });
  }

  useLayoutEffect(() => {
    organizationIdRef.current = organizationId;
    findingIdRef.current = findingId;
  }, [findingId, organizationId]);

  useEffect(() => {
    if (!canRead || organizationId === null || !findingIdValid) {
      return undefined;
    }
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    let active = true;
    void api.readFindingPriority(findingId).then(
      (priority) => {
        if (
          !active ||
          generation !== generationRef.current ||
          organizationIdRef.current !== organizationId ||
          findingIdRef.current !== findingId
        ) {
          return;
        }
        setView({ status: 'ready', priority });
      },
      (error: unknown) => {
        if (
          !active ||
          generation !== generationRef.current ||
          organizationIdRef.current !== organizationId ||
          findingIdRef.current !== findingId
        ) {
          return;
        }
        setView(viewForError(error));
      },
    );
    return () => {
      active = false;
    };
  }, [api, canRead, findingId, findingIdValid, organizationId]);

  if (!canRead || !findingIdValid) {
    return null;
  }

  return (
    <section className="finding-priority" aria-labelledby="finding-priority-heading">
      <h2 id="finding-priority-heading">{PRIORITY_HEADING}</h2>
      <PriorityBody view={view} />
      {canCalculate ? (
        <button
          type="button"
          disabled={view.status === 'calculating'}
          onClick={() => {
            const csrfToken = getCsrfToken();
            if (csrfToken === null) {
              setView({ status: 'unavailable' });
              return;
            }
            const generation = generationRef.current + 1;
            generationRef.current = generation;
            const previous = view.status === 'ready' ? view.priority : null;
            setView({ status: 'calculating', priority: previous });
            void api
              .calculateFindingPriority(findingId, csrfToken)
              .then(
                () => api.readFindingPriority(findingId),
                (error: unknown) => {
                  if (
                    generation !== generationRef.current ||
                    organizationIdRef.current !== organizationId ||
                    findingIdRef.current !== findingId
                  ) {
                    return Promise.reject(error);
                  }
                  setView(viewForError(error));
                  return Promise.reject(error);
                },
              )
              .then(
                (priority) => {
                  if (
                    generation !== generationRef.current ||
                    organizationIdRef.current !== organizationId ||
                    findingIdRef.current !== findingId ||
                    priority === undefined
                  ) {
                    return;
                  }
                  setView({ status: 'ready', priority });
                },
                () => undefined,
              );
          }}
        >
          {view.status === 'calculating' ? PRIORITY_CALCULATING : PRIORITY_CALCULATE}
        </button>
      ) : null}
    </section>
  );
}

function PriorityBody({ view }: { view: PriorityView }): ReactElement {
  if (view.status === 'loading') {
    return <p>{PRIORITY_LOADING}</p>;
  }
  if (view.status === 'not_found') {
    return <p role="alert">{PRIORITY_NOT_FOUND}</p>;
  }
  if (view.status === 'forbidden') {
    return <p role="alert">{PRIORITY_FORBIDDEN}</p>;
  }
  if (view.status === 'rate_limited') {
    return <p role="alert">{PRIORITY_RATE_LIMITED}</p>;
  }
  if (view.status === 'policy_unavailable') {
    return <p role="alert">{PRIORITY_POLICY_UNAVAILABLE}</p>;
  }
  if (view.status === 'unavailable') {
    return <p role="alert">{PRIORITY_UNAVAILABLE}</p>;
  }
  const priority = view.status === 'calculating' ? view.priority : view.priority;
  if (priority === null || view.status === 'calculating') {
    return <p>{view.status === 'calculating' ? PRIORITY_CALCULATING : PRIORITY_LOADING}</p>;
  }
  if (priority.status === 'not_calculated') {
    return <p>{PRIORITY_NOT_CALCULATED}</p>;
  }
  return (
    <>
      <dl>
        <div>
          <dt>Band</dt>
          <dd>{priority.calculation.priorityBand}</dd>
        </div>
        <div>
          <dt>Calculated at</dt>
          <dd>{priority.calculation.calculatedAt}</dd>
        </div>
        <div>
          <dt>{PRIORITY_DUE_DATE_LABEL}</dt>
          <dd>
            {priority.calculation.dueDateRecommendationDays}. {PRIORITY_DUE_DATE_NOTE}
          </dd>
        </div>
      </dl>
      <p>{priority.comparability === 'reference' ? PRIORITY_REFERENCE : PRIORITY_INCOMPARABLE}</p>
      <p>
        {priority.inputsChanged.status === 'none_detected'
          ? PRIORITY_INPUTS_NONE
          : PRIORITY_INPUTS_DETECTED}
      </p>
      {priority.inputsChanged.signals.length > 0 ? (
        <ul>
          {priority.inputsChanged.signals.map((signal) => (
            <li key={signal}>{signal}</li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

function viewForError(error: unknown): PriorityView {
  if (!isAuthRequestError(error)) {
    return { status: 'unavailable' };
  }
  if (error.status === 404) {
    return { status: 'not_found' };
  }
  if (error.status === 403) {
    return { status: 'forbidden' };
  }
  if (error.status === 429) {
    return { status: 'rate_limited' };
  }
  if (error.status === 503 && error.message === PRIORITY_POLICY_UNAVAILABLE) {
    return { status: 'policy_unavailable' };
  }
  return { status: 'unavailable' };
}
