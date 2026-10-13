'use client';

import { useEffect, useLayoutEffect, useRef, useState, type ReactElement } from 'react';

import type { ControlledFindingLatestObservationResponse } from '@patchpilot/contracts';

import { useAuth } from '../../../components/auth-provider';
import { GENERIC_SESSION_EXPIRED, isAuthRequestError } from '../../../lib/auth-api';
import {
  AGGREGATE_COPY,
  CREATION_SOURCE_TEXT,
  GRAPH_COMPLETENESS_LABEL,
  GRAPH_COMPLETENESS_TEXT,
  KNOWN_VERSIONS_COMPLETE,
  KNOWN_VERSIONS_HEADING,
  KNOWN_VERSIONS_NONE,
  KNOWN_VERSIONS_TRUNCATED,
  LATEST_OBSERVATION_HEADING,
  LATEST_OBSERVATION_LOADING,
  LATEST_OBSERVATION_NOT_FOUND,
  LATEST_OBSERVATION_RATE_LIMITED,
  LATEST_OBSERVATION_REFRESH,
  LATEST_OBSERVATION_UNAVAILABLE,
  LATEST_REPEATED_SOURCE_TEXT,
  NO_DEPENDENCIES_TEXT,
  OBSERVATION_RECORDED_LABEL,
  readLatestObservation,
  SUPPORT_LABELS,
} from '../../../lib/finding-latest-observation';
import { canPresentControlledFindingInspection } from '../../../lib/finding-permissions';
import { CONTROLLED_FINDING_UNAVAILABLE } from '../../../lib/finding-workflow';
import { isCanonicalUuid } from '../../../lib/resource-id';

type LatestObservationView =
  | { status: 'loading' }
  | { status: 'ready'; observation: ControlledFindingLatestObservationResponse }
  | { status: 'not_found' }
  | { status: 'rate_limited' }
  | { status: 'unavailable' }
  | { status: 'unauthenticated' }
  | { status: 'forbidden' };

/**
 * Independent read of GET /findings/:findingId/latest-observation.
 * Presentation uses the inspection role check. The API remains authoritative.
 * A 401 stays in this section and does not navigate. Creation inspection
 * still navigates to /session-expired on its own 401.
 */
export function FindingLatestObservationSection({
  findingId,
}: {
  findingId: string;
}): ReactElement | null {
  const { organization, api } = useAuth();
  const organizationId = organization?.id ?? null;
  const canRead = organization !== null && canPresentControlledFindingInspection(organization.role);
  const findingIdValid = isCanonicalUuid(findingId);
  const organizationIdRef = useRef(organizationId);
  const findingIdRef = useRef(findingId);
  const generationRef = useRef(0);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [trackedOrganizationId, setTrackedOrganizationId] = useState(organizationId);
  const [trackedFindingId, setTrackedFindingId] = useState(findingId);
  const [view, setView] = useState<LatestObservationView>({ status: 'loading' });

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
      return;
    }
    const requestOrganizationId = organizationId;
    const requestFindingId = findingId;
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    let active = true;

    function isCurrent(): boolean {
      return (
        active &&
        generation === generationRef.current &&
        requestOrganizationId === organizationIdRef.current &&
        requestFindingId === findingIdRef.current
      );
    }

    void (async () => {
      try {
        const reported = await api.inspectControlledFindingLatestObservation(requestFindingId);
        if (!isCurrent()) {
          return;
        }
        const observation = readLatestObservation(reported, requestFindingId);
        if (!isCurrent()) {
          return;
        }
        if (observation === null) {
          setView({ status: 'unavailable' });
          return;
        }
        setView({ status: 'ready', observation });
      } catch (error) {
        if (!isCurrent()) {
          return;
        }
        setView(latestObservationErrorStatus(error));
      }
    })();
    return () => {
      active = false;
      generationRef.current += 1;
    };
  }, [api, canRead, findingId, findingIdValid, organizationId, refreshNonce]);

  if (organization === null || !canRead || !findingIdValid) {
    return null;
  }

  function refresh(): void {
    if (view.status === 'loading' || view.status === 'unauthenticated') {
      return;
    }
    setView({ status: 'loading' });
    setRefreshNonce((value) => value + 1);
  }

  let body: ReactElement;
  if (view.status === 'loading') {
    body = <p role="status">{LATEST_OBSERVATION_LOADING}</p>;
  } else if (view.status === 'ready') {
    body = <LatestObservationResult observation={view.observation} />;
  } else if (view.status === 'not_found') {
    body = <p role="alert">{LATEST_OBSERVATION_NOT_FOUND}</p>;
  } else if (view.status === 'rate_limited') {
    body = <p role="alert">{LATEST_OBSERVATION_RATE_LIMITED}</p>;
  } else if (view.status === 'unauthenticated') {
    body = <p role="alert">{GENERIC_SESSION_EXPIRED}</p>;
  } else if (view.status === 'forbidden') {
    body = <p role="alert">{CONTROLLED_FINDING_UNAVAILABLE}</p>;
  } else {
    body = <p role="alert">{LATEST_OBSERVATION_UNAVAILABLE}</p>;
  }

  return (
    <section
      className="finding-latest-observation"
      aria-labelledby="latest-observation-heading"
      aria-busy={view.status === 'loading'}
    >
      <h2 id="latest-observation-heading">{LATEST_OBSERVATION_HEADING}</h2>
      <button
        type="button"
        onClick={refresh}
        disabled={view.status === 'loading' || view.status === 'unauthenticated'}
      >
        {LATEST_OBSERVATION_REFRESH}
      </button>
      {body}
    </section>
  );
}

function latestObservationErrorStatus(
  error: unknown,
): Exclude<LatestObservationView, { status: 'loading' | 'ready' }> {
  if (!isAuthRequestError(error)) {
    return { status: 'unavailable' };
  }
  if (error.status === 401) {
    return { status: 'unauthenticated' };
  }
  if (error.status === 403) {
    return { status: 'forbidden' };
  }
  if (error.status === 404) {
    return { status: 'not_found' };
  }
  if (error.status === 429 || error.code === 'rate_limited') {
    return { status: 'rate_limited' };
  }
  return { status: 'unavailable' };
}

function LatestObservationResult({
  observation,
}: {
  observation: ControlledFindingLatestObservationResponse;
}): ReactElement {
  const copy = AGGREGATE_COPY[observation.aggregate];
  const sourceLabel =
    observation.observationSource === 'creation' ? 'creation' : 'latest repeated observation';
  const sourceText =
    observation.observationSource === 'creation'
      ? CREATION_SOURCE_TEXT
      : LATEST_REPEATED_SOURCE_TEXT;

  return (
    <div role="status">
      <dl className="asset-summary">
        <div>
          <dt>Observation source</dt>
          <dd>{sourceLabel}</dd>
        </div>
        <div>
          <dt>{OBSERVATION_RECORDED_LABEL}</dt>
          <dd>{observation.observedAt} UTC</dd>
        </div>
      </dl>
      <p>{sourceText}</p>
      <h3>{copy.label}</h3>
      <p>{copy.explanation}</p>
      {observation.evidence.kind === 'occurrence_support' ? (
        <OccurrenceSupport evidence={observation.evidence} />
      ) : (
        <ComponentAbsence evidence={observation.evidence} />
      )}
    </div>
  );
}

function OccurrenceSupport({
  evidence,
}: {
  evidence: Extract<
    ControlledFindingLatestObservationResponse['evidence'],
    { kind: 'occurrence_support' }
  >;
}): ReactElement {
  const versions = evidence.knownVersions.values;
  return (
    <>
      <dl className="asset-summary">
        <div>
          <dt>{SUPPORT_LABELS.affected}</dt>
          <dd>{evidence.affectedSupportCount}</dd>
        </div>
        <div>
          <dt>{SUPPORT_LABELS.unaffected}</dt>
          <dd>{evidence.unaffectedSupportCount}</dd>
        </div>
        <div>
          <dt>{SUPPORT_LABELS.unknown}</dt>
          <dd>{evidence.unknownSupportCount}</dd>
        </div>
        <div>
          <dt>{SUPPORT_LABELS.unknownVersion}</dt>
          <dd>{evidence.unknownVersionSupportCount}</dd>
        </div>
      </dl>
      <h3>{KNOWN_VERSIONS_HEADING}</h3>
      {versions.length === 0 ? (
        <p>{KNOWN_VERSIONS_NONE}</p>
      ) : (
        <ul>
          {versions.map((version, index) => (
            <li key={`${index}:${version}`}>{version}</li>
          ))}
        </ul>
      )}
      <p>{evidence.knownVersions.truncated ? KNOWN_VERSIONS_TRUNCATED : KNOWN_VERSIONS_COMPLETE}</p>
      <p>Omitted distinct versions: {evidence.knownVersions.omittedDistinctCount}</p>
      <p>Distinct known versions: {evidence.knownVersions.distinctCount}</p>
    </>
  );
}

function ComponentAbsence({
  evidence,
}: {
  evidence: Extract<
    ControlledFindingLatestObservationResponse['evidence'],
    { kind: 'component_absence' }
  >;
}): ReactElement {
  return (
    <>
      <dl className="asset-summary">
        <div>
          <dt>{GRAPH_COMPLETENESS_LABEL}</dt>
          <dd>{evidence.graphCompleteness}</dd>
        </div>
      </dl>
      <p>{GRAPH_COMPLETENESS_TEXT}</p>
      {evidence.graphCompleteness === 'no_dependencies' ? <p>{NO_DEPENDENCIES_TEXT}</p> : null}
    </>
  );
}
