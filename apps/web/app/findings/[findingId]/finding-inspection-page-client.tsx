'use client';

import { useEffect, useLayoutEffect, useRef, useState, type ReactElement } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

import type { ControlledFindingInspectionResponse } from '@patchpilot/contracts';

import { AffectedVersionSummary } from '../../../components/affected-version-summary';
import { useAuth } from '../../../components/auth-provider';
import { OrganizationRequiredState } from '../../../components/organization-required';
import { RequireAuth } from '../../../components/require-auth';
import { SafeRequestIdentifiers } from '../../../components/safe-request-identifiers';
import { SignedInShell } from '../../../components/signed-in-shell';
import { canPresentControlledFindingInspection } from '../../../lib/finding-permissions';
import {
  CONTROLLED_FINDING_UNAVAILABLE,
  FINDING_NOT_FOUND_NOTE,
  LIFECYCLE_UNAVAILABLE_NOTE,
  RATE_LIMITED_NOTE,
  SERVICE_UNAVAILABLE_NOTE,
  UNPROCESSABLE_EVIDENCE_NOTE,
  inspectionApplicabilityText,
  inspectionExplanationText,
  otherOccurrenceClassificationText,
} from '../../../lib/finding-workflow';
import { isCanonicalUuid } from '../../../lib/resource-id';
import { isAuthRequestError } from '../../../lib/auth-api';

type InspectionView =
  | { status: 'loading' }
  | { status: 'ready'; finding: ControlledFindingInspectionResponse }
  | { status: 'forbidden' }
  | { status: 'not_found' }
  | { status: 'rate_limited' }
  | { status: 'unprocessable' }
  | {
      status: 'service_error';
      message: string;
      requestId: string | null;
      correlationId: string | null;
    };

export function FindingInspectionPageClient({ findingId }: { findingId: string }): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <FindingInspectionPageBody findingId={findingId} />
      </SignedInShell>
    </RequireAuth>
  );
}

function FindingInspectionPageBody({ findingId }: { findingId: string }): ReactElement {
  const { organization, api } = useAuth();
  const router = useRouter();
  const routerRef = useRef(router);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const organizationIdRef = useRef<string | null>(organization?.id ?? null);
  const findingIdValid = isCanonicalUuid(findingId);
  const [trackedOrganizationId, setTrackedOrganizationId] = useState(organization?.id ?? null);
  const [view, setView] = useState<InspectionView>({ status: 'loading' });

  if ((organization?.id ?? null) !== trackedOrganizationId) {
    setTrackedOrganizationId(organization?.id ?? null);
    setView({ status: 'loading' });
  }

  const canInspect =
    organization !== null && canPresentControlledFindingInspection(organization.role);

  useLayoutEffect(() => {
    routerRef.current = router;
    organizationIdRef.current = organization?.id ?? null;
  }, [organization?.id, router]);

  useEffect(() => {
    headingRef.current?.focus();
  }, [organization?.id, view.status]);

  useEffect(() => {
    if (organization === null || !canInspect || !findingIdValid) {
      return;
    }
    const organizationId = organization.id;
    let ignore = false;
    void (async () => {
      try {
        const finding = await api.inspectControlledFinding(findingId);
        if (ignore || organizationId !== organizationIdRef.current) {
          return;
        }
        if (finding.findingId !== findingId) {
          setView({ status: 'not_found' });
          return;
        }
        setView({ status: 'ready', finding });
      } catch (error) {
        if (ignore || organizationId !== organizationIdRef.current) {
          return;
        }
        if (isAuthRequestError(error) && error.status === 401) {
          routerRef.current.replace('/session-expired');
          return;
        }
        if (isAuthRequestError(error) && error.status === 403) {
          setView({ status: 'forbidden' });
          return;
        }
        if (isAuthRequestError(error) && error.status === 404) {
          setView({ status: 'not_found' });
          return;
        }
        if (isAuthRequestError(error) && (error.status === 429 || error.code === 'rate_limited')) {
          setView({ status: 'rate_limited' });
          return;
        }
        if (
          isAuthRequestError(error) &&
          error.status === 422 &&
          error.code === 'unprocessable_evidence'
        ) {
          setView({ status: 'unprocessable' });
          return;
        }
        setView({
          status: 'service_error',
          message: SERVICE_UNAVAILABLE_NOTE,
          requestId: isAuthRequestError(error) ? (error.requestId ?? null) : null,
          correlationId: isAuthRequestError(error) ? (error.correlationId ?? null) : null,
        });
      }
    })();
    return () => {
      ignore = true;
    };
  }, [api, canInspect, findingId, findingIdValid, organization]);

  if (organization === null) {
    return <OrganizationRequiredState />;
  }

  let content: ReactElement;
  if (!canInspect || view.status === 'forbidden') {
    content = <p role="alert">{CONTROLLED_FINDING_UNAVAILABLE}</p>;
  } else if (!findingIdValid || view.status === 'not_found') {
    content = <p role="alert">{FINDING_NOT_FOUND_NOTE}</p>;
  } else if (view.status === 'loading') {
    content = <p role="status">Loading Finding</p>;
  } else if (view.status === 'rate_limited') {
    content = <p role="alert">{RATE_LIMITED_NOTE}</p>;
  } else if (view.status === 'unprocessable') {
    content = <p role="alert">{UNPROCESSABLE_EVIDENCE_NOTE}</p>;
  } else if (view.status === 'service_error') {
    content = (
      <div role="alert">
        <p>{view.message}</p>
        <SafeRequestIdentifiers requestId={view.requestId} correlationId={view.correlationId} />
      </div>
    );
  } else {
    content = <FindingProjection finding={view.finding} />;
  }

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Finding
      </h1>
      {content}
    </main>
  );
}

function FindingProjection({
  finding,
}: {
  finding: ControlledFindingInspectionResponse;
}): ReactElement {
  const assetHref = isCanonicalUuid(finding.asset.id) ? `/assets/${finding.asset.id}` : null;
  const targetsHref = assetHref === null ? null : `/assets/${finding.asset.id}/findings/targets`;

  return (
    <>
      <dl className="asset-summary">
        <div>
          <dt>Asset</dt>
          <dd>{finding.asset.displayName}</dd>
        </div>
        <div>
          <dt>Component ecosystem</dt>
          <dd>{finding.component.ecosystem ?? 'None'}</dd>
        </div>
        <div>
          <dt>Component namespace</dt>
          <dd>{finding.component.namespace ?? 'None'}</dd>
        </div>
        <div>
          <dt>Component name</dt>
          <dd>{finding.component.name}</dd>
        </div>
        <div>
          <dt>Vulnerability public identifier</dt>
          <dd>{finding.vulnerability.publicId}</dd>
        </div>
        <div>
          <dt>State</dt>
          <dd>Open</dd>
        </div>
        <div>
          <dt>Affected occurrence count</dt>
          <dd>{finding.affectedOccurrenceCount}</dd>
        </div>
        <div>
          <dt>Other occurrence count</dt>
          <dd>{finding.otherOccurrenceCount}</dd>
        </div>
        <div>
          <dt>Other occurrences</dt>
          <dd>{otherOccurrenceClassificationText(finding.otherOccurrenceClassification)}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{finding.createdAt} UTC</dd>
        </div>
        <div>
          <dt>Creation policy</dt>
          <dd>
            {finding.creationObservationPolicy.policyId} version{' '}
            {finding.creationObservationPolicy.policyVersion}
          </dd>
        </div>
        <div>
          <dt>Applicability</dt>
          <dd>{inspectionApplicabilityText(finding.creationEvidenceApplicability)}</dd>
        </div>
      </dl>
      <AffectedVersionSummary summary={finding.affectedVersions} />
      {finding.explanationCodes.length === 0 ? null : (
        <ul>
          {finding.explanationCodes.map((code) => (
            <li key={code}>{inspectionExplanationText(code)}</li>
          ))}
        </ul>
      )}
      <p>{LIFECYCLE_UNAVAILABLE_NOTE}</p>
      <nav aria-label="Finding context">
        {assetHref === null ? null : <Link href={assetHref}>Open asset</Link>}{' '}
        {targetsHref === null ? null : (
          <Link href={targetsHref}>Review controlled Finding targets</Link>
        )}
      </nav>
    </>
  );
}
