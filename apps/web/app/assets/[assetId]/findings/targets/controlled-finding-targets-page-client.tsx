'use client';

import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactElement,
  type RefObject,
} from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

import type { ControlledFindingDiscoveryResponse } from '@patchpilot/contracts';

import { AffectedVersionSummary } from '../../../../../components/affected-version-summary';
import { useAuth } from '../../../../../components/auth-provider';
import { ControlledFindingConfirmationDialog } from '../../../../../components/controlled-finding-confirmation-dialog';
import { OrganizationRequiredState } from '../../../../../components/organization-required';
import { RequireAuth } from '../../../../../components/require-auth';
import { SafeRequestIdentifiers } from '../../../../../components/safe-request-identifiers';
import { SignedInShell } from '../../../../../components/signed-in-shell';
import {
  canPresentControlledFindingCreation,
  canPresentControlledFindingTargets,
} from '../../../../../lib/finding-permissions';
import {
  ACKNOWLEDGEMENT_MISMATCH_NOTE,
  ALREADY_APPLIED_NOTE,
  ASSET_NOT_FOUND_NOTE,
  CONTROLLED_FINDING_UNAVAILABLE,
  CREATED_NOTE,
  CREATION_REQUIRES_OWNER,
  EMPTY_TARGETS_NOTE,
  EXISTING_FINDING_NOTE,
  EXACT_REPLAY_OWNER_NOTE,
  FINDING_NOT_FOUND_NOTE,
  OVERSIZED_TARGETS_NOTE,
  RATE_LIMITED_NOTE,
  STALE_CURSOR_NOTE,
  STALE_EVIDENCE_GUIDANCE,
  STALE_EVIDENCE_SUMMARY,
  TARGETS_UNAVAILABLE_NOTE,
  UNPROCESSABLE_EVIDENCE_NOTE,
  classifyCreationFailure,
  discoveryExplanationText,
  readCreationCsrf,
  requestIdentifiers,
  snapshotAcknowledgement,
  type AcknowledgedDiscoveryCandidate,
} from '../../../../../lib/finding-workflow';
import { isCanonicalUuid } from '../../../../../lib/resource-id';
import { isAuthRequestError } from '../../../../../lib/auth-api';

type TargetsView =
  | { status: 'loading' }
  | { status: 'ready'; page: ControlledFindingDiscoveryResponse }
  | { status: 'forbidden' }
  | { status: 'asset_not_found' }
  | { status: 'rate_limited' }
  | {
      status: 'service_error';
      message: string;
      requestId: string | null;
      correlationId: string | null;
    };

type CreationOutcome =
  | { kind: 'created'; findingId: string }
  | { kind: 'already_applied'; findingId: string }
  | { kind: 'stale' }
  | { kind: 'unprocessable' }
  | { kind: 'uncertain'; requestId: string | null; correlationId: string | null }
  | { kind: 'rate_limited' }
  | { kind: 'not_found' }
  | {
      kind: 'bounded';
      message: string;
      requestId: string | null;
      correlationId: string | null;
    };

type ConfirmationState = {
  candidate: AcknowledgedDiscoveryCandidate;
  organizationId: string;
};

export function ControlledFindingTargetsPageClient({ assetId }: { assetId: string }): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <ControlledFindingTargetsPageBody assetId={assetId} />
      </SignedInShell>
    </RequireAuth>
  );
}

function ControlledFindingTargetsPageBody({ assetId }: { assetId: string }): ReactElement {
  const { organization, api, getCsrfToken } = useAuth();
  const router = useRouter();
  const routerRef = useRef(router);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const invokerRef = useRef<HTMLButtonElement | null>(null);
  const organizationIdRef = useRef<string | null>(organization?.id ?? null);
  const submittingRef = useRef(false);
  const mountedRef = useRef(true);
  const returnFocusRef = useRef(false);
  const outcomeRegionRef = useRef<HTMLDivElement | null>(null);
  const assetIdValid = isCanonicalUuid(assetId);

  const [trackedOrganizationId, setTrackedOrganizationId] = useState(organization?.id ?? null);
  const [cursorStack, setCursorStack] = useState<Array<string | null>>([null]);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [view, setView] = useState<TargetsView>({ status: 'loading' });
  const [assetName, setAssetName] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<ConfirmationState | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [outcome, setOutcome] = useState<CreationOutcome | null>(null);
  const [staleForCreation, setStaleForCreation] = useState(false);
  const [cursorNotice, setCursorNotice] = useState(false);
  const [workflowError, setWorkflowError] = useState<string | null>(null);

  if ((organization?.id ?? null) !== trackedOrganizationId) {
    setTrackedOrganizationId(organization?.id ?? null);
    setCursorStack([null]);
    setView({ status: 'loading' });
    setAssetName(null);
    setConfirmation(null);
    setSubmitting(false);
    setOutcome(null);
    setStaleForCreation(false);
    setCursorNotice(false);
    setWorkflowError(null);
  }

  const cursorKey = cursorStack[cursorStack.length - 1] ?? null;
  const canReview = organization !== null && canPresentControlledFindingTargets(organization.role);
  const canCreate = organization !== null && canPresentControlledFindingCreation(organization.role);

  useLayoutEffect(() => {
    routerRef.current = router;
    organizationIdRef.current = organization?.id ?? null;
    submittingRef.current = submitting;
  }, [organization?.id, router, submitting]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    headingRef.current?.focus();
  }, [organization?.id]);

  useEffect(() => {
    if (confirmation !== null) {
      return;
    }
    if (returnFocusRef.current) {
      returnFocusRef.current = false;
      invokerRef.current?.focus();
      return;
    }
    if (outcome !== null && outcome.kind !== 'uncertain') {
      outcomeRegionRef.current?.focus();
    }
  }, [confirmation, outcome]);

  useEffect(() => {
    if (organization === null || !canReview || !assetIdValid) {
      return;
    }
    const organizationId = organization.id;
    let ignore = false;
    void (async () => {
      const [assetResult, pageResult] = await Promise.allSettled([
        api.getAsset(assetId),
        cursorKey === null
          ? api.listControlledFindingTargets(assetId)
          : api.listControlledFindingTargets(assetId, { cursor: cursorKey }),
      ]);
      if (ignore || !mountedRef.current || organizationId !== organizationIdRef.current) {
        return;
      }

      const assetError = assetResult.status === 'rejected' ? assetResult.reason : null;
      const pageError = pageResult.status === 'rejected' ? pageResult.reason : null;
      if (isUnauthorized(assetError) || isUnauthorized(pageError)) {
        routerRef.current.replace('/session-expired');
        return;
      }
      if (isForbidden(assetError) || isForbidden(pageError)) {
        setAssetName(null);
        setView({ status: 'forbidden' });
        return;
      }
      if (isNotFound(assetError) || isNotFound(pageError)) {
        setAssetName(null);
        setView({ status: 'asset_not_found' });
        return;
      }
      if (
        isAuthRequestError(pageError) &&
        pageError.status === 409 &&
        pageError.code === 'conflict'
      ) {
        setConfirmation(null);
        setOutcome(null);
        setCursorNotice(true);
        if (cursorKey !== null) {
          setCursorStack([null]);
          return;
        }
        setView({
          status: 'service_error',
          message: STALE_CURSOR_NOTE,
          ...requestIdentifiers(pageError),
        });
        return;
      }
      if (isRateLimited(assetError) || isRateLimited(pageError)) {
        setView({ status: 'rate_limited' });
        return;
      }
      if (pageError !== null || assetError !== null) {
        const reported = isAuthRequestError(pageError)
          ? pageError
          : isAuthRequestError(assetError)
            ? assetError
            : null;
        setView({
          status: 'service_error',
          message: TARGETS_UNAVAILABLE_NOTE,
          requestId: reported?.requestId ?? null,
          correlationId: reported?.correlationId ?? null,
        });
        return;
      }
      if (assetResult.status !== 'fulfilled' || pageResult.status !== 'fulfilled') {
        return;
      }
      setAssetName(assetResult.value.id === assetId ? assetResult.value.name : null);
      setView({ status: 'ready', page: pageResult.value });
    })();
    return () => {
      ignore = true;
    };
  }, [api, assetId, assetIdValid, canReview, cursorKey, organization, reloadNonce]);

  if (organization === null) {
    return <OrganizationRequiredState />;
  }

  function discardAcknowledgement(): void {
    setConfirmation(null);
  }

  function refreshTargets(): void {
    if (submittingRef.current) {
      return;
    }
    discardAcknowledgement();
    setOutcome(null);
    setStaleForCreation(false);
    setCursorNotice(false);
    setWorkflowError(null);
    setView({ status: 'loading' });
    setCursorStack([null]);
    setReloadNonce((value) => value + 1);
  }

  function changePage(nextStack: Array<string | null>): void {
    if (submittingRef.current) {
      return;
    }
    discardAcknowledgement();
    setOutcome(null);
    setStaleForCreation(false);
    setCursorNotice(false);
    setWorkflowError(null);
    setView({ status: 'loading' });
    setCursorStack(nextStack);
  }

  function reviewCandidate(
    candidate: AcknowledgedDiscoveryCandidate,
    invoker: HTMLButtonElement,
  ): void {
    if (!canCreate || staleForCreation || submittingRef.current || confirmation !== null) {
      return;
    }
    if (candidate.acknowledgement.assetId !== assetId) {
      discardAcknowledgement();
      setWorkflowError(ACKNOWLEDGEMENT_MISMATCH_NOTE);
      return;
    }
    invokerRef.current = invoker;
    setWorkflowError(null);
    setOutcome(null);
    setConfirmation({
      candidate: {
        ...candidate,
        acknowledgement: snapshotAcknowledgement(candidate.acknowledgement),
      },
      organizationId: organization.id,
    });
  }

  function cancelConfirmation(): void {
    if (submittingRef.current) {
      return;
    }
    returnFocusRef.current = true;
    discardAcknowledgement();
    setOutcome(null);
  }

  async function confirmCreation(): Promise<void> {
    if (confirmation === null || submittingRef.current || organization === null) {
      return;
    }
    if (
      confirmation.organizationId !== organization.id ||
      confirmation.organizationId !== organizationIdRef.current
    ) {
      discardAcknowledgement();
      setOutcome(null);
      return;
    }
    const acknowledgement = confirmation.candidate.acknowledgement;
    if (acknowledgement.assetId !== assetId) {
      discardAcknowledgement();
      setWorkflowError(ACKNOWLEDGEMENT_MISMATCH_NOTE);
      return;
    }
    const csrfToken = readCreationCsrf(getCsrfToken());
    if (csrfToken === 'session_expired') {
      routerRef.current.replace('/session-expired');
      return;
    }
    const startedOrganizationId = organization.id;
    submittingRef.current = true;
    setSubmitting(true);
    try {
      const result = await api.createControlledFinding(acknowledgement, csrfToken);
      if (!mountedRef.current || startedOrganizationId !== organizationIdRef.current) {
        return;
      }
      discardAcknowledgement();
      setStaleForCreation(false);
      setOutcome(
        result.status === 'created'
          ? { kind: 'created', findingId: result.findingId }
          : { kind: 'already_applied', findingId: result.findingId },
      );
    } catch (error) {
      if (!mountedRef.current || startedOrganizationId !== organizationIdRef.current) {
        return;
      }
      const kind = classifyCreationFailure(error);
      if (kind === 'expired') {
        routerRef.current.replace('/session-expired');
        return;
      }
      if (kind === 'unavailable') {
        discardAcknowledgement();
        setAssetName(null);
        setView({ status: 'forbidden' });
        setOutcome(null);
        return;
      }
      if (kind === 'not_found') {
        discardAcknowledgement();
        setOutcome({ kind: 'not_found' });
        return;
      }
      if (kind === 'rate_limited') {
        discardAcknowledgement();
        setOutcome({ kind: 'rate_limited' });
        return;
      }
      if (kind === 'stale') {
        discardAcknowledgement();
        setStaleForCreation(true);
        setOutcome({ kind: 'stale' });
        return;
      }
      if (kind === 'unprocessable') {
        discardAcknowledgement();
        setOutcome({ kind: 'unprocessable' });
        return;
      }
      if (kind === 'uncertain') {
        const identifiers = isAuthRequestError(error)
          ? requestIdentifiers(error)
          : { requestId: null, correlationId: null };
        setOutcome({ kind: 'uncertain', ...identifiers });
        return;
      }
      discardAcknowledgement();
      setOutcome({
        kind: 'bounded',
        message: isAuthRequestError(error) ? error.message : TARGETS_UNAVAILABLE_NOTE,
        ...(isAuthRequestError(error)
          ? requestIdentifiers(error)
          : { requestId: null, correlationId: null }),
      });
    } finally {
      submittingRef.current = false;
      if (mountedRef.current) {
        setSubmitting(false);
      }
    }
  }

  const creationLocked =
    staleForCreation || outcome?.kind === 'created' || outcome?.kind === 'already_applied';
  const nextCursor = view.status === 'ready' ? view.page.nextCursor : null;

  let content: ReactElement;
  if (!canReview || view.status === 'forbidden') {
    content = <p role="alert">{CONTROLLED_FINDING_UNAVAILABLE}</p>;
  } else if (!assetIdValid || view.status === 'asset_not_found') {
    content = <p role="alert">{ASSET_NOT_FOUND_NOTE}</p>;
  } else if (view.status === 'loading') {
    content = <p role="status">Loading controlled Finding targets</p>;
  } else if (view.status === 'rate_limited') {
    content = <p role="alert">{RATE_LIMITED_NOTE}</p>;
  } else if (view.status === 'service_error') {
    content = (
      <div role="alert">
        <p>{view.message}</p>
        <SafeRequestIdentifiers requestId={view.requestId} correlationId={view.correlationId} />
      </div>
    );
  } else {
    content = (
      <>
        {cursorNotice ? (
          <p role="alert">{STALE_CURSOR_NOTE} Targets were loaded again from the beginning.</p>
        ) : null}
        {workflowError !== null ? <p role="alert">{workflowError}</p> : null}
        <CreationOutcomeNotice
          outcome={outcome}
          onRefresh={refreshTargets}
          regionRef={outcomeRegionRef}
        />
        {view.page.candidates.length === 0 ? <p>{EMPTY_TARGETS_NOTE}</p> : null}
        {view.page.oversizedCandidateCount > 0 ? (
          <p>
            {OVERSIZED_TARGETS_NOTE} Omitted targets: {view.page.oversizedCandidateCount}
          </p>
        ) : null}
        {view.page.candidates.map((candidate) => (
          <CandidateArticle
            key={`${candidate.classification}:${candidate.componentId}:${candidate.vulnerabilityId}`}
            candidate={candidate}
            canCreate={canCreate}
            creationLocked={creationLocked}
            onReview={reviewCandidate}
          />
        ))}
        <div className="asset-actions">
          <button
            type="button"
            onClick={() => {
              changePage(cursorStack.slice(0, -1));
            }}
            disabled={cursorStack.length <= 1 || submitting}
          >
            Previous page
          </button>
          <button
            type="button"
            onClick={() => {
              if (nextCursor === null) {
                return;
              }
              changePage([...cursorStack, nextCursor]);
            }}
            disabled={nextCursor === null || submitting}
          >
            Next page
          </button>
        </div>
        {confirmation !== null ? (
          <ControlledFindingConfirmationDialog
            assetName={assetName}
            candidate={confirmation.candidate}
            submitting={submitting}
            uncertainty={outcome?.kind === 'uncertain'}
            requestId={outcome?.kind === 'uncertain' ? outcome.requestId : null}
            correlationId={outcome?.kind === 'uncertain' ? outcome.correlationId : null}
            onCancel={cancelConfirmation}
            onConfirm={() => {
              void confirmCreation();
            }}
            onRefresh={refreshTargets}
          />
        ) : null}
      </>
    );
  }

  return (
    <main>
      {assetIdValid ? (
        <nav aria-label="Asset">
          <Link href="/assets">Assets</Link>{' '}
          <Link href={`/assets/${assetId}`}>{assetName ?? 'Selected asset'}</Link>
        </nav>
      ) : (
        <p>
          <Link href="/assets">Assets</Link>
        </p>
      )}
      <h1 ref={headingRef} tabIndex={-1}>
        Controlled Finding targets
      </h1>
      {content}
    </main>
  );
}

function CreationOutcomeNotice({
  outcome,
  onRefresh,
  regionRef,
}: {
  outcome: CreationOutcome | null;
  onRefresh: () => void;
  regionRef: RefObject<HTMLDivElement | null>;
}): ReactElement | null {
  if (outcome === null || outcome.kind === 'uncertain') {
    return null;
  }
  if (outcome.kind === 'created' || outcome.kind === 'already_applied') {
    return (
      <div ref={regionRef} className="finding-outcome" role="status" tabIndex={-1}>
        <p>{outcome.kind === 'created' ? CREATED_NOTE : ALREADY_APPLIED_NOTE}</p>
        {isCanonicalUuid(outcome.findingId) ? (
          <p>
            <Link href={`/findings/${outcome.findingId}`}>Open Finding</Link>
          </p>
        ) : null}
      </div>
    );
  }
  if (outcome.kind === 'stale') {
    return (
      <div ref={regionRef} className="finding-outcome" role="alert" tabIndex={-1}>
        <p>{STALE_EVIDENCE_SUMMARY}</p>
        <p>{STALE_EVIDENCE_GUIDANCE}</p>
        <button type="button" onClick={onRefresh}>
          Refresh targets
        </button>
      </div>
    );
  }
  if (outcome.kind === 'unprocessable') {
    return (
      <div ref={regionRef} className="finding-outcome" role="alert" tabIndex={-1}>
        {UNPROCESSABLE_EVIDENCE_NOTE}
      </div>
    );
  }
  if (outcome.kind === 'rate_limited') {
    return (
      <div ref={regionRef} className="finding-outcome" role="alert" tabIndex={-1}>
        {RATE_LIMITED_NOTE}
      </div>
    );
  }
  if (outcome.kind === 'not_found') {
    return (
      <div ref={regionRef} className="finding-outcome" role="alert" tabIndex={-1}>
        {FINDING_NOT_FOUND_NOTE}
      </div>
    );
  }
  return (
    <div ref={regionRef} className="finding-outcome" role="alert" tabIndex={-1}>
      <p>{outcome.message}</p>
      <SafeRequestIdentifiers requestId={outcome.requestId} correlationId={outcome.correlationId} />
    </div>
  );
}

function CandidateArticle({
  candidate,
  canCreate,
  creationLocked,
  onReview,
}: {
  candidate: ControlledFindingDiscoveryResponse['candidates'][number];
  canCreate: boolean;
  creationLocked: boolean;
  onReview: (candidate: AcknowledgedDiscoveryCandidate, invoker: HTMLButtonElement) => void;
}): ReactElement {
  const headingId = useId();
  const heading =
    candidate.classification === 'eligible_for_creation'
      ? 'Eligible for creation'
      : candidate.classification === 'exact_replay_available'
        ? 'Exact replay available'
        : 'Finding already recorded';
  const acknowledged = candidate.classification === 'existing_finding' ? null : candidate;

  return (
    <article aria-labelledby={headingId} className="finding-candidate">
      <h2 id={headingId}>{heading}</h2>
      <p>
        Component identifier: <span>{candidate.componentId}</span>
      </p>
      <p>
        Vulnerability public identifier: <span>{candidate.vulnerabilityPublicId}</span>
      </p>
      <p>Affected occurrence count: {candidate.affectedOccurrenceCount}</p>
      <AffectedVersionSummary summary={candidate.affectedVersions} />
      <p>Other occurrence count: {candidate.otherOccurrenceCount}</p>
      {candidate.explanationCodes.length === 0 ? null : (
        <ul>
          {candidate.explanationCodes.map((code) => (
            <li key={code}>{discoveryExplanationText(code)}</li>
          ))}
        </ul>
      )}
      {candidate.classification === 'existing_finding' ? <p>{EXISTING_FINDING_NOTE}</p> : null}
      {acknowledged !== null ? (
        <EvidenceDisclosure ids={acknowledged.acknowledgement.expectedProductMatchEvidenceIds} />
      ) : null}
      {acknowledged !== null && canCreate && !creationLocked ? (
        <>
          {acknowledged.classification === 'exact_replay_available' ? (
            <p>{EXACT_REPLAY_OWNER_NOTE}</p>
          ) : null}
          <button
            type="button"
            onClick={(event) => {
              onReview(acknowledged, event.currentTarget);
            }}
          >
            {acknowledged.classification === 'exact_replay_available'
              ? `Review exact replay for ${acknowledged.vulnerabilityPublicId}`
              : `Review creation for ${acknowledged.vulnerabilityPublicId}`}
          </button>
        </>
      ) : null}
      {acknowledged !== null && !canCreate ? <p>{CREATION_REQUIRES_OWNER}</p> : null}
    </article>
  );
}

function EvidenceDisclosure({ ids }: { ids: readonly string[] }): ReactElement {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();
  return (
    <div>
      <p>Evidence records in this acknowledgement: {ids.length}</p>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => {
          setExpanded((current) => !current);
        }}
      >
        {expanded ? 'Hide evidence identifiers' : 'Show evidence identifiers'}
      </button>
      {expanded ? (
        <ol id={panelId}>
          {ids.map((evidenceId) => (
            <li key={evidenceId}>{evidenceId}</li>
          ))}
        </ol>
      ) : null}
    </div>
  );
}

function isUnauthorized(error: unknown): boolean {
  return isAuthRequestError(error) && error.status === 401;
}

function isForbidden(error: unknown): boolean {
  return isAuthRequestError(error) && error.status === 403;
}

function isNotFound(error: unknown): boolean {
  return isAuthRequestError(error) && error.status === 404;
}

function isRateLimited(error: unknown): boolean {
  return isAuthRequestError(error) && (error.status === 429 || error.code === 'rate_limited');
}
