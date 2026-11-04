'use client';

import { useEffect, useRef, useState, type ReactElement } from 'react';
import Link from 'next/link';

import type { ProductMatchCandidatesResponse } from '@patchpilot/contracts';

import { useAuth } from '../../../../components/auth-provider';
import { OrganizationRequiredState } from '../../../../components/organization-required';
import { RequireAuth } from '../../../../components/require-auth';
import { SignedInShell } from '../../../../components/signed-in-shell';
import { isAuthRequestError } from '../../../../lib/auth-api';
import { canPresentProductMatchCandidates } from '../../../../lib/product-match-permissions';
import { isCanonicalUuid } from '../../../../lib/resource-id';

const EMPTY_NOTE = 'There is nothing to evaluate for this asset.';
const MISMATCH_NOTE =
  'The ingestion changed and this list was discarded. Reload the page before evaluating again.';
const UNCERTAIN_NOTE = 'The result is uncertain. Reload this page before trying again.';
const DENIED_NOTE = 'Product match candidates are available to an owner.';

type PageState =
  | { status: 'loading' }
  | { status: 'ready'; page: ProductMatchCandidatesResponse }
  | { status: 'empty' }
  | { status: 'denied' }
  | { status: 'not_found' }
  | { status: 'mismatch' }
  | { status: 'error'; message: string };

export function ProductMatchEvaluationsPageClient({ assetId }: { assetId: string }): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <ProductMatchEvaluationsBody assetId={assetId} />
      </SignedInShell>
    </RequireAuth>
  );
}

function ProductMatchEvaluationsBody({ assetId }: { assetId: string }): ReactElement {
  const { organization, api, getCsrfToken } = useAuth();
  const organizationIdRef = useRef<string | null>(organization?.id ?? null);
  const mountedRef = useRef(true);
  const submittingRef = useRef(false);
  const assetIdValid = isCanonicalUuid(assetId);
  const [trackedOrganizationId, setTrackedOrganizationId] = useState(organization?.id ?? null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [cursor, setCursor] = useState<string | null>(null);
  const [view, setView] = useState<PageState>({ status: 'loading' });
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [recorded, setRecorded] = useState(false);

  if ((organization?.id ?? null) !== trackedOrganizationId) {
    setTrackedOrganizationId(organization?.id ?? null);
    setCursor(null);
    setView({ status: 'loading' });
    setPendingId(null);
    setSubmitting(false);
    setUncertain(false);
    setRecorded(false);
    setReloadNonce(0);
  }

  const canReview = organization !== null && canPresentProductMatchCandidates(organization.role);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    organizationIdRef.current = organization?.id ?? null;
  }, [organization?.id]);

  useEffect(() => {
    if (organization === null || !canReview || !assetIdValid) {
      return;
    }
    const organizationId = organization.id;
    let ignore = false;
    void (async () => {
      try {
        const page =
          cursor === null
            ? await api.listProductMatchCandidates(assetId)
            : await api.listProductMatchCandidates(assetId, { cursor });
        if (ignore || !mountedRef.current || organizationId !== organizationIdRef.current) {
          return;
        }
        setView(
          page.candidates.length === 0 && page.nextCursor === null
            ? { status: 'empty' }
            : { status: 'ready', page },
        );
      } catch (error) {
        if (ignore || !mountedRef.current || organizationId !== organizationIdRef.current) {
          return;
        }
        if (isAuthRequestError(error) && error.status === 403) {
          setView({ status: 'denied' });
          return;
        }
        if (isAuthRequestError(error) && error.status === 404) {
          setView({ status: 'not_found' });
          return;
        }
        if (isAuthRequestError(error) && error.code === 'conflict') {
          setView({ status: 'mismatch' });
          return;
        }
        setView({
          status: 'error',
          message: 'Product match candidates are temporarily unavailable.',
        });
      }
    })();
    return () => {
      ignore = true;
    };
  }, [api, assetId, assetIdValid, canReview, cursor, organization, reloadNonce]);

  async function confirmEvaluation(advisoryRevisionId: string): Promise<void> {
    if (submittingRef.current || view.status !== 'ready' || organization === null) {
      return;
    }
    const csrfToken = getCsrfToken();
    if (csrfToken === null || csrfToken.length === 0) {
      setUncertain(true);
      return;
    }
    const discoveredIngestionId = view.page.ingestionId;
    submittingRef.current = true;
    setSubmitting(true);
    setUncertain(false);
    try {
      const response = await api.evaluateProductMatch(assetId, { advisoryRevisionId }, csrfToken);
      if (!mountedRef.current || organization.id !== organizationIdRef.current) {
        return;
      }
      if (response.ingestionId !== discoveredIngestionId) {
        setPendingId(null);
        setView({ status: 'mismatch' });
        return;
      }
      if (response.status === 'evaluated' || response.status === 'already_applied') {
        setRecorded(true);
        setPendingId(null);
        setView({
          status: 'ready',
          page: {
            ...view.page,
            candidates: view.page.candidates.map((candidate) =>
              candidate.advisoryRevisionId === advisoryRevisionId
                ? { ...candidate, evaluationState: 'evaluated' }
                : candidate,
            ),
          },
        });
      }
    } catch (error) {
      if (!mountedRef.current) {
        return;
      }
      if (isAuthRequestError(error) && (error.status === 0 || error.status === 500)) {
        setUncertain(true);
        return;
      }
      setView({
        status: 'error',
        message: 'Product match candidates are temporarily unavailable.',
      });
    } finally {
      submittingRef.current = false;
      if (mountedRef.current) {
        setSubmitting(false);
      }
    }
  }

  if (organization === null) {
    return <OrganizationRequiredState />;
  }
  if (!assetIdValid) {
    return (
      <>
        <h1>Product match evidence</h1>
        <p role="alert">Asset not found.</p>
      </>
    );
  }
  if (!canReview) {
    return (
      <>
        <h1>Product match evidence</h1>
        <p>{DENIED_NOTE}</p>
      </>
    );
  }

  const pending =
    view.status === 'ready'
      ? (view.page.candidates.find((candidate) => candidate.advisoryRevisionId === pendingId) ??
        null)
      : null;

  return (
    <>
      <h1>Product match evidence</h1>
      {view.status === 'loading' ? <p role="status">Loading candidates</p> : null}
      {view.status === 'empty' ? <p>{EMPTY_NOTE}</p> : null}
      {view.status === 'denied' ? <p>{DENIED_NOTE}</p> : null}
      {view.status === 'not_found' ? <p role="alert">Asset not found.</p> : null}
      {view.status === 'mismatch' ? (
        <>
          <p role="status">{MISMATCH_NOTE}</p>
          <button
            type="button"
            onClick={() => {
              setCursor(null);
              setRecorded(false);
              setView({ status: 'loading' });
              setReloadNonce((value) => value + 1);
            }}
          >
            Reload candidates
          </button>
        </>
      ) : null}
      {view.status === 'error' ? <p role="alert">{view.message}</p> : null}
      {uncertain ? <p role="status">{UNCERTAIN_NOTE}</p> : null}
      {recorded ? (
        <p>
          <Link href={`/assets/${assetId}/findings/targets`}>
            Review controlled Finding targets
          </Link>
        </p>
      ) : null}
      {view.status === 'ready' ? (
        <ul>
          {view.page.candidates.map((candidate) => (
            <li key={candidate.advisoryRevisionId}>
              <p>
                {candidate.packageNamespace === null
                  ? candidate.packageName
                  : `${candidate.packageNamespace}/${candidate.packageName}`}
              </p>
              <p>Occurrences in this ingestion: {candidate.matchedOccurrenceCount}</p>
              <p>{candidate.evaluationState === 'evaluated' ? 'Evaluated' : 'Not evaluated'}</p>
              <button type="button" onClick={() => setPendingId(candidate.advisoryRevisionId)}>
                Evaluate
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      {view.status === 'ready' && view.page.nextCursor !== null ? (
        <button type="button" disabled={submitting} onClick={() => setCursor(view.page.nextCursor)}>
          Next candidates
        </button>
      ) : null}
      {pending !== null ? (
        <div role="dialog" aria-labelledby="product-match-confirm-title">
          <h2 id="product-match-confirm-title">Record product match evidence for this package?</h2>
          <p>
            {pending.packageNamespace === null
              ? pending.packageName
              : `${pending.packageNamespace}/${pending.packageName}`}
          </p>
          <button
            type="button"
            disabled={submitting}
            onClick={() => {
              void confirmEvaluation(pending.advisoryRevisionId);
            }}
          >
            Record product match evidence
          </button>
          <button type="button" onClick={() => setPendingId(null)}>
            Cancel
          </button>
        </div>
      ) : null}
    </>
  );
}
