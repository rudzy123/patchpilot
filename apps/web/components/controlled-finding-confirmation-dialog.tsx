'use client';

import { useEffect, useId, useLayoutEffect, useRef, type ReactElement } from 'react';

import { AffectedVersionSummary } from './affected-version-summary';
import { SafeRequestIdentifiers } from './safe-request-identifiers';
import {
  COMMIT_UNCERTAINTY_NOTE,
  confirmationActionLabel,
  type AcknowledgedDiscoveryCandidate,
} from '../lib/finding-workflow';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export function ControlledFindingConfirmationDialog({
  assetName,
  candidate,
  submitting,
  uncertainty,
  requestId,
  correlationId,
  onCancel,
  onConfirm,
  onRefresh,
}: {
  assetName: string | null;
  candidate: AcknowledgedDiscoveryCandidate;
  submitting: boolean;
  uncertainty: boolean;
  requestId: string | null;
  correlationId: string | null;
  onCancel: () => void;
  onConfirm: () => void;
  onRefresh: () => void;
}): ReactElement {
  const titleId = useId();
  const descriptionId = useId();
  const uncertaintyId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const submittingRef = useRef(submitting);
  const actionLabel = confirmationActionLabel(candidate);
  const acknowledgement = candidate.acknowledgement;

  useLayoutEffect(() => {
    submittingRef.current = submitting;
  }, [submitting]);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    if (submitting) {
      headingRef.current?.focus();
    }
  }, [submitting]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) {
      return;
    }
    return inertOutside(dialog);
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        if (!submittingRef.current) {
          event.preventDefault();
          onCancel();
        }
        return;
      }
      if (event.key !== 'Tab') {
        return;
      }
      const node = dialogRef.current;
      if (node === null) {
        return;
      }
      const focusable = [...node.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)].filter(
        (element) => element.tabIndex !== -1,
      );
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (first === undefined || last === undefined) {
        event.preventDefault();
        return;
      }
      const active = document.activeElement;
      if (event.shiftKey) {
        if (active === first || active === headingRef.current || !node.contains(active)) {
          event.preventDefault();
          last.focus();
        }
        return;
      }
      if (active === last || !node.contains(active)) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [onCancel]);

  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={uncertainty ? `${descriptionId} ${uncertaintyId}` : descriptionId}
      className="asset-dialog"
    >
      <h2 id={titleId} ref={headingRef} tabIndex={-1}>
        {actionLabel}
      </h2>
      <div id={descriptionId}>
        <p>
          Asset name: <span>{assetName ?? 'Unavailable'}</span>
        </p>
        <p>
          Asset identifier: <span>{acknowledgement.assetId}</span>
        </p>
        <p>
          Component identifier: <span>{acknowledgement.componentId}</span>
        </p>
        <p>
          Vulnerability identifier: <span>{acknowledgement.vulnerabilityId}</span>
        </p>
        <p>
          Vulnerability public identifier: <span>{candidate.vulnerabilityPublicId}</span>
        </p>
        <p>Affected occurrence count: {candidate.affectedOccurrenceCount}</p>
        <AffectedVersionSummary summary={candidate.affectedVersions} />
        <h3>Evidence identifiers</h3>
        <ol>
          {acknowledgement.expectedProductMatchEvidenceIds.map((evidenceId) => (
            <li key={evidenceId}>{evidenceId}</li>
          ))}
        </ol>
        <p>This acknowledgement is a point-in-time record.</p>
        <p>The server revalidates this evidence set when it records a Finding.</p>
        <p>If the evidence has changed, the server refuses the request and records nothing.</p>
        {candidate.classification === 'exact_replay_available' ? (
          <p>
            A second Finding should not be created. The server may return the existing Finding when
            the lineage matches.
          </p>
        ) : null}
      </div>
      {uncertainty ? (
        <div id={uncertaintyId} role="alert">
          <p>{COMMIT_UNCERTAINTY_NOTE}</p>
          <SafeRequestIdentifiers requestId={requestId} correlationId={correlationId} />
        </div>
      ) : null}
      <div className="asset-actions">
        <button type="button" onClick={onCancel} disabled={submitting}>
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={submitting}
          aria-busy={submitting}
          {...(uncertainty ? { 'aria-describedby': uncertaintyId } : {})}
        >
          {actionLabel}
        </button>
        {uncertainty ? (
          <button type="button" onClick={onRefresh} disabled={submitting}>
            Refresh targets
          </button>
        ) : null}
      </div>
    </div>
  );
}

function inertOutside(dialog: HTMLElement): () => void {
  const changed: HTMLElement[] = [];
  let current: HTMLElement = dialog;
  let parent: HTMLElement | null = current.parentElement;
  while (parent !== null) {
    for (const child of parent.children) {
      if (!(child instanceof HTMLElement) || child === current || child.hasAttribute('inert')) {
        continue;
      }
      child.setAttribute('inert', '');
      changed.push(child);
    }
    current = parent;
    parent = current.parentElement;
  }
  return () => {
    for (const element of changed) {
      element.removeAttribute('inert');
    }
  };
}
