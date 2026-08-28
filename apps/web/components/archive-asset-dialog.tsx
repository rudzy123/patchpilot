'use client';

import { useEffect, useRef, type ReactElement } from 'react';

export function ArchiveAssetDialog({
  assetName,
  submitting,
  onCancel,
  onConfirm,
}: {
  assetName: string;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): ReactElement {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape' && !submitting) {
        onCancel();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [onCancel, submitting]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="archive-asset-title"
      className="asset-dialog"
    >
      <h2 id="archive-asset-title" ref={headingRef} tabIndex={-1}>
        Archive this asset?
      </h2>
      <p>
        Archive <span>{assetName}</span>? The asset will no longer be active. Evidence is kept.
      </p>
      <div className="asset-actions">
        <button type="button" onClick={onCancel} disabled={submitting}>
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={submitting}
          aria-busy={submitting}
        >
          {submitting ? 'Archiving' : 'Archive asset'}
        </button>
      </div>
    </div>
  );
}
