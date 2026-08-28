'use client';

import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';
import Link from 'next/link';

import type { AssetDetail } from '@patchpilot/contracts';

import { ArchiveAssetDialog } from '../../../components/archive-asset-dialog';
import { AssetForm } from '../../../components/asset-form';
import { OrganizationRequiredState } from '../../../components/organization-required';
import { RequireAuth } from '../../../components/require-auth';
import { SignedInShell } from '../../../components/signed-in-shell';
import { useAuth } from '../../../components/auth-provider';
import {
  ASSET_TYPE_OPTIONS,
  BUSINESS_CRITICALITY_OPTIONS,
  DATA_CLASSIFICATION_OPTIONS,
  INTERNET_EXPOSURE_OPTIONS,
  catalogLabel,
  valuesFromAsset,
} from '../../../lib/asset-form';
import { canMutateAssets } from '../../../lib/asset-permissions';
import {
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
  ORGANIZATION_CONTEXT_REQUIRED,
  isAuthRequestError,
} from '../../../lib/auth-api';

const ASSET_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function AssetDetailPageClient({ assetId }: { assetId: string }): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <AssetDetailPageBody assetId={assetId} />
      </SignedInShell>
    </RequireAuth>
  );
}

function AssetDetailPageBody({ assetId }: { assetId: string }): ReactElement {
  const { organization, api, getCsrfToken } = useAuth();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [confirmArchive, setConfirmArchive] = useState(false);
  const [archiving, setArchiving] = useState(false);
  const archiveInFlightRef = useRef(false);

  const assetIdValid = ASSET_ID_PATTERN.test(assetId);

  const loadAsset = useCallback(async (): Promise<AssetDetail | undefined> => {
    const loaded = await api.getAsset(assetId);
    setAsset(loaded);
    setStatus('ready');
    setErrorMessage(null);
    return loaded;
  }, [api, assetId]);

  useEffect(() => {
    if (confirmArchive) {
      return;
    }
    headingRef.current?.focus();
  }, [asset?.id, confirmArchive, organization, status]);

  useEffect(() => {
    if (organization === null || !assetIdValid) {
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const loaded = await api.getAsset(assetId);
        if (cancelled) {
          return;
        }
        setAsset(loaded);
        setStatus('ready');
        setErrorMessage(null);
      } catch (error) {
        if (cancelled) {
          return;
        }
        setStatus('error');
        setErrorMessage(mapDetailError(error));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, assetId, assetIdValid, organization]);

  if (organization === null) {
    return <OrganizationRequiredState />;
  }

  if (!assetIdValid) {
    return (
      <main>
        <p>
          <Link href="/assets">Back to assets</Link>
        </p>
        <h1 ref={headingRef} tabIndex={-1}>
          Asset
        </h1>
        <p role="alert">Asset not found.</p>
      </main>
    );
  }

  const canMutate = canMutateAssets(organization.role);
  const archived = asset?.lifecycleStatus === 'archived';
  const readOnly = !canMutate || archived;

  async function confirmArchiveAction(): Promise<void> {
    if (asset === null || archiveInFlightRef.current) {
      return;
    }
    const csrfToken = getCsrfToken();
    if (csrfToken === null) {
      setErrorMessage(GENERIC_SESSION_EXPIRED);
      return;
    }
    archiveInFlightRef.current = true;
    setArchiving(true);
    try {
      const archivedAsset = await api.archiveAsset(
        asset.id,
        { expectedVersion: asset.version },
        csrfToken,
      );
      setAsset(archivedAsset);
      setConfirmArchive(false);
    } catch (error) {
      if (isAuthRequestError(error) && error.code === 'conflict') {
        await loadAsset();
        setErrorMessage(error.message);
        setConfirmArchive(false);
        return;
      }
      setErrorMessage(mapDetailError(error));
    } finally {
      archiveInFlightRef.current = false;
      setArchiving(false);
    }
  }

  return (
    <main>
        <p>
          <Link href="/assets">Back to assets</Link>
        </p>
      {status === 'loading' ? (
        <>
          <h1 ref={headingRef} tabIndex={-1}>
            Asset
          </h1>
          <p role="status">Loading asset</p>
        </>
      ) : null}
      {status === 'error' ? (
        <>
          <h1 ref={headingRef} tabIndex={-1}>
            Asset
          </h1>
          <p role="alert">{errorMessage}</p>
        </>
      ) : null}
      {status === 'ready' && asset !== null ? (
        <>
          <h1 ref={headingRef} tabIndex={-1}>
            {asset.name}
          </h1>
          {archived ? <p role="status">This asset is archived.</p> : null}
          {!canMutate ? (
            <p>You can view assets in this organization. Changes require an administrator.</p>
          ) : null}
          {errorMessage !== null ? <p role="alert">{errorMessage}</p> : null}
          <AssetReadOnlySummary asset={asset} />
          {readOnly ? null : (
            <>
              <h2>Edit asset</h2>
              <AssetForm
                mode="edit"
                assetId={asset.id}
                initialValues={valuesFromAsset(asset)}
                expectedVersion={asset.version}
                onUpdated={(updated) => {
                  setAsset(updated);
                  setErrorMessage(null);
                }}
                onVersionConflict={loadAsset}
              />
              {confirmArchive ? (
                <ArchiveAssetDialog
                  assetName={asset.name}
                  submitting={archiving}
                  onCancel={() => setConfirmArchive(false)}
                  onConfirm={() => void confirmArchiveAction()}
                />
              ) : (
                <p className="asset-actions">
                  <button type="button" onClick={() => setConfirmArchive(true)}>
                    Archive
                  </button>
                </p>
              )}
            </>
          )}
        </>
      ) : null}
    </main>
  );
}

function AssetReadOnlySummary({ asset }: { asset: AssetDetail }): ReactElement {
  return (
    <section aria-label="Asset details">
      <dl className="asset-summary">
        <div>
          <dt>Type</dt>
          <dd>{catalogLabel(ASSET_TYPE_OPTIONS, asset.assetType)}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{asset.lifecycleStatus === 'archived' ? 'Archived' : 'Active'}</dd>
        </div>
        <div>
          <dt>Environment</dt>
          <dd>{asset.environment?.name ?? 'None'}</dd>
        </div>
        <div>
          <dt>Owning team</dt>
          <dd>{asset.owningTeam?.name ?? 'None'}</dd>
        </div>
        <div>
          <dt>Description</dt>
          <dd>{asset.description ?? 'None'}</dd>
        </div>
        <div>
          <dt>Business criticality</dt>
          <dd>{catalogLabel(BUSINESS_CRITICALITY_OPTIONS, asset.businessCriticality)}</dd>
        </div>
        <div>
          <dt>Internet exposure</dt>
          <dd>{catalogLabel(INTERNET_EXPOSURE_OPTIONS, asset.internetExposure)}</dd>
        </div>
        <div>
          <dt>Data classification</dt>
          <dd>{catalogLabel(DATA_CLASSIFICATION_OPTIONS, asset.dataClassification)}</dd>
        </div>
        <div>
          <dt>Repository URL</dt>
          <dd>{asset.repositoryUrl ?? 'None'}</dd>
        </div>
        <div>
          <dt>Deployment context</dt>
          <dd>{asset.deploymentContext ?? 'None'}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>{asset.version}</dd>
        </div>
      </dl>
      <h2>Tags</h2>
      {asset.tags.length === 0 ? <p>No tags.</p> : null}
      <ul>
        {asset.tags.map((tag) => (
          <li key={tag}>{tag}</li>
        ))}
      </ul>
      <h2>External identifiers</h2>
      {asset.externalIdentifiers.length === 0 ? <p>No external identifiers.</p> : null}
      <ul>
        {asset.externalIdentifiers.map((item) => (
          <li key={`${item.namespace}:${item.identifier}`}>
            {item.namespace}: {item.identifier}
          </li>
        ))}
      </ul>
      <h2>Owners</h2>
      {asset.owners.length === 0 ? <p>No owners assigned.</p> : null}
      <ul>
        {asset.owners.map((owner) => (
          <li key={owner.id}>
            {owner.kind === 'membership'
              ? `${owner.displayName} (${owner.role})`
              : `${owner.name} (${owner.role})`}
          </li>
        ))}
      </ul>
    </section>
  );
}

function mapDetailError(error: unknown): string {
  if (isAuthRequestError(error) && error.message === ORGANIZATION_CONTEXT_REQUIRED) {
    return ORGANIZATION_CONTEXT_REQUIRED;
  }
  if (isAuthRequestError(error) && error.status === 401) {
    return GENERIC_SESSION_EXPIRED;
  }
  if (isAuthRequestError(error) && error.status === 404) {
    return 'Asset not found.';
  }
  if (isAuthRequestError(error)) {
    return error.message;
  }
  return GENERIC_UNAVAILABLE;
}
