'use client';

import { useEffect, useRef, useState, type ReactElement } from 'react';
import Link from 'next/link';

import type { AssetSummary } from '@patchpilot/contracts';

import { catalogLabel, ASSET_TYPE_OPTIONS } from '../../lib/asset-form';
import { canMutateAssets } from '../../lib/asset-permissions';
import {
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
  ORGANIZATION_CONTEXT_REQUIRED,
  isAuthRequestError,
} from '../../lib/auth-api';
import { OrganizationRequiredState } from '../../components/organization-required';
import { RequireAuth } from '../../components/require-auth';
import { SignedInShell } from '../../components/signed-in-shell';
import { useAuth } from '../../components/auth-provider';

export function AssetsPageClient(): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <AssetsPageBody />
      </SignedInShell>
    </RequireAuth>
  );
}

function AssetsPageBody(): ReactElement {
  const { organization, api } = useAuth();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [items, setItems] = useState<AssetSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    headingRef.current?.focus();
  }, [organization, status]);

  useEffect(() => {
    if (organization === null) {
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const page = await api.listAssets({ lifecycleStatus: 'active' });
        if (cancelled) {
          return;
        }
        setItems(page.items);
        setNextCursor(page.nextCursor);
        setStatus('ready');
        setErrorMessage(null);
      } catch (error) {
        if (cancelled) {
          return;
        }
        setStatus('error');
        setErrorMessage(mapListError(error));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, organization]);

  if (organization === null) {
    return <OrganizationRequiredState />;
  }

  const canMutate = canMutateAssets(organization.role);

  async function loadMore(): Promise<void> {
    if (nextCursor === null || loadingMore) {
      return;
    }
    setLoadingMore(true);
    try {
      const page = await api.listAssets({ lifecycleStatus: 'active', cursor: nextCursor });
      setItems((current) => [...current, ...page.items]);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setErrorMessage(mapListError(error));
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Assets
      </h1>
      {canMutate ? (
        <p>
          <Link href="/assets/new">Create asset</Link>
        </p>
      ) : (
        <p>You can view assets in this organization. Changes require an administrator.</p>
      )}

      {status === 'loading' ? <p role="status">Loading assets</p> : null}
      {status === 'error' && errorMessage !== null ? <p role="alert">{errorMessage}</p> : null}
      {status === 'ready' && items.length === 0 ? <p>No assets yet.</p> : null}
      {status === 'ready' && items.length > 0 ? (
        <div className="asset-table-wrap">
          <table>
            <caption>Active assets</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Type</th>
                <th scope="col">Status</th>
                <th scope="col">Environment</th>
                <th scope="col">Team</th>
              </tr>
            </thead>
            <tbody>
              {items.map((asset) => (
                <tr key={asset.id}>
                  <th scope="row">
                    <Link href={`/assets/${asset.id}`}>{asset.name}</Link>
                  </th>
                  <td>{catalogLabel(ASSET_TYPE_OPTIONS, asset.assetType)}</td>
                  <td>{asset.lifecycleStatus === 'archived' ? 'Archived' : 'Active'}</td>
                  <td>{asset.environment?.name ?? 'None'}</td>
                  <td>{asset.owningTeam?.name ?? 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {nextCursor !== null ? (
        <p>
          <button type="button" onClick={() => void loadMore()} disabled={loadingMore}>
            {loadingMore ? 'Loading' : 'Load more'}
          </button>
        </p>
      ) : null}
    </main>
  );
}

function mapListError(error: unknown): string {
  if (isAuthRequestError(error) && error.message === ORGANIZATION_CONTEXT_REQUIRED) {
    return ORGANIZATION_CONTEXT_REQUIRED;
  }
  if (isAuthRequestError(error) && error.status === 401) {
    return GENERIC_SESSION_EXPIRED;
  }
  if (isAuthRequestError(error)) {
    return error.message;
  }
  return GENERIC_UNAVAILABLE;
}
