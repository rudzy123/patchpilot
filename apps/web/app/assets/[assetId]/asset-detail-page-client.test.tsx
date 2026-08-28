import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ASSET_VERSION_CONFLICT } from '../../../lib/auth-api';
import {
  ASSET_ID,
  CSRF_TOKEN_FIXTURE,
  adminOrganizationFixture,
  assetDetailFixture,
  createFakeAuthApi,
  publicOrganizationFixture,
  sessionFixture,
} from '../../../test/auth-fixtures';
import { renderWithAuth } from '../../../test/render-with-auth';

import { AssetDetailPageClient } from './asset-detail-page-client';

function adminApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: adminOrganizationFixture })),
    ...overrides,
  });
}

describe('AssetDetailPageClient', () => {
  it('renders escaped name, description, tags, and identifiers as text', async () => {
    const xssAsset = {
      ...assetDetailFixture,
      name: '<script>alert(1)</script>',
      description: '<img src=x onerror=alert(1)>',
      tags: ['<b>core</b>'],
      externalIdentifiers: [{ namespace: 'https://evil.example', identifier: 'PAY-1' }],
      repositoryUrl: 'https://git.example.invalid/payments',
    };
    const authApi = adminApi({
      getAsset: vi.fn(async () => xssAsset),
    });
    const { container } = renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    const heading = await screen.findByRole('heading', {
      level: 1,
      name: '<script>alert(1)</script>',
    });
    expect(heading.querySelector('script')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    const details = screen.getByRole('region', { name: 'Asset details' });
    expect(details).toHaveTextContent('<img src=x onerror=alert(1)>');
    expect(container.querySelector('img[src="x"]')).toBeNull();
    expect(details).toHaveTextContent('<b>core</b>');
    expect(screen.queryByRole('link', { name: '<b>core</b>' })).not.toBeInTheDocument();
    expect(details).toHaveTextContent('https://evil.example: PAY-1');
    expect(screen.queryByRole('link', { name: /PAY-1/ })).not.toBeInTheDocument();
    expect(details).toHaveTextContent('https://git.example.invalid/payments');
    expect(
      screen.queryByRole('link', { name: 'https://git.example.invalid/payments' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/SBOM/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/vulnerabilit/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/finding/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/remediation/i)).not.toBeInTheDocument();
  });

  it('saves edits with expectedVersion and the in-memory CSRF token', async () => {
    const authApi = adminApi();
    const user = userEvent.setup();
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    const name = await screen.findByLabelText('Name');
    await user.clear(name);
    await user.type(name, 'Payments renamed');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => {
      expect(authApi.updateAsset).toHaveBeenCalledTimes(1);
    });
    expect(authApi.updateAsset).toHaveBeenCalledWith(
      ASSET_ID,
      expect.objectContaining({
        expectedVersion: 1,
        name: 'Payments renamed',
      }),
      CSRF_TOKEN_FIXTURE,
    );
  });

  it('requires explicit confirmation before archiving', async () => {
    const authApi = adminApi();
    const user = userEvent.setup();
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    await screen.findByRole('heading', { name: 'Payments' });
    await user.click(await screen.findByRole('button', { name: 'Archive' }));
    expect(authApi.archiveAsset).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog', { name: 'Archive this asset?' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Archive asset' }));
    await waitFor(() => {
      expect(authApi.archiveAsset).toHaveBeenCalledWith(
        ASSET_ID,
        { expectedVersion: 1 },
        CSRF_TOKEN_FIXTURE,
      );
    });
    expect(await screen.findByText('This asset is archived.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Archive' })).not.toBeInTheDocument();
  });

  it('refreshes the asset after an optimistic-concurrency conflict', async () => {
    const refreshed = {
      ...assetDetailFixture,
      name: 'Payments refreshed',
      description: 'Updated elsewhere',
      version: 2,
    };
    const authApi = adminApi({
      getAsset: vi.fn().mockResolvedValueOnce(assetDetailFixture).mockResolvedValueOnce(refreshed),
      updateAsset: vi.fn(async () => {
        throw { status: 409, code: 'conflict', message: ASSET_VERSION_CONFLICT };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    const name = await screen.findByLabelText('Name');
    await user.clear(name);
    await user.type(name, 'Stale name');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    expect(await screen.findByText(/This asset was updated by someone else/)).toBeInTheDocument();
    await waitFor(() => {
      expect(authApi.getAsset).toHaveBeenCalledTimes(2);
    });
    expect(screen.getByLabelText('Name')).toHaveValue('Payments refreshed');
    expect(screen.getByRole('alert')).toHaveFocus();
  });

  it('keeps viewers and members read-only', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    expect(await screen.findByRole('heading', { name: 'Payments' })).toBeInTheDocument();
    expect(screen.getByText(/Changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Archive' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    expect(authApi.updateAsset).not.toHaveBeenCalled();
    expect(authApi.archiveAsset).not.toHaveBeenCalled();
  });

  it('renders the archived state without mutation controls', async () => {
    const authApi = adminApi({
      getAsset: vi.fn(async () => ({
        ...assetDetailFixture,
        lifecycleStatus: 'archived' as const,
        archivedAt: '2026-08-28T15:00:00.000Z',
        version: 2,
      })),
    });
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    expect(await screen.findByText('This asset is archived.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Archive' })).not.toBeInTheDocument();
  });

  it('shows organization context required when none is active', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    expect(
      await screen.findByRole('heading', { name: 'Organization context is required' }),
    ).toBeInTheDocument();
    expect(authApi.getAsset).not.toHaveBeenCalled();
  });

  it('blocks duplicate archive confirmation while the request is in flight', async () => {
    let finishArchive: ((asset: typeof assetDetailFixture) => void) | undefined;
    const authApi = adminApi({
      archiveAsset: vi.fn(
        () =>
          new Promise((resolve) => {
            finishArchive = resolve;
          }),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    await user.click(await screen.findByRole('button', { name: 'Archive' }));
    const confirm = screen.getByRole('button', { name: 'Archive asset' });
    await user.click(confirm);
    await waitFor(() => {
      expect(confirm).toBeDisabled();
    });
    fireEvent.click(confirm);
    expect(authApi.archiveAsset).toHaveBeenCalledTimes(1);
    finishArchive?.({
      ...assetDetailFixture,
      lifecycleStatus: 'archived',
      archivedAt: '2026-08-28T15:00:00.000Z',
      version: 2,
    });
  });

  it('does not fetch an invalid asset identifier', async () => {
    const authApi = adminApi();
    renderWithAuth(<AssetDetailPageClient assetId="not-a-uuid" />, { authApi });

    expect(await screen.findByRole('alert')).toHaveTextContent('Asset not found.');
    expect(authApi.getAsset).not.toHaveBeenCalled();
  });

  it('does not offer mutations to a viewer', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({
          organization: { ...publicOrganizationFixture, role: 'viewer' },
        }),
      ),
    });
    renderWithAuth(<AssetDetailPageClient assetId={ASSET_ID} />, { authApi });

    expect(await screen.findByText(/Changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
  });
});
