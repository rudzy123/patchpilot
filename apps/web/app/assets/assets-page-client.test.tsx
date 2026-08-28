import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  ASSET_ID,
  adminOrganizationFixture,
  createFakeAuthApi,
  publicOrganizationFixture,
  sessionFixture,
} from '../../test/auth-fixtures';
import { renderWithAuth } from '../../test/render-with-auth';

import { AssetsPageClient } from './assets-page-client';

function memberApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture()),
    ...overrides,
  });
}

function adminApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: adminOrganizationFixture })),
    ...overrides,
  });
}

describe('AssetsPageClient', () => {
  it('renders the active asset list without product or security statistics', async () => {
    const authApi = memberApi();
    renderWithAuth(<AssetsPageClient />, { authApi });

    expect(await screen.findByRole('heading', { name: 'Assets' })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Payments' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    expect(screen.getByText('Application')).toBeInTheDocument();
    expect(screen.getByText('production')).toBeInTheDocument();
    expect(screen.getByText('Platform')).toBeInTheDocument();
    expect(authApi.listAssets).toHaveBeenCalledWith({ lifecycleStatus: 'active' });
    expect(screen.queryByRole('link', { name: 'Create asset' })).not.toBeInTheDocument();
    expect(screen.queryByText(/SBOM/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/vulnerabilit/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/finding/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/remediation/i)).not.toBeInTheDocument();
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('renders an empty state when the organization has no assets', async () => {
    const authApi = memberApi({
      listAssets: vi.fn(async () => ({ items: [], nextCursor: null })),
    });
    renderWithAuth(<AssetsPageClient />, { authApi });

    expect(await screen.findByText('No assets yet.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('keeps viewers and members in a read-only list state', async () => {
    const viewerApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({
          organization: { ...publicOrganizationFixture, role: 'viewer' },
        }),
      ),
    });
    renderWithAuth(<AssetsPageClient />, { authApi: viewerApi });

    expect(await screen.findByText(/Changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Create asset' })).not.toBeInTheDocument();
  });

  it('lets administrators open the create-asset page', async () => {
    renderWithAuth(<AssetsPageClient />, { authApi: adminApi() });

    expect(await screen.findByRole('link', { name: 'Create asset' })).toHaveAttribute(
      'href',
      '/assets/new',
    );
  });

  it('shows the organization-context-required state when none is active', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(<AssetsPageClient />, { authApi });

    expect(
      await screen.findByRole('heading', { name: 'Organization context is required' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Select organization' })).toHaveAttribute(
      'href',
      '/organizations',
    );
    expect(authApi.listAssets).not.toHaveBeenCalled();
  });

  it('renders a loading status while the asset list is in flight', async () => {
    const authApi = memberApi({
      listAssets: vi.fn(() => new Promise(() => undefined)),
    });
    renderWithAuth(<AssetsPageClient />, { authApi });

    expect(await screen.findByText('Loading assets')).toBeInTheDocument();
  });

  it('renders a list error without fake metrics', async () => {
    const authApi = memberApi({
      listAssets: vi.fn(async () => {
        throw { status: 500, code: 'internal', message: 'Asset list failed.' };
      }),
    });
    renderWithAuth(<AssetsPageClient />, { authApi });

    expect(await screen.findByRole('alert')).toHaveTextContent('Asset list failed.');
    expect(screen.queryByText(/critical vulnerabilities/i)).not.toBeInTheDocument();
  });

  it('is operable from the keyboard on the create-asset link', async () => {
    const user = userEvent.setup();
    renderWithAuth(<AssetsPageClient />, { authApi: adminApi() });
    const payments = await screen.findByRole('link', { name: 'Payments' });
    const create = screen.getByRole('link', { name: 'Create asset' });
    create.focus();
    expect(create).toHaveFocus();
    await user.tab();
    expect(payments).toHaveFocus();
  });
});
