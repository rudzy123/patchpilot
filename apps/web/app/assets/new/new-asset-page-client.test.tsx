import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { navigationMocks } from '../../../test/router-mock';
import {
  ASSET_ID,
  CSRF_TOKEN_FIXTURE,
  ENVIRONMENT_ID,
  TEAM_ID,
  adminOrganizationFixture,
  assetDetailFixture,
  createFakeAuthApi,
  publicOrganizationFixture,
  sessionFixture,
} from '../../../test/auth-fixtures';
import { renderWithAuth } from '../../../test/render-with-auth';

import { NewAssetPageClient } from './new-asset-page-client';

function adminApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: adminOrganizationFixture })),
    ...overrides,
  });
}

describe('NewAssetPageClient', () => {
  it('validates required fields and focuses the error summary', async () => {
    const authApi = adminApi();
    const user = userEvent.setup();
    renderWithAuth(<NewAssetPageClient />, { authApi });

    const submit = await screen.findByRole('button', { name: 'Create asset' });
    await user.click(submit);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Enter a name');
    expect(alert).toHaveTextContent('Select an asset type');
    expect(alert).toHaveFocus();
    expect(authApi.createAsset).not.toHaveBeenCalled();
  });

  it('creates an asset with the in-memory CSRF token and no client organization authority', async () => {
    const authApi = adminApi();
    const user = userEvent.setup();
    renderWithAuth(<NewAssetPageClient />, { authApi });

    await user.type(await screen.findByLabelText('Name'), 'Billing');
    await user.selectOptions(screen.getByLabelText('Asset type'), 'service');
    await screen.findByRole('option', { name: 'production' });
    await user.selectOptions(screen.getByLabelText('Environment'), ENVIRONMENT_ID);
    await user.selectOptions(screen.getByLabelText('Owning team'), TEAM_ID);
    await user.click(screen.getByRole('button', { name: 'Create asset' }));

    await waitFor(() => {
      expect(authApi.createAsset).toHaveBeenCalledTimes(1);
    });
    expect(authApi.createAsset).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Billing',
        assetType: 'service',
        environmentId: ENVIRONMENT_ID,
        owningTeamId: TEAM_ID,
      }),
      CSRF_TOKEN_FIXTURE,
    );
    expect(JSON.stringify(authApi.createAsset.mock.calls[0]?.[0])).not.toContain('organizationId');
    await waitFor(() => {
      expect(navigationMocks.push).toHaveBeenCalledWith(`/assets/${ASSET_ID}`);
    });
  });

  it('blocks duplicate create submissions while the request is in flight', async () => {
    let finishCreate: ((asset: typeof assetDetailFixture) => void) | undefined;
    const authApi = adminApi({
      createAsset: vi.fn(
        () =>
          new Promise((resolve) => {
            finishCreate = resolve;
          }),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<NewAssetPageClient />, { authApi });

    await user.type(await screen.findByLabelText('Name'), 'Billing');
    await user.selectOptions(screen.getByLabelText('Asset type'), 'application');
    const submit = screen.getByRole('button', { name: 'Create asset' });
    await user.click(submit);
    await waitFor(() => {
      expect(submit).toBeDisabled();
    });
    const form = submit.closest('form');
    expect(form).not.toBeNull();
    fireEvent.submit(form!);
    expect(authApi.createAsset).toHaveBeenCalledTimes(1);
    expect(authApi.createAsset.mock.calls[0]?.[1]).toBe(CSRF_TOKEN_FIXTURE);
    finishCreate?.(assetDetailFixture);
  });

  it('keeps viewers and members from creating assets', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    renderWithAuth(<NewAssetPageClient />, { authApi });

    expect(await screen.findByText(/Changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create asset' })).not.toBeInTheDocument();
    expect(authApi.createAsset).not.toHaveBeenCalled();
  });

  it('shows organization context required when none is active', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(<NewAssetPageClient />, { authApi });

    expect(
      await screen.findByRole('heading', { name: 'Organization context is required' }),
    ).toBeInTheDocument();
    expect(authApi.createAsset).not.toHaveBeenCalled();
  });

  it('exposes environment, team, membership, tag, and identifier controls', async () => {
    const user = userEvent.setup();
    renderWithAuth(<NewAssetPageClient />, { authApi: adminApi() });

    expect(await screen.findByLabelText('Environment')).toBeInTheDocument();
    expect(screen.getByLabelText('Owning team')).toBeInTheDocument();
    expect(screen.getByLabelText('Owner kind')).toBeInTheDocument();
    expect(screen.getByLabelText('Member')).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Owner kind'), 'team');
    expect(screen.getByLabelText('Team')).toBeInTheDocument();
    expect(screen.getByLabelText('Tag')).toBeInTheDocument();
    expect(screen.getByLabelText('Namespace')).toBeInTheDocument();
    expect(screen.getByLabelText('Identifier')).toBeInTheDocument();
  });

  it('does not offer create to a viewer', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({
          organization: { ...publicOrganizationFixture, role: 'viewer' },
        }),
      ),
    });
    renderWithAuth(<NewAssetPageClient />, { authApi });

    expect(await screen.findByText(/Changes require an administrator/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
  });
});
