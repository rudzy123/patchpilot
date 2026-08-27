import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  createFakeAuthApi,
  publicOrganizationFixture,
  secondOrganizationFixture,
  sessionFixture,
} from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

import { OrganizationSelector } from './organization-selector';

describe('OrganizationSelector', () => {
  it('labels the organization field and continues with the selected organization', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
      selectOrganization: vi.fn(async () =>
        sessionFixture({ organization: secondOrganizationFixture }),
      ),
    });
    const onSelected = vi.fn();
    const user = userEvent.setup();
    renderWithAuth(<OrganizationSelector onSelected={onSelected} />, { authApi });

    const heading = await screen.findByRole('heading', { name: 'Select an organization' });
    expect(heading).toHaveFocus();
    const select = screen.getByLabelText('Organization');
    await user.selectOptions(select, secondOrganizationFixture.id);
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => {
      expect(onSelected).toHaveBeenCalledTimes(1);
    });
    expect(authApi.selectOrganization).toHaveBeenCalledWith(
      secondOrganizationFixture.id,
      'csrf-memory-only-token',
    );
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('does not treat an empty catalog as selectable authority', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
      listOrganizations: vi.fn(async () => ({ organizations: [] })),
    });
    renderWithAuth(<OrganizationSelector onSelected={vi.fn()} />, { authApi });

    await screen.findByRole('heading', { name: 'Select an organization' });
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
    expect(
      screen.queryByRole('option', { name: publicOrganizationFixture.name }),
    ).not.toBeInTheDocument();
  });
});
