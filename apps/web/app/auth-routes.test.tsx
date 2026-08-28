import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AccessDeniedPageClient } from './access-denied/access-denied-page-client';
import { HomePageClient } from './home/home-page-client';
import { LoginPageClient } from './login/login-page-client';
import { OrganizationsPageClient } from './organizations/organizations-page-client';
import { SessionExpiredPageClient } from './session-expired/session-expired-page-client';
import { navigationMocks } from '../test/router-mock';
import { createFakeAuthApi, sessionFixture } from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

describe('authentication routes', () => {
  it('renders an accessible login page and sends a successful session to home', async () => {
    const authApi = createFakeAuthApi();
    const user = userEvent.setup();
    renderWithAuth(<LoginPageClient />, { authApi });

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    await user.type(await screen.findByLabelText('Email'), 'operator@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct-horse-test-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/home');
    });
    expect(screen.queryByText('Register')).not.toBeInTheDocument();
    expect(screen.queryByText('Forgot password')).not.toBeInTheDocument();
  });

  it('renders the organization selector for an authenticated session without an organization', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(<OrganizationsPageClient />, { authApi });

    expect(
      await screen.findByRole('heading', { name: 'Select an organization' }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('Organization')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Account' })).toBeInTheDocument();
  });

  it('renders a signed-in home without product dashboards or fake metrics', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    renderWithAuth(<HomePageClient />, { authApi });

    expect(await screen.findByRole('heading', { name: 'Signed in' })).toBeInTheDocument();
    expect(screen.getByText(/is authenticated/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Asset inventory' })).toHaveAttribute('href', '/assets');
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
    expect(screen.queryByText(/dashboard/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SBOM/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/vulnerability/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/metric/i)).not.toBeInTheDocument();
  });

  it('renders the expired-session page with a sign-in link', async () => {
    renderWithAuth(<SessionExpiredPageClient />);
    const heading = screen.getByRole('heading', { name: 'Session expired' });
    expect(heading).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login');
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
  });

  it('renders access denied and returns to the live session without looping', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    const user = userEvent.setup();
    renderWithAuth(<AccessDeniedPageClient />, { authApi });

    expect(await screen.findByRole('heading', { name: 'Access denied' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Back to session' }));
    expect(navigationMocks.replace).toHaveBeenCalledWith('/home');
  });
});
