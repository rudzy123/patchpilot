import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';

import {
  GENERIC_ACCESS_DENIED,
  GENERIC_LOGIN_FAILURE,
  GENERIC_SESSION_EXPIRED,
} from '../lib/auth-api';
import {
  CSRF_TOKEN_FIXTURE,
  createFakeAuthApi,
  publicOrganizationFixture,
  publicUserFixture,
  sessionFixture,
  unauthorizedError,
} from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

import { useAuth } from './auth-provider';

function AuthProbe(): ReactElement {
  const value = useAuth();
  return (
    <div>
      <p>status:{value.status}</p>
      <p>user:{value.user?.displayName ?? 'none'}</p>
      <p>org:{value.organization?.name ?? 'none'}</p>
      <p>error:{value.errorMessage ?? 'none'}</p>
      <pre data-testid="auth-json">{JSON.stringify(value)}</pre>
      <button type="button" onClick={() => void value.logout()}>
        probe-logout
      </button>
      <button
        type="button"
        onClick={() => void value.login('operator@example.test', 'correct-horse-test-password')}
      >
        probe-login
      </button>
      <button
        type="button"
        onClick={() => void value.selectOrganization(publicOrganizationFixture.id)}
      >
        probe-select
      </button>
    </div>
  );
}

function sessionRead(overrides: Parameters<typeof sessionFixture>[0] = {}) {
  return vi.fn(async () => sessionFixture(overrides));
}

describe('AuthProvider', () => {
  it('keeps the CSRF token out of React context, storage, and serialized state', async () => {
    const authApi = createFakeAuthApi({
      readSession: sessionRead(),
    });
    renderWithAuth(<AuthProbe />, { authApi });

    await waitFor(() => {
      expect(screen.getByText('status:authenticated')).toBeInTheDocument();
    });

    expect(screen.getByTestId('auth-json').textContent).not.toContain(CSRF_TOKEN_FIXTURE);
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('prevents duplicate in-flight login submissions', async () => {
    let finishLogin: ((session: ReturnType<typeof sessionFixture>) => void) | undefined;
    const authApi = createFakeAuthApi({
      login: vi.fn(
        () =>
          new Promise((resolve) => {
            finishLogin = resolve;
          }),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<AuthProbe />, { authApi });
    await waitFor(() => {
      expect(screen.getByText('status:anonymous')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'probe-login' }));
    await user.click(screen.getByRole('button', { name: 'probe-login' }));
    expect(authApi.login).toHaveBeenCalledTimes(1);
    finishLogin?.(sessionFixture());
    await waitFor(() => {
      expect(screen.getByText('status:authenticated')).toBeInTheDocument();
    });
  });

  it('uses a generic login failure and clears local session state', async () => {
    const authApi = createFakeAuthApi({
      login: vi.fn(async () => {
        throw {
          status: 401,
          code: 'unauthorized',
          message: 'No account for operator@example.test',
        };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<AuthProbe />, { authApi });
    await waitFor(() => {
      expect(screen.getByText('status:anonymous')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'probe-login' }));
    await waitFor(() => {
      expect(screen.getByText(`error:${GENERIC_LOGIN_FAILURE}`)).toBeInTheDocument();
    });
    expect(screen.getByText('user:none')).toBeInTheDocument();
    expect(screen.getByTestId('auth-json').textContent).not.toContain(CSRF_TOKEN_FIXTURE);
    expect(screen.getByTestId('auth-json').textContent).not.toContain('operator@example.test');
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('clears in-memory session and CSRF state on logout', async () => {
    const authApi = createFakeAuthApi({
      readSession: sessionRead(),
    });
    const user = userEvent.setup();
    renderWithAuth(<AuthProbe />, { authApi });
    await waitFor(() => {
      expect(screen.getByText(`user:${publicUserFixture.displayName}`)).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'probe-logout' }));
    await waitFor(() => {
      expect(screen.getByText('status:anonymous')).toBeInTheDocument();
    });
    expect(authApi.logout).toHaveBeenCalledWith(CSRF_TOKEN_FIXTURE);
    expect(screen.getByText('user:none')).toBeInTheDocument();
    expect(screen.getByTestId('auth-json').textContent).not.toContain(CSRF_TOKEN_FIXTURE);
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('clears local state when an authenticated request expires', async () => {
    const authApi = createFakeAuthApi({
      readSession: sessionRead(),
      selectOrganization: vi.fn(async () => {
        throw unauthorizedError();
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<AuthProbe />, { authApi });
    await waitFor(() => {
      expect(screen.getByText('status:authenticated')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'probe-select' }));
    await waitFor(() => {
      expect(screen.getByText('status:expired')).toBeInTheDocument();
    });
    expect(screen.getByText(`error:${GENERIC_SESSION_EXPIRED}`)).toBeInTheDocument();
    expect(screen.getByText('user:none')).toBeInTheDocument();
    expect(screen.getByTestId('auth-json').textContent).not.toContain(CSRF_TOKEN_FIXTURE);
  });

  it('records access denied without treating the client selection as authority', async () => {
    const authApi = createFakeAuthApi({
      readSession: sessionRead({ organization: null }),
      selectOrganization: vi.fn(async () => {
        throw { status: 404, code: 'not_found', message: 'Organization not found.' };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<AuthProbe />, { authApi });
    await waitFor(() => {
      expect(screen.getByText('status:authenticated')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'probe-select' }));
    await waitFor(() => {
      expect(screen.getByText('status:denied')).toBeInTheDocument();
    });
    expect(screen.getByText(`error:${GENERIC_ACCESS_DENIED}`)).toBeInTheDocument();
    expect(screen.getByText(`user:${publicUserFixture.displayName}`)).toBeInTheDocument();
  });
});
