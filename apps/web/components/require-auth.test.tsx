import { useEffect, type ReactElement, type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';

import { navigationMocks } from '../test/router-mock';
import {
  createFakeAuthApi,
  publicOrganizationFixture,
  sessionFixture,
  unauthorizedError,
} from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

import { useAuth } from './auth-provider';
import { RequireAuth } from './require-auth';

function TriggerSelect({ children }: { children: ReactNode }): ReactElement {
  const { status, selectOrganization } = useAuth();
  useEffect(() => {
    if (status === 'authenticated') {
      void selectOrganization(publicOrganizationFixture.id);
    }
  }, [selectOrganization, status]);
  return <>{children}</>;
}

describe('RequireAuth', () => {
  it('redirects anonymous visitors to login', async () => {
    renderWithAuth(
      <RequireAuth>
        <p>secret</p>
      </RequireAuth>,
    );
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/login');
    });
    expect(screen.queryByText('secret')).not.toBeInTheDocument();
  });

  it('redirects expired sessions to the expired-session page', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
      selectOrganization: vi.fn(async () => {
        throw unauthorizedError();
      }),
    });
    renderWithAuth(
      <TriggerSelect>
        <RequireAuth>
          <p>secret</p>
        </RequireAuth>
      </TriggerSelect>,
      { authApi },
    );
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/session-expired');
    });
  });

  it('redirects access denied to the access-denied page', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
      selectOrganization: vi.fn(async () => {
        throw { status: 404, code: 'not_found', message: 'Organization not found.' };
      }),
    });
    renderWithAuth(
      <TriggerSelect>
        <RequireAuth>
          <p>secret</p>
        </RequireAuth>
      </TriggerSelect>,
      { authApi },
    );
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/access-denied');
    });
  });

  it('sends authenticated users without an organization to the selector', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: null })),
    });
    renderWithAuth(
      <RequireAuth>
        <p>secret</p>
      </RequireAuth>,
      { authApi },
    );
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/organizations');
    });
    expect(screen.queryByText('secret')).not.toBeInTheDocument();
  });

  it('renders children when the session has an authorized organization', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    renderWithAuth(
      <RequireAuth>
        <p>secret</p>
      </RequireAuth>,
      { authApi },
    );
    expect(await screen.findByText('secret')).toBeInTheDocument();
    expect(navigationMocks.replace).not.toHaveBeenCalled();
  });
});
