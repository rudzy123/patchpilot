import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { navigationMocks } from '../test/router-mock';
import { createFakeAuthApi, sessionFixture, unauthorizedError } from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

import { SignedInShell } from './signed-in-shell';

describe('SignedInShell', () => {
  it('signs out, clears memory, and returns to login', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    const user = userEvent.setup();
    renderWithAuth(
      <SignedInShell>
        <p>shell-child</p>
      </SignedInShell>,
      { authApi },
    );

    await waitFor(() => {
      expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();
    });
    expect(screen.getByText('Ada Org')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Change organization' })).toHaveAttribute(
      'href',
      '/organizations',
    );

    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/login');
    });
    expect(authApi.logout).toHaveBeenCalledTimes(1);
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('still clears local state when logout fails', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
      logout: vi.fn(async () => {
        throw unauthorizedError();
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(
      <SignedInShell>
        <p>shell-child</p>
      </SignedInShell>,
      { authApi },
    );
    await screen.findByRole('button', { name: 'Sign out' });
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/login');
    });
    expect(window.localStorage).toHaveLength(0);
  });
});
