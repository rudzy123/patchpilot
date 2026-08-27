import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GENERIC_LOGIN_FAILURE } from '../lib/auth-api';
import { createFakeAuthApi, sessionFixture } from '../test/auth-fixtures';
import { renderWithAuth } from '../test/render-with-auth';

import { LoginForm } from './login-form';

describe('LoginForm', () => {
  it('labels fields, focuses the email input, and disables duplicate submit', async () => {
    let finishLogin: ((session: ReturnType<typeof sessionFixture>) => void) | undefined;
    const authApi = createFakeAuthApi({
      login: vi.fn(
        () =>
          new Promise((resolve) => {
            finishLogin = resolve;
          }),
      ),
    });
    const onSignedIn = vi.fn();
    const user = userEvent.setup();
    renderWithAuth(<LoginForm onSignedIn={onSignedIn} />, { authApi });

    const email = await screen.findByLabelText('Email');
    expect(email).toHaveFocus();
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');

    await user.type(email, 'operator@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct-horse-test-password');
    const submit = screen.getByRole('button', { name: 'Sign in' });
    await user.click(submit);
    await waitFor(() => {
      expect(submit).toBeDisabled();
    });
    expect(authApi.login).toHaveBeenCalledTimes(1);
    expect(authApi.login).toHaveBeenCalledWith({
      email: 'operator@example.test',
      password: 'correct-horse-test-password',
    });

    finishLogin?.(sessionFixture());
    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledWith('home');
    });
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('moves focus to the generic failure alert', async () => {
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
    renderWithAuth(<LoginForm onSignedIn={vi.fn()} />, { authApi });

    await user.type(await screen.findByLabelText('Email'), 'operator@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct-horse-test-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(GENERIC_LOGIN_FAILURE);
    expect(alert).not.toHaveTextContent('operator@example.test');
    expect(alert).toHaveFocus();
  });

  it('is operable with the keyboard', async () => {
    const authApi = createFakeAuthApi();
    const onSignedIn = vi.fn();
    const user = userEvent.setup();
    renderWithAuth(<LoginForm onSignedIn={onSignedIn} />, { authApi });

    await screen.findByLabelText('Email');
    expect(screen.getByLabelText('Email')).toHaveFocus();
    await user.keyboard('operator@example.test');
    await user.tab();
    expect(screen.getByLabelText('Password')).toHaveFocus();
    await user.keyboard('correct-horse-test-password');
    await user.keyboard('{Enter}');

    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledWith('home');
    });
  });
});
