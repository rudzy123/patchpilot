import { type ReactElement } from 'react';
import { render, type RenderResult } from '@testing-library/react';

import { AuthProvider } from '../components/auth-provider';
import type { AuthApi } from '../lib/auth-api';

import { createFakeAuthApi, type FakeAuthApi } from './auth-fixtures';

export function renderWithAuth(
  ui: ReactElement,
  options: { authApi?: FakeAuthApi | AuthApi } = {},
): RenderResult {
  return render(
    <AuthProvider
      apiBaseUrl="http://127.0.0.1:3001"
      authApi={options.authApi ?? createFakeAuthApi()}
    >
      {ui}
    </AuthProvider>,
  );
}
