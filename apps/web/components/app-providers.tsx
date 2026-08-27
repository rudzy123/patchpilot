'use client';

import type { ReactElement, ReactNode } from 'react';

import { AuthProvider } from './auth-provider';

export function AppProviders({
  apiBaseUrl,
  children,
}: {
  apiBaseUrl: string;
  children: ReactNode;
}): ReactElement {
  return <AuthProvider apiBaseUrl={apiBaseUrl}>{children}</AuthProvider>;
}
