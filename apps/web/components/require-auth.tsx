'use client';

import { useEffect, type ReactElement, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';

import { useAuth, type AuthStatus } from './auth-provider';

export function RequireAuth({
  children,
  allowWithoutOrganization = false,
}: {
  children: ReactNode;
  allowWithoutOrganization?: boolean;
}): ReactElement | null {
  const { status, organization } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status === 'anonymous') {
      router.replace('/login');
    } else if (status === 'expired') {
      router.replace('/session-expired');
    } else if (status === 'denied') {
      router.replace('/access-denied');
    } else if (status === 'authenticated' && organization === null && !allowWithoutOrganization) {
      router.replace('/organizations');
    }
  }, [allowWithoutOrganization, organization, router, status]);

  if (status === 'bootstrapping' || status === 'unavailable') {
    return (
      <p role="status">
        {status === 'bootstrapping' ? 'Checking session' : 'Unable to check session'}
      </p>
    );
  }

  if (!isAuthenticatedStatus(status)) {
    return null;
  }

  if (organization === null && !allowWithoutOrganization) {
    return null;
  }

  return <>{children}</>;
}

function isAuthenticatedStatus(status: AuthStatus): boolean {
  return status === 'authenticated';
}
