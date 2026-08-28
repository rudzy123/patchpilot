'use client';

import { useRouter } from 'next/navigation';
import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';

import { useAuth } from './auth-provider';

export function SignedInShell({ children }: { children: ReactNode }): ReactElement {
  const { user, organization, logout, submitting } = useAuth();
  const router = useRouter();

  async function handleLogout(): Promise<void> {
    await logout();
    router.replace('/login');
  }

  return (
    <div className="asset-shell">
      <header>
        <p>
          Signed in as <span>{user?.displayName ?? 'Unknown user'}</span>
          {organization !== null ? (
            <>
              {' '}
              in <span>{organization.name}</span>
            </>
          ) : null}
        </p>
        <nav aria-label="Primary">
          <a href="/home">Home</a>
          <Link href="/assets">Assets</Link>
        </nav>
        <nav aria-label="Account">
          <a href="/organizations">Change organization</a>
          <button type="button" onClick={() => void handleLogout()} disabled={submitting}>
            Sign out
          </button>
        </nav>
      </header>
      {children}
    </div>
  );
}
