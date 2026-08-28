'use client';

import { useEffect, useRef, type ReactElement } from 'react';
import Link from 'next/link';

import { RequireAuth } from '../../components/require-auth';
import { SignedInShell } from '../../components/signed-in-shell';
import { useAuth } from '../../components/auth-provider';

export function HomePageClient(): ReactElement {
  const { user, organization } = useAuth();
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [user]);

  return (
    <RequireAuth>
      <SignedInShell>
        <main>
          <h1 ref={headingRef} tabIndex={-1}>
            Signed in
          </h1>
          <p>
            {user?.displayName} is authenticated
            {organization !== null ? ` for ${organization.name}` : ''}.
          </p>
          <p>
            <Link href="/assets">Asset inventory</Link>
          </p>
        </main>
      </SignedInShell>
    </RequireAuth>
  );
}
