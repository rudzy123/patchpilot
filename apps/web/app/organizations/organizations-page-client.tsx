'use client';

import type { ReactElement } from 'react';
import { useRouter } from 'next/navigation';

import { OrganizationSelector } from '../../components/organization-selector';
import { RequireAuth } from '../../components/require-auth';
import { SignedInShell } from '../../components/signed-in-shell';

export function OrganizationsPageClient(): ReactElement {
  const router = useRouter();

  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <main>
          <OrganizationSelector onSelected={() => router.replace('/home')} />
        </main>
      </SignedInShell>
    </RequireAuth>
  );
}
