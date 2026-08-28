'use client';

import { useEffect, useRef, type ReactElement } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

import { AssetForm } from '../../../components/asset-form';
import { OrganizationRequiredState } from '../../../components/organization-required';
import { RequireAuth } from '../../../components/require-auth';
import { SignedInShell } from '../../../components/signed-in-shell';
import { useAuth } from '../../../components/auth-provider';
import { canMutateAssets } from '../../../lib/asset-permissions';

export function NewAssetPageClient(): ReactElement {
  return (
    <RequireAuth allowWithoutOrganization>
      <SignedInShell>
        <NewAssetPageBody />
      </SignedInShell>
    </RequireAuth>
  );
}

function NewAssetPageBody(): ReactElement {
  const { organization } = useAuth();
  const router = useRouter();
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [organization]);

  if (organization === null) {
    return <OrganizationRequiredState />;
  }

  if (!canMutateAssets(organization.role)) {
    return (
      <main>
        <h1 ref={headingRef} tabIndex={-1}>
          Create asset
        </h1>
        <p>You can view assets in this organization. Changes require an administrator.</p>
        <p>
          <Link href="/assets">Back to assets</Link>
        </p>
      </main>
    );
  }

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Create asset
      </h1>
      <AssetForm
        mode="create"
        onCreated={(asset) => {
          router.push(`/assets/${asset.id}`);
        }}
      />
    </main>
  );
}
