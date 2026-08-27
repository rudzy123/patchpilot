'use client';

import { useEffect, useRef, type ReactElement } from 'react';
import { useRouter } from 'next/navigation';

import { useAuth } from '../../components/auth-provider';

export function AccessDeniedPageClient(): ReactElement {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const router = useRouter();
  const { organization, acknowledgeAccessDenied } = useAuth();

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  function handleBackToSession(): void {
    acknowledgeAccessDenied();
    router.replace(organization === null ? '/organizations' : '/home');
  }

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Access denied
      </h1>
      <p>You do not have access to that resource.</p>
      <p>
        <button type="button" onClick={handleBackToSession}>
          Back to session
        </button>
      </p>
    </main>
  );
}
