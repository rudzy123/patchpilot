'use client';

import { useEffect, useRef, type ReactElement } from 'react';
import { useRouter } from 'next/navigation';

import { LoginForm } from '../../components/login-form';
import { useAuth } from '../../components/auth-provider';

export function LoginPageClient(): ReactElement {
  const router = useRouter();
  const { status, organization } = useAuth();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const showForm = status !== 'bootstrapping' && status !== 'authenticated';

  useEffect(() => {
    if (showForm) {
      return;
    }
    headingRef.current?.focus();
  }, [showForm]);

  useEffect(() => {
    if (status === 'authenticated') {
      router.replace(organization === null ? '/organizations' : '/home');
    }
  }, [organization, router, status]);

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Sign in
      </h1>
      <p>Sign in with your PatchPilot email and password.</p>
      {status === 'bootstrapping' ? <p role="status">Checking session</p> : null}
      {showForm ? (
        <LoginForm
          onSignedIn={(destination) => {
            router.replace(destination === 'organizations' ? '/organizations' : '/home');
          }}
        />
      ) : null}
    </main>
  );
}
