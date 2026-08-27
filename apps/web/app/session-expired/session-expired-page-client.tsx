'use client';

import { useEffect, useRef, type ReactElement } from 'react';

export function SessionExpiredPageClient(): ReactElement {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Session expired
      </h1>
      <p>Your session has expired. Sign in again to continue.</p>
      <p>
        <a href="/login">Sign in</a>
      </p>
    </main>
  );
}
