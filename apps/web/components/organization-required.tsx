'use client';

import { useEffect, useRef, type ReactElement } from 'react';

export function OrganizationRequiredState(): ReactElement {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <main>
      <h1 ref={headingRef} tabIndex={-1}>
        Organization context is required
      </h1>
      <p>Select an active organization before viewing or changing assets.</p>
      <p>
        <a href="/organizations">Select organization</a>
      </p>
    </main>
  );
}
