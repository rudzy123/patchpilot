'use client';

import { useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';

import { useAuth } from './auth-provider';

export function OrganizationSelector({ onSelected }: { onSelected: () => void }): ReactElement {
  const { organizations, organization, selectOrganization, submitting, errorMessage } = useAuth();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const [userChoice, setUserChoice] = useState<string | null>(null);
  const selectedId = userChoice ?? organization?.id ?? '';

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    if (errorMessage !== null) {
      errorRef.current?.focus();
    }
  }, [errorMessage]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submitting) {
      return;
    }
    const result = await selectOrganization(selectedId);
    if (result === 'home') {
      onSelected();
    }
  }

  return (
    <section>
      <h1 ref={headingRef} tabIndex={-1}>
        Select an organization
      </h1>
      <p>
        Choose the organization you are authorized to work in. This selection is not a grant of
        access by itself.
      </p>
      {errorMessage !== null ? (
        <div
          id="organization-error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
          aria-live="assertive"
          className="auth-alert"
        >
          {errorMessage}
        </div>
      ) : null}
      <form onSubmit={(event) => void handleSubmit(event)}>
        <div className="auth-field">
          <label htmlFor="organizationId">Organization</label>
          <select
            id="organizationId"
            name="organizationId"
            required
            value={selectedId}
            disabled={submitting || organizations.length === 0}
            aria-invalid={errorMessage !== null}
            aria-describedby={errorMessage === null ? undefined : 'organization-error'}
            onChange={(event) => {
              setUserChoice(event.target.value);
            }}
          >
            <option value="" disabled>
              Select an organization
            </option>
            {organizations.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>
        <button
          type="submit"
          disabled={submitting || organizations.length === 0 || selectedId === ''}
          aria-busy={submitting}
        >
          {submitting ? 'Continuing' : 'Continue'}
        </button>
      </form>
    </section>
  );
}
