'use client';

import { useEffect, useRef, type FormEvent, type ReactElement } from 'react';

import { useAuth } from './auth-provider';

export function LoginForm({
  onSignedIn,
}: {
  onSignedIn: (destination: 'home' | 'organizations') => void;
}): ReactElement {
  const { login, submitting, errorMessage, clearError } = useAuth();
  const errorRef = useRef<HTMLDivElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
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
    const form = new FormData(event.currentTarget);
    const email = String(form.get('email') ?? '');
    const password = String(form.get('password') ?? '');
    const result = await login(email, password);
    if (result === 'home' || result === 'organizations') {
      onSignedIn(result);
    }
  }

  return (
    <form onSubmit={(event) => void handleSubmit(event)}>
      {errorMessage !== null ? (
        <div
          id="login-error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
          aria-live="assertive"
          className="auth-alert"
        >
          {errorMessage}
        </div>
      ) : null}
      <div className="auth-field">
        <label htmlFor="email">Email</label>
        <input
          ref={emailRef}
          id="email"
          name="email"
          type="email"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          aria-invalid={errorMessage !== null}
          aria-describedby={errorMessage === null ? undefined : 'login-error'}
          onChange={clearError}
        />
      </div>
      <div className="auth-field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          minLength={12}
          aria-invalid={errorMessage !== null}
          aria-describedby={errorMessage === null ? undefined : 'login-error'}
          onChange={clearError}
        />
      </div>
      <button type="submit" disabled={submitting} aria-busy={submitting}>
        {submitting ? 'Signing in' : 'Sign in'}
      </button>
    </form>
  );
}
