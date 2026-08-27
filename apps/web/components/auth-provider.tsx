'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from 'react';

import type { PublicAuthOrganization, PublicAuthUser } from '@patchpilot/contracts';

import {
  createAuthApi,
  GENERIC_ACCESS_DENIED,
  GENERIC_LOGIN_FAILURE,
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
  isAuthRequestError,
  type AuthApi,
} from '../lib/auth-api';

export type AuthStatus =
  'bootstrapping' | 'anonymous' | 'authenticated' | 'expired' | 'denied' | 'unavailable';

export type AuthViewState = {
  status: AuthStatus;
  user: PublicAuthUser | null;
  organization: PublicAuthOrganization | null;
  organizations: readonly PublicAuthOrganization[];
  submitting: boolean;
  errorMessage: string | null;
};

export type AuthContextValue = AuthViewState & {
  login: (email: string, password: string) => Promise<'home' | 'organizations' | 'error'>;
  logout: () => Promise<void>;
  selectOrganization: (organizationId: string) => Promise<'home' | 'denied' | 'error'>;
  acknowledgeAccessDenied: () => void;
  clearError: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  apiBaseUrl,
  authApi,
  children,
}: {
  apiBaseUrl: string;
  authApi?: AuthApi;
  children: ReactNode;
}): ReactElement {
  const api = useMemo(() => authApi ?? createAuthApi(apiBaseUrl), [apiBaseUrl, authApi]);
  const csrfTokenRef = useRef<string | null>(null);
  const loginInFlightRef = useRef(false);
  const selectInFlightRef = useRef(false);
  const [status, setStatus] = useState<AuthStatus>('bootstrapping');
  const [user, setUser] = useState<PublicAuthUser | null>(null);
  const [organization, setOrganization] = useState<PublicAuthOrganization | null>(null);
  const [organizations, setOrganizations] = useState<readonly PublicAuthOrganization[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const clearLocalState = useCallback(() => {
    csrfTokenRef.current = null;
    setUser(null);
    setOrganization(null);
    setOrganizations([]);
    setSubmitting(false);
    loginInFlightRef.current = false;
    selectInFlightRef.current = false;
  }, []);

  const rememberSession = useCallback(
    async (session: {
      user: PublicAuthUser;
      organization: PublicAuthOrganization | null;
      csrfToken: string;
    }): Promise<boolean> => {
      let listed: readonly PublicAuthOrganization[];
      try {
        listed = (await api.listOrganizations()).organizations;
      } catch (error) {
        if (isAuthRequestError(error) && error.status === 401) {
          clearLocalState();
          setStatus('expired');
          setErrorMessage(GENERIC_SESSION_EXPIRED);
          return false;
        }
        listed = session.organization === null ? [] : [session.organization];
      }
      csrfTokenRef.current = session.csrfToken;
      setUser(session.user);
      setOrganization(session.organization);
      setOrganizations(listed);
      setStatus('authenticated');
      setErrorMessage(null);
      return true;
    },
    [api, clearLocalState],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const session = await api.readSession();
        if (cancelled) {
          return;
        }
        await rememberSession(session);
      } catch (error) {
        if (cancelled) {
          return;
        }
        clearLocalState();
        if (isAuthRequestError(error) && error.status === 401) {
          setStatus('anonymous');
          setErrorMessage(null);
          return;
        }
        setStatus('unavailable');
        setErrorMessage(GENERIC_UNAVAILABLE);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, clearLocalState, rememberSession]);

  const login = useCallback(
    async (email: string, password: string): Promise<'home' | 'organizations' | 'error'> => {
      if (loginInFlightRef.current) {
        return 'error';
      }
      loginInFlightRef.current = true;
      setSubmitting(true);
      setErrorMessage(null);
      try {
        const session = await api.login({ email, password });
        const remembered = await rememberSession(session);
        if (!remembered) {
          return 'error';
        }
        return session.organization === null ? 'organizations' : 'home';
      } catch (error) {
        clearLocalState();
        setStatus('anonymous');
        if (isAuthRequestError(error) && error.code === 'unauthorized') {
          setErrorMessage(GENERIC_LOGIN_FAILURE);
        } else if (isAuthRequestError(error)) {
          setErrorMessage(error.message);
        } else {
          setErrorMessage(GENERIC_LOGIN_FAILURE);
        }
        return 'error';
      } finally {
        loginInFlightRef.current = false;
        setSubmitting(false);
      }
    },
    [api, clearLocalState, rememberSession],
  );

  const logout = useCallback(async () => {
    const csrfToken = csrfTokenRef.current;
    try {
      await api.logout(csrfToken);
    } catch {
      // Publicly idempotent: always clear local Session and CSRF state.
    } finally {
      clearLocalState();
      setStatus('anonymous');
      setErrorMessage(null);
    }
  }, [api, clearLocalState]);

  const selectOrganization = useCallback(
    async (organizationId: string): Promise<'home' | 'denied' | 'error'> => {
      if (selectInFlightRef.current) {
        return 'error';
      }
      const csrfToken = csrfTokenRef.current;
      if (csrfToken === null) {
        clearLocalState();
        setStatus('expired');
        setErrorMessage(GENERIC_SESSION_EXPIRED);
        return 'error';
      }
      selectInFlightRef.current = true;
      setSubmitting(true);
      setErrorMessage(null);
      try {
        const session = await api.selectOrganization(organizationId, csrfToken);
        const remembered = await rememberSession(session);
        if (!remembered) {
          return 'error';
        }
        return 'home';
      } catch (error) {
        if (isAuthRequestError(error) && error.status === 401) {
          clearLocalState();
          setStatus('expired');
          setErrorMessage(GENERIC_SESSION_EXPIRED);
          return 'error';
        }
        if (
          isAuthRequestError(error) &&
          (error.status === 403 || error.status === 404 || error.code === 'forbidden')
        ) {
          setStatus('denied');
          setErrorMessage(GENERIC_ACCESS_DENIED);
          return 'denied';
        }
        setErrorMessage(isAuthRequestError(error) ? error.message : GENERIC_UNAVAILABLE);
        return 'error';
      } finally {
        selectInFlightRef.current = false;
        setSubmitting(false);
      }
    },
    [api, clearLocalState, rememberSession],
  );

  const acknowledgeAccessDenied = useCallback(() => {
    setErrorMessage(null);
    if (user !== null) {
      setStatus('authenticated');
      return;
    }
    setStatus('anonymous');
  }, [user]);

  const clearError = useCallback(() => {
    setErrorMessage(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      organization,
      organizations,
      submitting,
      errorMessage,
      login,
      logout,
      selectOrganization,
      acknowledgeAccessDenied,
      clearError,
    }),
    [
      status,
      user,
      organization,
      organizations,
      submitting,
      errorMessage,
      login,
      logout,
      selectOrganization,
      acknowledgeAccessDenied,
      clearError,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error('useAuth must be used within AuthProvider.');
  }
  return value;
}
