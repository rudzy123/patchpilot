import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const webRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

const authImplementationFiles = [
  'lib/auth-api.ts',
  'lib/asset-form.ts',
  'lib/asset-permissions.ts',
  'components/auth-provider.tsx',
  'components/login-form.tsx',
  'components/organization-selector.tsx',
  'components/require-auth.tsx',
  'components/signed-in-shell.tsx',
  'components/app-providers.tsx',
  'components/asset-form.tsx',
  'components/archive-asset-dialog.tsx',
  'components/organization-required.tsx',
  'app/layout.tsx',
  'app/login/login-page-client.tsx',
  'app/login/page.tsx',
  'app/home/home-page-client.tsx',
  'app/home/page.tsx',
  'app/organizations/organizations-page-client.tsx',
  'app/organizations/page.tsx',
  'app/session-expired/session-expired-page-client.tsx',
  'app/session-expired/page.tsx',
  'app/access-denied/access-denied-page-client.tsx',
  'app/access-denied/page.tsx',
  'app/assets/assets-page-client.tsx',
  'app/assets/page.tsx',
  'app/assets/new/new-asset-page-client.tsx',
  'app/assets/new/page.tsx',
  'app/assets/[assetId]/asset-detail-page-client.tsx',
  'app/assets/[assetId]/page.tsx',
];

function readWebFile(relativePath: string): string {
  return readFileSync(path.join(webRoot, relativePath), 'utf8');
}

describe('web authentication source constraints', () => {
  it('does not persist tokens in web storage, cookies, or the URL', () => {
    const sources = authImplementationFiles.map((file) => ({ file, source: readWebFile(file) }));
    for (const { file, source } of sources) {
      expect(source.includes('localStorage'), `${file} must not use localStorage`).toBe(false);
      expect(source.includes('sessionStorage'), `${file} must not use sessionStorage`).toBe(false);
      expect(source.includes('document.cookie'), `${file} must not read document.cookie`).toBe(
        false,
      );
      expect(source.includes('dangerouslySetInnerHTML'), `${file} must not set inner HTML`).toBe(
        false,
      );
      expect(source).not.toMatch(/searchParams.*csrf/i);
      expect(source).not.toMatch(/[?&]csrf=/i);
      expect(source).not.toMatch(/gtag|analytics|mixpanel|segment\./i);
    }
  });

  it('keeps CSRF in React memory and sends credentials on the cookie session', () => {
    const provider = readWebFile('components/auth-provider.tsx');
    const api = readWebFile('lib/auth-api.ts');
    expect(provider).toContain('csrfTokenRef');
    expect(provider).not.toContain('localStorage');
    expect(api).toContain("credentials: 'include'");
    expect(api).toContain("cache: 'no-store'");
    expect(api).toContain('GENERIC_LOGIN_FAILURE');
  });

  it('does not log credentials in the auth client or login form', () => {
    const sources = [
      'lib/auth-api.ts',
      'components/auth-provider.tsx',
      'components/login-form.tsx',
    ].map((file) => readWebFile(file));
    for (const source of sources) {
      expect(source).not.toContain('console.');
      expect(source).not.toMatch(/logger\.(info|debug|error|warn).*password/i);
      expect(source).not.toMatch(/logger\.(info|debug|error|warn).*email/i);
    }
  });

  it('does not add registration, password reset, or product workflow routes', () => {
    const files = [
      'app/login/login-page-client.tsx',
      'app/home/home-page-client.tsx',
      'app/organizations/organizations-page-client.tsx',
      'app/landing.tsx',
    ].map((file) => readWebFile(file).toLowerCase());
    for (const source of files) {
      expect(source).not.toContain('register');
      expect(source).not.toContain('password reset');
      expect(source).not.toContain('forgot password');
      expect(source).not.toContain('dashboard');
      expect(source).not.toContain('fake metric');
    }
  });
});
