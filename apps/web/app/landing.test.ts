import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const appDirectory = path.dirname(fileURLToPath(import.meta.url));

function readAppFile(filename: string): string {
  return readFileSync(path.join(appDirectory, filename), 'utf8');
}

describe('web landing page', () => {
  it('states the product name, purpose, and development status', () => {
    const landing = readAppFile('landing.tsx');
    const page = readAppFile('page.tsx');

    expect(page).toContain('loadPublicConfig');
    expect(landing).toContain('publicConfig.appName');
    expect(landing).toContain('Self-hosted vulnerability prioritization and remediation');
    expect(landing).toContain('without an AI provider');
    expect(landing).toContain('under active development');
    expect(landing).toContain('Public environment label');
    expect(landing).not.toContain('DATABASE_URL');
    expect(landing).not.toContain('postgresql://');
  });

  it('uses accessible landmarks, a single page heading, and a named health link', () => {
    const landing = readAppFile('landing.tsx');
    const layout = readAppFile('layout.tsx');

    expect(layout).toContain('lang="en"');
    expect(layout).toContain('AppProviders');
    expect(layout).toContain('loadPublicConfig');
    expect(layout).toContain('apiBaseUrl');
    expect(landing).toContain('<main>');
    expect(landing).toContain('<h1>{publicConfig.appName}</h1>');
    expect(landing.match(/<h1/g)?.length).toBe(1);
    expect(landing).toContain('href="/login"');
    expect(landing).toContain('Sign in');
    expect(landing).toContain('href="/health"');
    expect(landing).toContain('Service health');
    expect(landing).not.toContain('click here');
  });
});
