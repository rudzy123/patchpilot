import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  applyEnvFileContents,
  findDevelopmentEnvFile,
  hydrateProcessEnvFromDevelopmentFiles,
  shouldLoadDevelopmentEnvFiles,
} from './load-env-files.js';

describe('development env file loading', () => {
  it('does not load files when production is already selected', () => {
    expect(shouldLoadDevelopmentEnvFiles({ PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production' })).toBe(
      false,
    );
    expect(shouldLoadDevelopmentEnvFiles({ NODE_ENV: 'production' })).toBe(false);
    expect(
      shouldLoadDevelopmentEnvFiles({ PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'development' }),
    ).toBe(true);
  });

  it('fills missing keys without overriding existing values or exporting secrets already present', () => {
    const hydrated = applyEnvFileContents(
      'DATABASE_URL=postgresql://from-file\nLOG_LEVEL=info\nEMPTY=\n',
      { DATABASE_URL: 'postgresql://already-set' },
    );

    expect(hydrated['DATABASE_URL']).toBe('postgresql://already-set');
    expect(hydrated['LOG_LEVEL']).toBe('info');
    expect(hydrated['EMPTY']).toBeUndefined();
  });

  it('finds the repository root .env and skips loading in production', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'patchpilot-env-'));
    writeFileSync(path.join(root, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    writeFileSync(path.join(root, '.env'), 'LOG_LEVEL=debug\n');
    const nested = path.join(root, 'apps', 'api');
    mkdirSync(nested, { recursive: true });

    try {
      expect(findDevelopmentEnvFile(nested)).toBe(path.join(root, '.env'));

      const productionEnv: NodeJS.ProcessEnv = { NODE_ENV: 'production' };
      hydrateProcessEnvFromDevelopmentFiles(productionEnv, { startDirectory: nested });
      expect(productionEnv['LOG_LEVEL']).toBeUndefined();

      const developmentEnv: NodeJS.ProcessEnv = {};
      hydrateProcessEnvFromDevelopmentFiles(developmentEnv, { startDirectory: nested });
      expect(developmentEnv['LOG_LEVEL']).toBe('debug');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
