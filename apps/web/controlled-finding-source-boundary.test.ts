import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const webRoot = path.dirname(fileURLToPath(import.meta.url));

const SOURCE_FILES = [
  'lib/auth-api.ts',
  'lib/finding-permissions.ts',
  'lib/finding-workflow.ts',
  'lib/resource-id.ts',
  'components/controlled-finding-confirmation-dialog.tsx',
  'components/affected-version-summary.tsx',
  'components/safe-request-identifiers.tsx',
  'app/assets/[assetId]/asset-detail-page-client.tsx',
  'app/assets/[assetId]/findings/targets/page.tsx',
  'app/assets/[assetId]/findings/targets/controlled-finding-targets-page-client.tsx',
  'app/findings/[findingId]/page.tsx',
  'app/findings/[findingId]/finding-inspection-page-client.tsx',
  'next.config.ts',
];

const FORBIDDEN = [
  '@prisma/client',
  '@patchpilot/database',
  '@patchpilot/domain',
  'bullmq',
  'ioredis',
  'dangerouslySetInnerHTML',
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'innerHTML',
  'document.write',
  'worker_threads',
  'from "next/server"',
  "from 'next/server'",
];

describe('controlled Finding web source boundary', () => {
  it('stays an API client without persistence, workers, or unsafe HTML', () => {
    for (const relativePath of SOURCE_FILES) {
      const source = readFileSync(path.join(webRoot, relativePath), 'utf8');
      for (const forbidden of FORBIDDEN) {
        expect(source, `${relativePath} contains ${forbidden}`).not.toContain(forbidden);
      }
      expect(source, relativePath).not.toContain('console.');
    }
  });

  it('does not add a Finding list route', () => {
    const findingsDir = path.join(webRoot, 'app/findings');
    const names = readdirSync(findingsDir);
    expect(names).not.toContain('page.tsx');
    expect(statSync(path.join(findingsDir, '[findingId]/page.tsx')).isFile()).toBe(true);
  });
});
