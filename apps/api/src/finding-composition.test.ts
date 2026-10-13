import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

function source(relative: string): string {
  return readFileSync(path.join(repoRoot, relative), 'utf8');
}

describe('controlled finding API composition', () => {
  it('constructs creation and inspection only from the API runtime', () => {
    const runtime = source('apps/api/src/finding-runtime.ts');
    const server = source('apps/api/src/server.ts');
    const routes = source('apps/api/src/finding-routes.ts');
    expect(server).toContain('composeControlledFindingOperatorRuntime');
    expect(runtime).toContain('createControlledFindingCreationApplication');
    expect(runtime).toContain('createControlledFindingInspectionApplication');
    expect(runtime).toContain('createControlledFindingCreationPersistence');
    expect(runtime).toContain('createControlledFindingInspectionPersistence');
    expect(runtime).toContain('createControlledFindingLatestObservationApplication');
    expect(runtime).toContain(`createControlledFindingLatestObservation${'Read'}`);
    expect(runtime).not.toContain('issueFindingCreationAuthorization');
    expect(runtime).not.toContain(`selectFindingLatest${'Observation'}`);
    expect(runtime).not.toContain('createControlledFindingRepeatedObservationPersistence');
    expect(runtime).not.toContain('openFindingInspection');
    expect(routes).not.toContain('issueFindingCreationAuthorization');
    expect(routes).not.toContain('createControlledFindingCreationPersistence');
    expect(routes).not.toContain('@patchpilot/database');
    const latest = source('apps/api/src/finding-latest-observation-routes.ts');
    const latestHttp = source('apps/api/src/finding-latest-observation-http.ts');
    expect(latestHttp).toContain("'/findings/:findingId/latest-observation'");
    expect(latest).not.toContain('@patchpilot/database');
    expect(latest).not.toContain(`selectFindingLatest${'Observation'}`);
    expect(latest).not.toContain(`createControlledFindingLatestObservation${'Read'}`);
    expect(latest).not.toContain('createControlledFindingRepeatedObservationPersistence');
    expect(latest).not.toContain('@prisma/client');
    expect(routes).not.toContain('vulnerability-intelligence');
    expect(runtime).not.toContain('bullmq');
    expect(runtime).not.toContain('osv.dev');
    expect(runtime).not.toContain('createProductMatchEvaluationComposition');

    for (const relative of [
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'packages/database/src/seed/development.ts',
    ]) {
      const text = source(relative);
      expect(text, relative).not.toContain('composeControlledFindingOperatorRuntime');
      expect(text, relative).not.toContain('createControlledFindingCreationApplication');
      expect(text, relative).not.toContain('createControlledFindingInspectionApplication');
      expect(text, relative).not.toContain('createControlledFindingLatestObservationApplication');
      expect(text, relative).not.toContain('/findings');
    }
  });
});
