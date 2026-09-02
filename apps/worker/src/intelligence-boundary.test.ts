import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const workerSrc = dirname(fileURLToPath(import.meta.url));

function productionFiles(): string[] {
  return readdirSync(workerSrc)
    .filter(
      (name) =>
        name.startsWith('intelligence-') &&
        name.endsWith('.ts') &&
        !name.includes('.test.') &&
        !name.includes('.integration.'),
    )
    .map((name) => join(workerSrc, name));
}

const BANNED =
  /FindingRepository|FindingObservation|createFinding|finding\.recalculate|VulnerabilityAlias|VulnerabilitySourceRecord|ComponentRepository|ComponentOccurrence|AssetRepository|RiskCalculation|from '@patchpilot\/auth'|cron|node-cron|bullmq-pro|adm-zip|jszip|unzipper/;

describe('intelligence worker zero-Finding boundary', () => {
  it('does not import Finding, matching, ZIP, or cron packages', () => {
    const files = productionFiles();
    expect(files.length).toBeGreaterThan(0);
    for (const filePath of files) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(BANNED);
      expect(source, filePath).not.toContain('www.cisa.gov');
    }
  });

  it('keeps the intelligence processor registered independently of KEV enablement', () => {
    const main = readFileSync(join(workerSrc, 'main.ts'), 'utf8');
    expect(main).toContain('processIntelligenceSyncQueueJob');
    expect(main).toContain('processIntelligence:');
    const router = readFileSync(join(workerSrc, 'queue-job-router.ts'), 'utf8');
    expect(router).toContain('INTELLIGENCE_SYNC_JOB_TYPE');
    expect(router).toContain('processIntelligence');
    const runtime = readFileSync(join(workerSrc, 'intelligence-runtime.ts'), 'utf8');
    expect(runtime).toContain('if (loopsStarted || !options.kevEnabled)');
    expect(runtime).not.toContain('processIntelligence');
  });
});
