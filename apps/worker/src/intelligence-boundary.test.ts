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
});
