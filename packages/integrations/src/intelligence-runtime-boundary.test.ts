import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const srcRoot = join(dirname(fileURLToPath(import.meta.url)));

function productionTypeScriptFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...productionTypeScriptFiles(fullPath));
      continue;
    }

    if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.integration.test.ts')) {
      continue;
    }

    if (entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }

  return files;
}

const INTELLIGENCE_FILES = [
  'cisa-kev-https.ts',
  'intelligence-address-policy.ts',
  'intelligence-http-media-type.ts',
  'intelligence-http-retry.ts',
  'intelligence-http-stream.ts',
  's3-intelligence-snapshot-storage.ts',
  's3-osv-advisory-object-storage.ts',
];

describe('intelligence runtime boundary', () => {
  it('keeps CISA HTTP and snapshot storage free of database, parser, queue, and ZIP runtimes', () => {
    const banned =
      /@patchpilot\/database|@prisma\/client|FindingRepository|FindingObservation|ComponentRepository|AssetRepository|RiskCalculation|from 'bullmq'|from "bullmq"|from 'fastify'|from "fastify"|worker_threads|process\.env|from 'yauzl'|from "yauzl"|from 'jszip'|from "jszip"|undici|node-fetch|axios|got\b|proxy-agent/;
    for (const fileName of INTELLIGENCE_FILES) {
      const source = readFileSync(join(srcRoot, fileName), 'utf8');
      expect(source, fileName).not.toMatch(banned);
      expect(source, fileName).not.toContain('globalThis.fetch');
    }
  });

  it('does not contact CISA merely by importing the transport module', async () => {
    const production = productionTypeScriptFiles(srcRoot).filter((filePath) =>
      filePath.endsWith('cisa-kev-https.ts'),
    );
    expect(production).toHaveLength(1);
    const source = readFileSync(production[0] ?? '', 'utf8');
    expect(source).toContain('https.request');
    expect(source).not.toContain('fetch(');
    const loaded = await import('./cisa-kev-https.js');
    expect(typeof loaded.createCisaKevHttpsTransport).toBe('function');
  });
});
