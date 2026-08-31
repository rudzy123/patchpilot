import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcRoot = join(packageRoot, 'src');

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
    if (entry.name === 'hang-worker-thread.ts') {
      continue;
    }
    if (entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('@patchpilot/sbom session 8 batch 3 boundary', () => {
  it('does not import Prisma, AWS SDK, BullMQ, Redis, Fastify, Next.js, or process.env', () => {
    const files = productionTypeScriptFiles(srcRoot);
    expect(files.length).toBeGreaterThan(0);
    const banned =
      /@prisma\/client|@aws-sdk|S3Client|bullmq|ioredis|from 'fastify'|from "fastify"|from 'next'|process\.env/;
    for (const filePath of files) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(banned);
    }
  });

  it('keeps parser-thread DTOs free of tenant and storage identifiers', () => {
    const source = readFileSync(join(srcRoot, 'parser-thread.ts'), 'utf8');
    expect(source).toContain('requestId');
    expect(source).toContain('expectedSha256');
    expect(source).not.toMatch(
      /organizationId|assetId|sbomId|objectKey|filename|credentials|endpoint/,
    );
  });
});
