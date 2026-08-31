import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = join(packageRoot, '..', '..');

const BANNED_PACKAGES = [
  '@aws-sdk/lib-storage',
  'minio',
  '@cyclonedx/cyclonedx-library',
  'ajv-formats-draft2019',
  '@fastify/multipart',
  'libxmljs2',
  'fast-xml-parser',
  'xml2js',
] as const;

describe('approved Session 8 Batch 2 dependencies', () => {
  it('pins the approved packages and omits banned parsers and upload helpers', () => {
    const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    const dependencies = manifest.dependencies ?? {};
    expect(dependencies['ajv']).toBe('8.20.0');
    expect(dependencies['ajv-formats']).toBe('3.0.1');
    expect(dependencies['packageurl-js']).toBe('2.0.1');
    expect(dependencies['secure-json-parse']).toBe('4.1.0');
    for (const name of BANNED_PACKAGES) {
      expect(dependencies).not.toHaveProperty(name);
    }
    expect(manifest.scripts ?? {}).not.toHaveProperty('vendor');
    expect(JSON.stringify(manifest.scripts ?? {})).not.toContain('vendor-cyclonedx');
  });

  it('does not download CycloneDX schemas from CI or the vendor script lifecycle', () => {
    const ci = readFileSync(join(workspaceRoot, '.github/workflows/ci.yml'), 'utf8');
    const packageJson = readFileSync(join(workspaceRoot, 'package.json'), 'utf8');
    expect(ci).not.toContain('cyclonedx.org/schema');
    expect(ci).not.toContain('vendor-cyclonedx-json-schema');
    expect(packageJson).not.toContain('vendor-cyclonedx-json-schema');
  });
});
