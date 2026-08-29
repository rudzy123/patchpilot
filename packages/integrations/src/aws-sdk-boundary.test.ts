import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcRoot = join(packageRoot, 'src');
const workspaceRoot = join(packageRoot, '..', '..');

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

describe('@aws-sdk/client-s3 boundary', () => {
  it('imports under Node 24 without constructing a client', async () => {
    expect(process.versions.node.startsWith('24.')).toBe(true);
    const loaded = await import('@aws-sdk/client-s3');
    expect(loaded.S3Client).toBeTypeOf('function');
  });

  it('does not use the default AWS credential-provider chain in production code', () => {
    const productionFiles = productionTypeScriptFiles(srcRoot);
    expect(productionFiles.length).toBeGreaterThan(0);
    const credentialChain =
      /defaultProvider|fromNodeProviderChain|fromIni\(|fromEnv\(|fromInstanceMetadata|fromContainerMetadata|createCredentialChain|credentialDefaultProvider/;
    const publicAcl = /public-read-write|public-read|ObjectCannedACL|CannedACL/;

    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(credentialChain);
      expect(source, filePath).not.toMatch(publicAcl);
      expect(source, filePath).not.toMatch(/\bACL\s*:/);
    }
  });

  it('does not declare MinIO or multipart upload helpers in this package', () => {
    const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
    };
    const dependencies = manifest.dependencies ?? {};
    expect(dependencies['@aws-sdk/client-s3']).toBe('3.1120.0');
    expect(dependencies).not.toHaveProperty('@aws-sdk/lib-storage');
    expect(dependencies).not.toHaveProperty('minio');
  });

  it('does not add a pnpm override for this client', () => {
    const lockfile = readFileSync(join(workspaceRoot, 'pnpm-lock.yaml'), 'utf8');
    const workspace = readFileSync(join(workspaceRoot, 'pnpm-workspace.yaml'), 'utf8');
    expect(lockfile).not.toMatch(/^overrides:/m);
    expect(workspace).not.toMatch(/^overrides:/m);
    expect(workspace).not.toContain('pnpm.overrides');
    expect(workspace).not.toContain('minimumReleaseAgeExclude');
  });
});
