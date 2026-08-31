import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY } from './vendor-directory.js';

type ProvenanceFile = {
  localPath: string;
  sourcePath: string;
  sha256: string;
};

type Provenance = {
  schemaVersion: string;
  sourceRepository: string;
  sourceTag: string;
  sourceCommit: string;
  retrievedAt: string;
  license: string;
  licenseFile: string;
  files: ProvenanceFile[];
};

const PINNED_COMMIT = '8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7';

const REQUIRED_SCHEMAS = [
  'bom-1.4.schema.json',
  'bom-1.5.schema.json',
  'bom-1.6.schema.json',
  'jsf-0.82.schema.json',
  'spdx.schema.json',
] as const;

function readProvenance(): Provenance {
  return JSON.parse(
    readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, 'PROVENANCE.json'), 'utf8'),
  ) as Provenance;
}

function parseSha256Sums(): Map<string, string> {
  const text = readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, 'SHA256SUMS'), 'utf8');
  const sums = new Map<string, string>();
  for (const line of text.split('\n')) {
    if (line.length === 0) {
      continue;
    }
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    expect(match).not.toBeNull();
    const digest = match?.[1];
    const fileName = match?.[2];
    expect(digest).toBeDefined();
    expect(fileName).toBeDefined();
    if (digest !== undefined && fileName !== undefined) {
      sums.set(fileName, digest);
    }
  }
  return sums;
}

describe('vendored CycloneDX JSON schemas', () => {
  it('matches SHA256SUMS for every checksummed file', () => {
    const sums = parseSha256Sums();
    expect(sums.size).toBeGreaterThan(0);
    for (const [fileName, expected] of sums) {
      const bytes = readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, fileName));
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(expected);
    }
  });

  it('records the resolved source commit in PROVENANCE.json', () => {
    const provenance = readProvenance();
    expect(provenance.sourceTag).toBe('1.6.1');
    expect(provenance.sourceRepository).toBe('https://github.com/CycloneDX/specification');
    expect(provenance.sourceCommit).toBe(PINNED_COMMIT);
    expect(provenance.sourceCommit).toMatch(/^[0-9a-f]{40}$/);
    expect(provenance.license).toBe('Apache-2.0');
    expect(provenance.licenseFile).toBe('LICENSE');
  });

  it('references every vendored schema in PROVENANCE.json', () => {
    const provenance = readProvenance();
    const schemaFiles = readdirSync(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY).filter((name) =>
      name.endsWith('.schema.json'),
    );
    const listedSchemas = provenance.files
      .map((file) => file.localPath)
      .filter((name) => name.endsWith('.schema.json'));

    expect(listedSchemas.sort()).toEqual([...REQUIRED_SCHEMAS].sort());
    expect(schemaFiles.sort()).toEqual(listedSchemas.sort());

    for (const file of provenance.files) {
      expect(existsSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, file.localPath))).toBe(true);
      expect(file.sourcePath.length).toBeGreaterThan(0);
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('does not contain unlisted schema files', () => {
    const provenance = readProvenance();
    const listed = new Set(provenance.files.map((file) => file.localPath));
    const schemaFiles = readdirSync(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY).filter((name) =>
      name.endsWith('.schema.json'),
    );
    for (const fileName of schemaFiles) {
      expect(listed.has(fileName)).toBe(true);
    }
    expect(schemaFiles).not.toContain('bom-1.3.schema.json');
    expect(schemaFiles).not.toContain('bom-1.7.schema.json');
    expect(schemaFiles.some((name) => name.includes('strict'))).toBe(false);
  });

  it('does not vendor XML or protobuf schemas', () => {
    const names = readdirSync(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY);
    expect(names.filter((name) => name.endsWith('.xsd') || name.endsWith('.xml'))).toEqual([]);
    expect(names.filter((name) => name.endsWith('.proto'))).toEqual([]);
  });

  it('includes the Apache-2.0 NOTICE and LICENSE', () => {
    const notice = readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, 'NOTICE'), 'utf8');
    const license = readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, 'LICENSE'), 'utf8');
    expect(notice).toContain('OWASP Foundation');
    expect(notice).toContain('Apache License, Version 2.0');
    expect(license).toContain('Apache License');
  });
});
