import { readFileSync } from 'node:fs';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createOfflineAjv } from './offline-ajv.js';
import {
  ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS,
  compileAllowlistedCycloneDxSchemas,
  readVendoredSchemaFile,
  selectAllowlistedSpecVersion,
  validateCycloneDxDocument,
} from './schema-registry.js';
import { parseUntrustedJson } from './untrusted-json.js';

const fixtureDirectory = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

function readFixture(fileName: string): unknown {
  return parseUntrustedJson(readFileSync(join(fixtureDirectory, fileName), 'utf8'));
}

describe('CycloneDX schema compilation', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('compiles CycloneDX 1.4, 1.5, and 1.6 offline', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const httpRequest = vi.spyOn(http, 'request');
    const httpsRequest = vi.spyOn(https, 'request');
    const httpGet = vi.spyOn(http, 'get');
    const httpsGet = vi.spyOn(https, 'get');
    const dnsLookup = vi.spyOn(dns, 'lookup');
    const netConnect = vi.spyOn(net, 'connect');

    const validators = compileAllowlistedCycloneDxSchemas();

    expect(Object.keys(validators)).toEqual(['1.4', '1.5', '1.6']);
    expect(validators['1.4']).toBeTypeOf('function');
    expect(validators['1.5']).toBeTypeOf('function');
    expect(validators['1.6']).toBeTypeOf('function');
    expect(ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS).toEqual(['1.4', '1.5', '1.6']);
    expect(ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS).not.toContain('1.3');
    expect(ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS).not.toContain('1.7');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(httpRequest).not.toHaveBeenCalled();
    expect(httpsRequest).not.toHaveBeenCalled();
    expect(httpGet).not.toHaveBeenCalled();
    expect(httpsGet).not.toHaveBeenCalled();
    expect(dnsLookup).not.toHaveBeenCalled();
    expect(netConnect).not.toHaveBeenCalled();
  });

  it('fails closed when a local $ref is missing', () => {
    const ajv = createOfflineAjv();
    expect(() =>
      ajv.compile({
        $id: 'http://patchpilot.test/missing-ref.schema.json',
        $ref: 'not-vendored.schema.json',
      }),
    ).toThrow(/can't resolve reference|MissingRef/i);

    const bom16 = readVendoredSchemaFile('bom-1.6.schema.json');
    expect(() => createOfflineAjv().compile(bom16)).toThrow(/can't resolve reference|MissingRef/i);
  });

  it('validates synthetic CycloneDX 1.4, 1.5, and 1.6 fixtures', () => {
    expect(validateCycloneDxDocument(readFixture('valid-1.4.json'))).toEqual({
      ok: true,
      specVersion: '1.4',
    });
    expect(validateCycloneDxDocument(readFixture('valid-1.5.json'))).toEqual({
      ok: true,
      specVersion: '1.5',
    });
    expect(validateCycloneDxDocument(readFixture('valid-1.6.json'))).toEqual({
      ok: true,
      specVersion: '1.6',
    });
  });

  it('does not select unsupported CycloneDX 1.3 or 1.7', () => {
    const unsupported13 = readFixture('unsupported-1.3.json');
    const unsupported17 = readFixture('unsupported-1.7.json');
    expect(selectAllowlistedSpecVersion(unsupported13)).toBeUndefined();
    expect(selectAllowlistedSpecVersion(unsupported17)).toBeUndefined();
    expect(validateCycloneDxDocument(unsupported13)).toEqual({
      ok: false,
      reason: 'unsupported_spec_version',
    });
    expect(validateCycloneDxDocument(unsupported17)).toEqual({
      ok: false,
      reason: 'unsupported_spec_version',
    });
  });

  it('rejects schema-invalid synthetic data after version selection', () => {
    expect(validateCycloneDxDocument(readFixture('schema-invalid-1.4.json'))).toEqual({
      ok: false,
      reason: 'schema_invalid',
    });
  });
});
