import { describe, expect, it } from 'vitest';

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { PackageURL } from 'packageurl-js';
import secureJsonParse from 'secure-json-parse';

import { packageBoundary } from './index.js';

describe('@patchpilot/sbom', () => {
  it('exports a package boundary for the worker-thread parser', () => {
    expect(packageBoundary).toBe('@patchpilot/sbom');
  });

  it('imports approved packages under NodeNext', () => {
    expect(Ajv).toBeTypeOf('function');
    expect(addFormats).toBeTypeOf('function');
    expect(PackageURL).toBeTypeOf('function');
    expect(secureJsonParse).toBeTypeOf('function');
  });
});
