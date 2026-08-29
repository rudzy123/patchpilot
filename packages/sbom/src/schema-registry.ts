import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ValidateFunction } from 'ajv';

import { createOfflineAjv } from './offline-ajv.js';
import { VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY } from './vendor-directory.js';

export const ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS = ['1.4', '1.5', '1.6'] as const;

export type AllowlistedCycloneDxSpecVersion = (typeof ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS)[number];

const BOM_SCHEMA_FILES = {
  '1.4': 'bom-1.4.schema.json',
  '1.5': 'bom-1.5.schema.json',
  '1.6': 'bom-1.6.schema.json',
} as const;

const SHARED_SCHEMA_FILES = ['jsf-0.82.schema.json', 'spdx.schema.json'] as const;

export type CycloneDxSchemaValidation =
  | { ok: true; specVersion: AllowlistedCycloneDxSpecVersion }
  | { ok: false; reason: 'unsupported_spec_version' | 'schema_invalid' };

let compiledValidators: Record<AllowlistedCycloneDxSpecVersion, ValidateFunction> | undefined;

function readVendorJson(fileName: string): object {
  const text = readFileSync(join(VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY, fileName), 'utf8');
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Vendored schema ${fileName} is not a JSON object.`);
  }
  return parsed;
}

function stripIgnoredAdditionalItems(node: unknown): void {
  if (Array.isArray(node)) {
    for (const item of node) {
      stripIgnoredAdditionalItems(item);
    }
    return;
  }
  if (typeof node !== 'object' || node === null) {
    return;
  }
  const record = node as Record<string, unknown>;
  const items = record['items'];
  if ('additionalItems' in record && items !== undefined && !Array.isArray(items)) {
    // Draft-07 ignores additionalItems unless `items` is a tuple. CycloneDX JSON
    // schemas still include additionalItems: false on list schemas. Strip it from
    // the in-memory copy so Ajv strict mode can compile; vendor files stay intact.
    delete record['additionalItems'];
  }
  for (const value of Object.values(record)) {
    stripIgnoredAdditionalItems(value);
  }
}

export function readVendoredSchemaFile(fileName: string): object {
  const schema = structuredClone(readVendorJson(fileName));
  stripIgnoredAdditionalItems(schema);
  return schema;
}

export function compileAllowlistedCycloneDxSchemas(): Record<
  AllowlistedCycloneDxSpecVersion,
  ValidateFunction
> {
  const ajv = createOfflineAjv();
  for (const fileName of SHARED_SCHEMA_FILES) {
    ajv.addSchema(readVendoredSchemaFile(fileName));
  }

  return {
    '1.4': ajv.compile(readVendoredSchemaFile(BOM_SCHEMA_FILES['1.4'])),
    '1.5': ajv.compile(readVendoredSchemaFile(BOM_SCHEMA_FILES['1.5'])),
    '1.6': ajv.compile(readVendoredSchemaFile(BOM_SCHEMA_FILES['1.6'])),
  };
}

function validators(): Record<AllowlistedCycloneDxSpecVersion, ValidateFunction> {
  compiledValidators ??= compileAllowlistedCycloneDxSchemas();
  return compiledValidators;
}

export function selectAllowlistedSpecVersion(
  document: unknown,
): AllowlistedCycloneDxSpecVersion | undefined {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    return undefined;
  }
  const specVersion = (document as Record<string, unknown>)['specVersion'];
  if (specVersion === '1.4' || specVersion === '1.5' || specVersion === '1.6') {
    return specVersion;
  }
  return undefined;
}

export function validateCycloneDxDocument(document: unknown): CycloneDxSchemaValidation {
  const specVersion = selectAllowlistedSpecVersion(document);
  if (specVersion === undefined) {
    return { ok: false, reason: 'unsupported_spec_version' };
  }
  const valid = validators()[specVersion](document);
  if (!valid) {
    return { ok: false, reason: 'schema_invalid' };
  }
  return { ok: true, specVersion };
}
