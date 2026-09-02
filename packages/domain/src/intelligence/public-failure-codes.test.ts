import { describe, expect, it } from 'vitest';

import { intelligenceSafeFailureCodes } from './failures.js';
import {
  intelligencePublicFailureCodes,
  isIntelligencePublicFailureCode,
  mapInternalFailureCodeToPublic,
  publicFailureCodeEqualsInternalCode,
} from './public-failure-codes.js';

const EXPECTED_PUBLIC_BY_INTERNAL: Record<string, string> = {
  dns_rejected: 'provider_unavailable',
  redirect_rejected: 'provider_unavailable',
  rate_limited: 'provider_unavailable',
  provider_client_error: 'provider_unavailable',
  provider_server_error: 'provider_unavailable',
  request_cancelled: 'provider_unavailable',
  connection_timeout: 'synchronization_timeout',
  response_timeout: 'synchronization_timeout',
  parser_timeout: 'synchronization_timeout',
  content_type_invalid: 'invalid_provider_response',
  response_too_large: 'invalid_provider_response',
  response_empty: 'invalid_provider_response',
  utf8_invalid: 'invalid_provider_response',
  json_syntax: 'invalid_provider_response',
  prototype_pollution: 'invalid_provider_response',
  json_depth: 'invalid_provider_response',
  json_nodes: 'invalid_provider_response',
  json_string_length: 'invalid_provider_response',
  schema_invalid: 'invalid_provider_response',
  count_mismatch: 'invalid_provider_response',
  duplicate_cve: 'invalid_provider_response',
  malformed_cve: 'invalid_provider_response',
  vulnerability_count_limit: 'invalid_provider_response',
  text_field_limit: 'invalid_provider_response',
  cwe_count_limit: 'invalid_provider_response',
  catalog_version_missing: 'invalid_provider_response',
  catalog_release_date_invalid: 'invalid_provider_response',
  normalized_output_too_large: 'invalid_provider_response',
  snapshot_missing: 'storage_unavailable',
  snapshot_storage_failed: 'storage_unavailable',
  hash_mismatch: 'storage_unavailable',
  parser_crash: 'processing_failed',
  generation_incomplete: 'processing_failed',
  activation_conflict: 'processing_failed',
  persistence_failed: 'processing_failed',
  processing_failed: 'processing_failed',
  invalid_provider_source: 'processing_failed',
  provider_disabled: 'processing_failed',
  catalog_regression: 'catalog_regression',
};

describe('public intelligence failure codes', () => {
  it('maps every internal safe code into one public code', () => {
    expect([...intelligenceSafeFailureCodes].sort()).toEqual(
      Object.keys(EXPECTED_PUBLIC_BY_INTERNAL).sort(),
    );
    for (const code of intelligenceSafeFailureCodes) {
      expect(mapInternalFailureCodeToPublic(code)).toBe(EXPECTED_PUBLIC_BY_INTERNAL[code]);
    }
  });

  it('maps null to null and unknown persisted codes to processing_failed', () => {
    expect(mapInternalFailureCodeToPublic(null)).toBeNull();
    expect(mapInternalFailureCodeToPublic('not_a_real_code')).toBe('processing_failed');
    expect(mapInternalFailureCodeToPublic('ECONNRESET')).toBe('processing_failed');
  });

  it('does not leak internal codes unchanged unless they are deliberately identical', () => {
    for (const code of intelligenceSafeFailureCodes) {
      const mapped = mapInternalFailureCodeToPublic(code);
      if (code === mapped) {
        expect(publicFailureCodeEqualsInternalCode(code)).toBe(true);
        expect(code === 'catalog_regression' || code === 'processing_failed').toBe(true);
      } else {
        expect(intelligencePublicFailureCodes.includes(code as never)).toBe(false);
      }
    }
  });

  it('closes the public allowlist and maps catalog_regression correctly', () => {
    expect(intelligencePublicFailureCodes).toEqual([
      'provider_unavailable',
      'synchronization_timeout',
      'invalid_provider_response',
      'storage_unavailable',
      'processing_failed',
      'catalog_regression',
    ]);
    expect(mapInternalFailureCodeToPublic('catalog_regression')).toBe('catalog_regression');
    expect(isIntelligencePublicFailureCode('schema_invalid')).toBe(false);
    expect(isIntelligencePublicFailureCode('provider_unavailable')).toBe(true);
  });
});
