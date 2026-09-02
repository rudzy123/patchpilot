export const intelligencePublicFailureCodes = [
  'provider_unavailable',
  'synchronization_timeout',
  'invalid_provider_response',
  'storage_unavailable',
  'processing_failed',
  'catalog_regression',
] as const;
export type IntelligencePublicFailureCode = (typeof intelligencePublicFailureCodes)[number];

const PROVIDER_UNAVAILABLE_CODES = new Set<string>([
  'dns_rejected',
  'redirect_rejected',
  'rate_limited',
  'provider_client_error',
  'provider_server_error',
  'request_cancelled',
]);

const SYNCHRONIZATION_TIMEOUT_CODES = new Set<string>([
  'connection_timeout',
  'response_timeout',
  'parser_timeout',
]);

const INVALID_PROVIDER_RESPONSE_CODES = new Set<string>([
  'content_type_invalid',
  'response_too_large',
  'response_empty',
  'utf8_invalid',
  'json_syntax',
  'prototype_pollution',
  'json_depth',
  'json_nodes',
  'json_string_length',
  'schema_invalid',
  'count_mismatch',
  'duplicate_cve',
  'malformed_cve',
  'vulnerability_count_limit',
  'text_field_limit',
  'cwe_count_limit',
  'catalog_version_missing',
  'catalog_release_date_invalid',
  'normalized_output_too_large',
]);

const STORAGE_UNAVAILABLE_CODES = new Set<string>([
  'snapshot_missing',
  'snapshot_storage_failed',
  'hash_mismatch',
]);

const IDENTICAL_PUBLIC_CODES = new Set<string>(['catalog_regression', 'processing_failed']);

export function isIntelligencePublicFailureCode(
  value: string,
): value is IntelligencePublicFailureCode {
  return (intelligencePublicFailureCodes as readonly string[]).includes(value);
}

export function mapInternalFailureCodeToPublic(
  code: string | null,
): IntelligencePublicFailureCode | null {
  if (code === null) {
    return null;
  }

  if (PROVIDER_UNAVAILABLE_CODES.has(code)) {
    return 'provider_unavailable';
  }
  if (SYNCHRONIZATION_TIMEOUT_CODES.has(code)) {
    return 'synchronization_timeout';
  }
  if (INVALID_PROVIDER_RESPONSE_CODES.has(code)) {
    return 'invalid_provider_response';
  }
  if (STORAGE_UNAVAILABLE_CODES.has(code)) {
    return 'storage_unavailable';
  }
  if (code === 'catalog_regression') {
    return 'catalog_regression';
  }

  return 'processing_failed';
}

export function publicFailureCodeEqualsInternalCode(code: string): boolean {
  return IDENTICAL_PUBLIC_CODES.has(code);
}
