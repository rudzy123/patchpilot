export const intelligenceSafeFailureCategories = [
  'configuration',
  'network',
  'timeout',
  'rate_limit',
  'provider',
  'content',
  'integrity',
  'schema',
  'structural_limit',
  'storage',
  'database',
  'parser',
  'catalog_regression',
  'internal',
] as const;
export type IntelligenceSafeFailureCategory = (typeof intelligenceSafeFailureCategories)[number];

export const intelligenceSafeFailureCodes = [
  'provider_disabled',
  'invalid_provider_source',
  'dns_rejected',
  'redirect_rejected',
  'connection_timeout',
  'response_timeout',
  'request_cancelled',
  'rate_limited',
  'provider_client_error',
  'provider_server_error',
  'content_type_invalid',
  'response_too_large',
  'response_empty',
  'utf8_invalid',
  'hash_mismatch',
  'snapshot_missing',
  'snapshot_storage_failed',
  'json_syntax',
  'prototype_pollution',
  'json_depth',
  'json_nodes',
  'json_string_length',
  'normalized_output_too_large',
  'schema_invalid',
  'count_mismatch',
  'duplicate_cve',
  'malformed_cve',
  'vulnerability_count_limit',
  'text_field_limit',
  'cwe_count_limit',
  'catalog_version_missing',
  'catalog_release_date_invalid',
  'catalog_regression',
  'parser_timeout',
  'parser_crash',
  'generation_incomplete',
  'activation_conflict',
  'persistence_failed',
  'processing_failed',
] as const;
export type IntelligenceSafeFailureCode = (typeof intelligenceSafeFailureCodes)[number];

export const intelligenceFailureDispositions = ['failed', 'quarantined'] as const;
export type IntelligenceFailureDisposition = (typeof intelligenceFailureDispositions)[number];

export type IntelligenceSafeFailureClassification = {
  category: IntelligenceSafeFailureCategory;
  retryable: boolean;
  disposition: IntelligenceFailureDisposition;
  snapshotMayExist: boolean;
  freshnessMayAdvance: false;
};

export const intelligenceSafeFailureCatalog: {
  readonly [Code in IntelligenceSafeFailureCode]: IntelligenceSafeFailureClassification;
} = {
  provider_disabled: {
    category: 'configuration',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  invalid_provider_source: {
    category: 'configuration',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  dns_rejected: {
    category: 'network',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  redirect_rejected: {
    category: 'network',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  connection_timeout: {
    category: 'timeout',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  response_timeout: {
    category: 'timeout',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  request_cancelled: {
    category: 'timeout',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  rate_limited: {
    category: 'rate_limit',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  provider_client_error: {
    category: 'provider',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  provider_server_error: {
    category: 'provider',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  content_type_invalid: {
    category: 'content',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  response_too_large: {
    category: 'content',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  response_empty: {
    category: 'content',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  utf8_invalid: {
    category: 'content',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  hash_mismatch: {
    category: 'integrity',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  snapshot_missing: {
    category: 'storage',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: false,
    freshnessMayAdvance: false,
  },
  snapshot_storage_failed: {
    category: 'storage',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  json_syntax: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  prototype_pollution: {
    category: 'parser',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  json_depth: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  json_nodes: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  json_string_length: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  normalized_output_too_large: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  schema_invalid: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  count_mismatch: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  duplicate_cve: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  malformed_cve: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  vulnerability_count_limit: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  text_field_limit: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  cwe_count_limit: {
    category: 'structural_limit',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  catalog_version_missing: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  catalog_release_date_invalid: {
    category: 'schema',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  catalog_regression: {
    category: 'catalog_regression',
    retryable: false,
    disposition: 'quarantined',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  parser_timeout: {
    category: 'parser',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  parser_crash: {
    category: 'parser',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  generation_incomplete: {
    category: 'internal',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  activation_conflict: {
    category: 'database',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  persistence_failed: {
    category: 'database',
    retryable: true,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
  processing_failed: {
    category: 'internal',
    retryable: false,
    disposition: 'failed',
    snapshotMayExist: true,
    freshnessMayAdvance: false,
  },
};

const quarantineCategories = new Set<IntelligenceSafeFailureCategory>([
  'content',
  'integrity',
  'schema',
  'structural_limit',
  'parser',
  'catalog_regression',
]);

export function classifyIntelligenceSafeFailure(
  code: IntelligenceSafeFailureCode,
): IntelligenceSafeFailureClassification {
  return intelligenceSafeFailureCatalog[code];
}

export function isIntelligenceSafeFailureCode(value: string): value is IntelligenceSafeFailureCode {
  return (intelligenceSafeFailureCodes as readonly string[]).includes(value);
}

export function isIntelligenceQuarantineCategory(
  category: IntelligenceSafeFailureCategory,
): boolean {
  return quarantineCategories.has(category);
}

export function intelligenceParserThreadDisposition(
  code: IntelligenceSafeFailureCode,
): IntelligenceFailureDisposition {
  return intelligenceSafeFailureCatalog[code].disposition;
}

export function intelligenceFailureFreshnessMayAdvance(_code: IntelligenceSafeFailureCode): false {
  return false;
}
