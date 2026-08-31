export const safeFailureCategories = [
  'validation',
  'limit',
  'storage',
  'timeout',
  'poison',
  'internal',
] as const;
export type SafeFailureCategory = (typeof safeFailureCategories)[number];

export const safeFailureCodes = [
  'payload_too_large',
  'content_type',
  'utf8',
  'json_syntax',
  'json_depth',
  'json_nodes',
  'json_string_length',
  'not_cyclonedx',
  'unsupported_spec_version',
  'schema_invalid',
  'component_limit',
  'edge_limit',
  'identifier_length',
  'tool_limit',
  'reference_limit',
  'property_limit',
  'duplicate_bom_ref',
  'unresolved_dependency_ref',
  'invalid_purl',
  'prototype_pollution',
  'hash_mismatch',
  'object_missing',
  'storage_timeout',
  'parser_timeout',
  'parser_crash',
  'normalized_output_too_large',
  'processing_failed',
  'queue_unavailable',
] as const;
export type SafeFailureCode = (typeof safeFailureCodes)[number];

export const safeFailureOutcomes = [
  'rejected',
  'quarantined',
  'retryable_infrastructure',
  'terminal_internal',
] as const;
export type SafeFailureOutcome = (typeof safeFailureOutcomes)[number];

export type SafeFailureClassification = {
  category: SafeFailureCategory;
  outcome: SafeFailureOutcome;
};

export const safeFailureCatalog: { readonly [Code in SafeFailureCode]: SafeFailureClassification } =
  {
    payload_too_large: { category: 'limit', outcome: 'rejected' },
    content_type: { category: 'validation', outcome: 'rejected' },
    utf8: { category: 'validation', outcome: 'rejected' },
    json_syntax: { category: 'validation', outcome: 'rejected' },
    json_depth: { category: 'limit', outcome: 'rejected' },
    json_nodes: { category: 'limit', outcome: 'rejected' },
    json_string_length: { category: 'limit', outcome: 'rejected' },
    not_cyclonedx: { category: 'validation', outcome: 'rejected' },
    unsupported_spec_version: { category: 'validation', outcome: 'rejected' },
    schema_invalid: { category: 'validation', outcome: 'rejected' },
    component_limit: { category: 'limit', outcome: 'rejected' },
    edge_limit: { category: 'limit', outcome: 'rejected' },
    identifier_length: { category: 'limit', outcome: 'rejected' },
    tool_limit: { category: 'limit', outcome: 'rejected' },
    reference_limit: { category: 'limit', outcome: 'rejected' },
    property_limit: { category: 'limit', outcome: 'rejected' },
    duplicate_bom_ref: { category: 'validation', outcome: 'rejected' },
    unresolved_dependency_ref: { category: 'validation', outcome: 'rejected' },
    invalid_purl: { category: 'validation', outcome: 'rejected' },
    prototype_pollution: { category: 'poison', outcome: 'quarantined' },
    hash_mismatch: { category: 'storage', outcome: 'quarantined' },
    object_missing: { category: 'storage', outcome: 'retryable_infrastructure' },
    storage_timeout: { category: 'storage', outcome: 'retryable_infrastructure' },
    parser_timeout: { category: 'timeout', outcome: 'quarantined' },
    parser_crash: { category: 'poison', outcome: 'quarantined' },
    normalized_output_too_large: { category: 'limit', outcome: 'rejected' },
    processing_failed: { category: 'internal', outcome: 'terminal_internal' },
    queue_unavailable: { category: 'timeout', outcome: 'retryable_infrastructure' },
  };

export function classifySafeFailure(code: SafeFailureCode): SafeFailureClassification {
  return safeFailureCatalog[code];
}

export function isSafeFailureCode(value: string): value is SafeFailureCode {
  return (safeFailureCodes as readonly string[]).includes(value);
}

export function isParserThreadFailureCode(code: SafeFailureCode): boolean {
  const outcome = safeFailureCatalog[code].outcome;
  return outcome === 'rejected' || outcome === 'quarantined';
}

export function parserThreadDisposition(
  code: SafeFailureCode,
): 'rejected' | 'quarantined' | undefined {
  const outcome = safeFailureCatalog[code].outcome;
  if (outcome === 'rejected' || outcome === 'quarantined') {
    return outcome;
  }
  return undefined;
}
