import { describe, expect, it } from 'vitest';

import {
  classifySafeFailure,
  isParserThreadFailureCode,
  parserThreadDisposition,
  safeFailureCatalog,
  safeFailureCategories,
  safeFailureCodes,
  safeFailureOutcomes,
} from './failures.js';

describe('safe failure taxonomy', () => {
  it('is a closed category and code catalog', () => {
    expect(safeFailureCategories).toEqual([
      'validation',
      'limit',
      'storage',
      'timeout',
      'poison',
      'internal',
    ]);
    expect(safeFailureOutcomes).toEqual([
      'rejected',
      'quarantined',
      'retryable_infrastructure',
      'terminal_internal',
    ]);
    expect(safeFailureCodes).toHaveLength(28);
    expect(Object.keys(safeFailureCatalog).sort()).toEqual([...safeFailureCodes].sort());
  });

  it('classifies every code without provider exception messages', () => {
    for (const code of safeFailureCodes) {
      const classification = classifySafeFailure(code);
      expect(safeFailureCategories).toContain(classification.category);
      expect(safeFailureOutcomes).toContain(classification.outcome);
      expect(JSON.stringify(classification)).not.toMatch(/Error|exception|stack/i);
    }
  });

  it('maps approved conditions to the documented outcomes', () => {
    expect(classifySafeFailure('payload_too_large')).toEqual({
      category: 'limit',
      outcome: 'rejected',
    });
    expect(classifySafeFailure('content_type').outcome).toBe('rejected');
    expect(classifySafeFailure('schema_invalid').outcome).toBe('rejected');
    expect(classifySafeFailure('unresolved_dependency_ref').outcome).toBe('rejected');
    expect(classifySafeFailure('prototype_pollution')).toEqual({
      category: 'poison',
      outcome: 'quarantined',
    });
    expect(classifySafeFailure('parser_timeout').outcome).toBe('quarantined');
    expect(classifySafeFailure('storage_timeout')).toEqual({
      category: 'storage',
      outcome: 'retryable_infrastructure',
    });
    expect(classifySafeFailure('processing_failed')).toEqual({
      category: 'internal',
      outcome: 'terminal_internal',
    });
    expect(classifySafeFailure('queue_unavailable')).toEqual({
      category: 'timeout',
      outcome: 'retryable_infrastructure',
    });
  });

  it('limits parser-thread failures to rejected or quarantined dispositions', () => {
    expect(isParserThreadFailureCode('schema_invalid')).toBe(true);
    expect(parserThreadDisposition('schema_invalid')).toBe('rejected');
    expect(isParserThreadFailureCode('storage_timeout')).toBe(false);
    expect(parserThreadDisposition('processing_failed')).toBeUndefined();
  });
});
