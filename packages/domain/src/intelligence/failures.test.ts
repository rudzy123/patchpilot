import { describe, expect, it } from 'vitest';

import {
  classifyIntelligenceSafeFailure,
  intelligenceFailureFreshnessMayAdvance,
  intelligenceSafeFailureCatalog,
  intelligenceSafeFailureCategories,
  intelligenceSafeFailureCodes,
} from './failures.js';

describe('intelligence safe failure taxonomy', () => {
  it('closes categories and codes without exposing provider errors', () => {
    expect(intelligenceSafeFailureCategories).toEqual([
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
    ]);
    expect(intelligenceSafeFailureCodes).toContain('provider_disabled');
    expect(intelligenceSafeFailureCodes).toContain('catalog_regression');
    expect(intelligenceSafeFailureCodes).toContain('normalized_output_too_large');
    expect(intelligenceSafeFailureCodes).not.toContain('ECONNRESET');
    expect(Object.keys(intelligenceSafeFailureCatalog)).toHaveLength(
      intelligenceSafeFailureCodes.length,
    );
  });

  it('classifies retryability, disposition, snapshot presence, and freshness', () => {
    const timeout = classifyIntelligenceSafeFailure('connection_timeout');
    expect(timeout.retryable).toBe(true);
    expect(timeout.disposition).toBe('failed');
    expect(timeout.snapshotMayExist).toBe(false);
    expect(timeout.freshnessMayAdvance).toBe(false);

    const schema = classifyIntelligenceSafeFailure('schema_invalid');
    expect(schema.retryable).toBe(false);
    expect(schema.disposition).toBe('quarantined');
    expect(schema.snapshotMayExist).toBe(true);
    expect(schema.freshnessMayAdvance).toBe(false);

    const regression = classifyIntelligenceSafeFailure('catalog_regression');
    expect(regression.category).toBe('catalog_regression');
    expect(regression.disposition).toBe('quarantined');

    const outputTooLarge = classifyIntelligenceSafeFailure('normalized_output_too_large');
    expect(outputTooLarge.category).toBe('structural_limit');
    expect(outputTooLarge.disposition).toBe('quarantined');
    expect(outputTooLarge.retryable).toBe(false);
    expect(outputTooLarge.snapshotMayExist).toBe(true);
    expect(outputTooLarge.freshnessMayAdvance).toBe(false);

    expect(intelligenceFailureFreshnessMayAdvance('processing_failed')).toBe(false);
  });

  it('classifies parser timeout and crash as retryable infrastructure failures', () => {
    const timeout = classifyIntelligenceSafeFailure('parser_timeout');
    expect(timeout.retryable).toBe(true);
    expect(timeout.disposition).toBe('failed');
    expect(timeout.category).toBe('parser');
    expect(timeout.snapshotMayExist).toBe(true);
    expect(timeout.freshnessMayAdvance).toBe(false);

    const crash = classifyIntelligenceSafeFailure('parser_crash');
    expect(crash.retryable).toBe(true);
    expect(crash.disposition).toBe('failed');
    expect(crash.category).toBe('parser');
    expect(crash.snapshotMayExist).toBe(true);
  });

  it('does not advance freshness for any failure or quarantine code', () => {
    for (const code of intelligenceSafeFailureCodes) {
      expect(intelligenceSafeFailureCatalog[code].freshnessMayAdvance).toBe(false);
    }
  });
});
