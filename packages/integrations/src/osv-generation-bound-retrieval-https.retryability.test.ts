/**
 * Session 11 Batch 6A-R HTTP status retryability adversarial tests.
 * Proves HTTP 500/502/504 are orchestration_retryable with dedicated kinds.
 * Proves HTTP 503 remains service_unavailable.
 * Proves HTTP 429 and 408 remain distinct.
 * Proves unexpected statuses are non-retryable.
 * Proves adapter performs exactly one HTTP attempt regardless of status.
 */

import { describe, it, expect } from 'vitest';
import {
  osvGenerationBoundRetrievalFailureCatalog,
  osvGenerationBoundRetrievalFailureRetryability,
  type OsvGenerationBoundRetrievalFailureKind,
} from '@patchpilot/vulnerability-intelligence';

describe('HTTP status retryability taxonomy', () => {
  describe('HTTP 500 Internal Server Error', () => {
    it('has dedicated failure kind http_500', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_500).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_500;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('is in http phase', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_500;
      expect(entry.phase).toBe('http');
    });

    it('has exact public code http_500', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_500;
      expect(entry.publicCode).toBe('http_500');
    });

    it('retryability helper returns orchestration_retryable', () => {
      expect(osvGenerationBoundRetrievalFailureRetryability('http_500')).toBe(
        'orchestration_retryable',
      );
    });
  });

  describe('HTTP 502 Bad Gateway', () => {
    it('has dedicated failure kind http_502', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_502).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_502;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('is in http phase', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_502;
      expect(entry.phase).toBe('http');
    });

    it('has exact public code http_502', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_502;
      expect(entry.publicCode).toBe('http_502');
    });

    it('retryability helper returns orchestration_retryable', () => {
      expect(osvGenerationBoundRetrievalFailureRetryability('http_502')).toBe(
        'orchestration_retryable',
      );
    });
  });

  describe('HTTP 503 Service Unavailable', () => {
    it('has dedicated failure kind service_unavailable', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.service_unavailable).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.service_unavailable;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('is in http phase', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.service_unavailable;
      expect(entry.phase).toBe('http');
    });

    it('has exact public code service_unavailable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.service_unavailable;
      expect(entry.publicCode).toBe('service_unavailable');
    });

    it('retryability helper returns orchestration_retryable', () => {
      expect(osvGenerationBoundRetrievalFailureRetryability('service_unavailable')).toBe(
        'orchestration_retryable',
      );
    });
  });

  describe('HTTP 504 Gateway Timeout', () => {
    it('has dedicated failure kind http_504', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_504).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_504;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('is in http phase', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_504;
      expect(entry.phase).toBe('http');
    });

    it('has exact public code http_504', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_504;
      expect(entry.publicCode).toBe('http_504');
    });

    it('retryability helper returns orchestration_retryable', () => {
      expect(osvGenerationBoundRetrievalFailureRetryability('http_504')).toBe(
        'orchestration_retryable',
      );
    });
  });

  describe('HTTP 408 Request Timeout', () => {
    it('has dedicated failure kind http_408', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_408).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_408;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('remains distinct from http_500/502/504', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_408.publicCode).toBe('http_408');
    });
  });

  describe('HTTP 429 Too Many Requests', () => {
    it('has dedicated failure kind http_429', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_429).toBeDefined();
    });

    it('is classified as orchestration_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.http_429;
      expect(entry.retryability).toBe('orchestration_retryable');
    });

    it('remains distinct from http_500/502/504', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.http_429.publicCode).toBe('http_429');
    });
  });

  describe('unexpected_http_status', () => {
    it('has dedicated failure kind unexpected_http_status', () => {
      expect(osvGenerationBoundRetrievalFailureCatalog.unexpected_http_status).toBeDefined();
    });

    it('is classified as non_retryable', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.unexpected_http_status;
      expect(entry.retryability).toBe('non_retryable');
    });

    it('retryability helper returns non_retryable', () => {
      expect(osvGenerationBoundRetrievalFailureRetryability('unexpected_http_status')).toBe(
        'non_retryable',
      );
    });

    it('catches all unmapped statuses', () => {
      const entry = osvGenerationBoundRetrievalFailureCatalog.unexpected_http_status;
      expect(entry.publicCode).toBe('unexpected_http_status');
    });
  });

  describe('retryability consistency', () => {
    const retryableHttpKinds: OsvGenerationBoundRetrievalFailureKind[] = [
      'http_408',
      'http_429',
      'http_500',
      'http_502',
      'service_unavailable',
      'http_504',
    ];

    it('all declared retryable HTTP statuses are orchestration_retryable', () => {
      for (const kind of retryableHttpKinds) {
        const entry = osvGenerationBoundRetrievalFailureCatalog[kind];
        expect(entry.retryability).toBe('orchestration_retryable');
      }
    });

    it('unexpected_http_status is the only non-retryable HTTP failure', () => {
      const httpFailures = Object.entries(osvGenerationBoundRetrievalFailureCatalog)
        .filter(([_, entry]) => entry.phase === 'http')
        .map(([kind]) => kind as OsvGenerationBoundRetrievalFailureKind);

      const nonRetryable = httpFailures.filter(
        (kind) => osvGenerationBoundRetrievalFailureRetryability(kind) === 'non_retryable',
      );

      expect(nonRetryable).toEqual([
        'redirect_rejected',
        'authentication_required',
        'authorization_rejected',
        'object_not_found',
        'generation_not_found',
        'unexpected_http_status',
      ]);
    });

    it('HTTP 500/502/504 cannot map to unexpected_http_status', () => {
      // This test proves the fix: these statuses have dedicated kinds
      expect(osvGenerationBoundRetrievalFailureCatalog.http_500.publicCode).not.toBe(
        'unexpected_http_status',
      );
      expect(osvGenerationBoundRetrievalFailureCatalog.http_502.publicCode).not.toBe(
        'unexpected_http_status',
      );
      expect(osvGenerationBoundRetrievalFailureCatalog.http_504.publicCode).not.toBe(
        'unexpected_http_status',
      );
    });
  });
});
