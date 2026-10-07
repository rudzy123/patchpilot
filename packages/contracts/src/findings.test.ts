import { describe, expect, it } from 'vitest';

import {
  controlledFindingCreationRequestSchema,
  controlledFindingIdParamSchema,
} from './findings.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';

function request(evidence: string[] = [EVIDENCE_A, EVIDENCE_B]): Record<string, unknown> {
  return {
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    expectedSbomIngestionId: INGESTION,
    expectedProductMatchEvidenceIds: evidence,
  };
}

describe('controlled finding creation request', () => {
  it('accepts one closed target and a strictly ascending evidence set', () => {
    expect(controlledFindingCreationRequestSchema.safeParse(request()).success).toBe(true);
  });

  it('rejects extra fields, uppercase ids, duplicates, unsorted ids, and sets outside 1 to 16', () => {
    expect(
      controlledFindingCreationRequestSchema.safeParse({
        ...request(),
        organizationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      }).success,
    ).toBe(false);
    expect(
      controlledFindingCreationRequestSchema.safeParse({
        ...request(),
        assetId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'.toUpperCase(),
      }).success,
    ).toBe(false);
    expect(
      controlledFindingCreationRequestSchema.safeParse(request([EVIDENCE_A, EVIDENCE_A])).success,
    ).toBe(false);
    expect(
      controlledFindingCreationRequestSchema.safeParse(request([EVIDENCE_B, EVIDENCE_A])).success,
    ).toBe(false);
    expect(controlledFindingCreationRequestSchema.safeParse(request([])).success).toBe(false);
    const oversized = Array.from({ length: 17 }, (_value, index) => {
      const suffix = index.toString(16).padStart(12, '0');
      return `aaaaaaaa-aaaa-4aaa-8aaa-${suffix}`;
    });
    expect(controlledFindingCreationRequestSchema.safeParse(request(oversized)).success).toBe(
      false,
    );
    expect(controlledFindingIdParamSchema.safeParse({ findingId: FINDING_UPPER() }).success).toBe(
      false,
    );
  });
});

function FINDING_UPPER(): string {
  return 'ABABABAB-ABAB-4BAB-8BAB-ABABABABABAB';
}
