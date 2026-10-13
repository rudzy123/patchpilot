import { describe, expect, it } from 'vitest';

import {
  controlledFindingCreationRequestSchema,
  controlledFindingIdParamSchema,
  controlledFindingLatestObservationResponseSchema,
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

const FINDING = 'abababab-abab-4bab-8bab-abababababab';

describe('controlled finding latest-observation response', () => {
  it('accepts creation fallback and the four public aggregates', () => {
    expect(controlledFindingLatestObservationResponseSchema.safeParse(creationBody()).success).toBe(
      true,
    );
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse(
        occurrenceBody('affected', 'latest_repeated', { affectedSupportCount: 2 }),
      ).success,
    ).toBe(true);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse(
        occurrenceBody('unaffected', 'latest_repeated', { unaffectedSupportCount: 1 }),
      ).success,
    ).toBe(true);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse(
        occurrenceBody('unknown', 'latest_repeated', { unknownSupportCount: 1 }),
      ).success,
    ).toBe(true);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        schemaVersion: 'finding_latest_observation_transport_v1',
        findingId: FINDING,
        observationSource: 'latest_repeated',
        observedAt: '2026-10-08T12:00:00.000000Z',
        aggregate: 'component_absent',
        evidence: { kind: 'component_absence', graphCompleteness: 'no_dependencies' },
      }).success,
    ).toBe(true);
  });

  it('rejects mapped results, hybrids, creation mismatches, and version-summary drift', () => {
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        ...creationBody(),
        mappedResult: 'present',
      }).success,
    ).toBe(false);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        ...creationBody(),
        evidence: {
          ...creationBody().evidence,
          graphCompleteness: 'complete',
        },
      }).success,
    ).toBe(false);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        ...occurrenceBody('unaffected', 'creation', { unaffectedSupportCount: 1 }),
      }).success,
    ).toBe(false);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        ...creationBody(),
        evidence: {
          ...creationBody().evidence,
          affectedSupportCount: 0,
        },
      }).success,
    ).toBe(false);
    const drifted = occurrenceBody('affected', 'latest_repeated', { affectedSupportCount: 1 });
    drifted.evidence.knownVersions.truncated = false;
    drifted.evidence.knownVersions.omittedDistinctCount = 1;
    expect(controlledFindingLatestObservationResponseSchema.safeParse(drifted).success).toBe(false);
    expect(
      controlledFindingLatestObservationResponseSchema.safeParse({
        ...creationBody(),
        assetId: '44444444-4444-4444-8444-444444444444',
      }).success,
    ).toBe(false);
  });
});

function creationBody() {
  return occurrenceBody('affected', 'creation', { affectedSupportCount: 1 });
}

function occurrenceBody(
  aggregate: 'affected' | 'unaffected' | 'unknown',
  observationSource: 'creation' | 'latest_repeated',
  counts: {
    affectedSupportCount?: number;
    unaffectedSupportCount?: number;
    unknownSupportCount?: number;
  },
) {
  return {
    schemaVersion: 'finding_latest_observation_transport_v1' as const,
    findingId: FINDING,
    observationSource,
    observedAt: '2026-10-08T12:00:00.000000Z',
    aggregate,
    evidence: {
      kind: 'occurrence_support' as const,
      affectedSupportCount: counts.affectedSupportCount ?? 0,
      unaffectedSupportCount: counts.unaffectedSupportCount ?? 0,
      unknownSupportCount: counts.unknownSupportCount ?? 0,
      unknownVersionSupportCount: 0,
      knownVersions: {
        values: [] as string[],
        truncated: false,
        omittedDistinctCount: 0,
        distinctCount: 0,
      },
    },
  };
}
