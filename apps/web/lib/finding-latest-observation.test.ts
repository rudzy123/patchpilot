import { describe, expect, it } from 'vitest';

import { FINDING_ID, FINDING_ID_2, creationLatestObservation } from '../test/finding-fixtures';

import { readLatestObservation } from './finding-latest-observation';

const OBSERVED_AT = '2026-10-08T12:00:00.000000Z';

function occurrence(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 'finding_latest_observation_transport_v1',
    findingId: FINDING_ID,
    observationSource: 'latest_repeated',
    observedAt: OBSERVED_AT,
    aggregate: 'affected',
    evidence: {
      kind: 'occurrence_support',
      affectedSupportCount: 1,
      unaffectedSupportCount: 0,
      unknownSupportCount: 0,
      unknownVersionSupportCount: 0,
      knownVersions: {
        values: ['10.0.0', '2.0.0'],
        truncated: false,
        omittedDistinctCount: 0,
        distinctCount: 2,
      },
    },
    ...overrides,
  };
}

describe('readLatestObservation', () => {
  it('accepts creation fallback and each legal aggregate without reordering versions', () => {
    const creation = readLatestObservation(creationLatestObservation(), FINDING_ID);
    expect(creation?.observationSource).toBe('creation');
    expect(creation?.aggregate).toBe('affected');

    const repeated = readLatestObservation(occurrence(), FINDING_ID);
    expect(repeated?.evidence.kind).toBe('occurrence_support');
    if (repeated?.evidence.kind === 'occurrence_support') {
      expect(repeated.evidence.knownVersions.values).toEqual(['10.0.0', '2.0.0']);
    }

    expect(
      readLatestObservation(
        occurrence({
          aggregate: 'unaffected',
          evidence: {
            ...(occurrence().evidence as object),
            unaffectedSupportCount: 2,
            affectedSupportCount: 0,
          },
        }),
        FINDING_ID,
      )?.aggregate,
    ).toBe('unaffected');
    expect(
      readLatestObservation(
        occurrence({
          aggregate: 'unknown',
          evidence: {
            ...(occurrence().evidence as object),
            unknownSupportCount: 1,
            affectedSupportCount: 0,
          },
        }),
        FINDING_ID,
      )?.aggregate,
    ).toBe('unknown');
    expect(
      readLatestObservation(
        {
          schemaVersion: 'finding_latest_observation_transport_v1',
          findingId: FINDING_ID,
          observationSource: 'latest_repeated',
          observedAt: OBSERVED_AT,
          aggregate: 'component_absent',
          evidence: { kind: 'component_absence', graphCompleteness: 'no_dependencies' },
        },
        FINDING_ID,
      )?.aggregate,
    ).toBe('component_absent');
  });

  it('rejects closed-contract violations instead of repairing them', () => {
    const rejected = [
      occurrence({ schemaVersion: 'finding_latest_observation_projection_v1' }),
      occurrence({ observationSource: 'repeated' }),
      occurrence({ aggregate: 'absent' }),
      occurrence({ observedAt: '2026-10-08T12:00:00Z' }),
      occurrence({ observedAt: 'not-a-timestamp' }),
      occurrence({ mappedResult: 'present' }),
      occurrence({ observations: ['secret-history-version'] }),
      occurrence({ observationId: 'obs-1' }),
      occurrence({ assetId: FINDING_ID_2 }),
      occurrence({ supportLinkId: 'support-1' }),
      occurrence({ lastObservedAt: OBSERVED_AT }),
      {
        ...occurrence(),
        evidence: {
          ...(occurrence().evidence as object),
          graphCompleteness: 'complete',
        },
      },
      occurrence({
        observationSource: 'creation',
        evidence: {
          ...(occurrence().evidence as object),
          affectedSupportCount: 1,
          unaffectedSupportCount: 1,
        },
      }),
      occurrence({
        observationSource: 'creation',
        evidence: {
          ...(occurrence().evidence as object),
          affectedSupportCount: 0,
        },
      }),
      occurrence({
        aggregate: 'unaffected',
        observationSource: 'creation',
        evidence: {
          ...(occurrence().evidence as object),
          affectedSupportCount: 0,
          unaffectedSupportCount: 1,
        },
      }),
      occurrence({
        evidence: {
          ...(occurrence().evidence as object),
          knownVersions: {
            values: ['2.0.0', '10.0.0'],
            truncated: false,
            omittedDistinctCount: 0,
            distinctCount: 2,
          },
        },
      }),
      occurrence({
        evidence: {
          ...(occurrence().evidence as object),
          knownVersions: {
            values: ['1.0.0'],
            truncated: false,
            omittedDistinctCount: 1,
            distinctCount: 1,
          },
        },
      }),
      occurrence({
        evidence: {
          ...(occurrence().evidence as object),
          knownVersions: {
            values: ['1.0.0\u0000'],
            truncated: false,
            omittedDistinctCount: 0,
            distinctCount: 1,
          },
        },
      }),
      {
        schemaVersion: 'finding_latest_observation_transport_v1',
        findingId: FINDING_ID,
        observationSource: 'latest_repeated',
        observedAt: OBSERVED_AT,
        aggregate: 'component_absent',
        evidence: {
          kind: 'component_absence',
          graphCompleteness: 'complete',
          componentCount: 3,
          dependencyEdgeCount: 4,
          absenceFingerprint: 'fingerprint-secret',
        },
      },
      {
        schemaVersion: 'finding_latest_observation_transport_v1',
        findingId: FINDING_ID,
        observationSource: 'latest_repeated',
        observedAt: OBSERVED_AT,
        aggregate: 'component_absent',
        evidence: occurrence().evidence,
      },
    ];

    for (const body of rejected) {
      expect(readLatestObservation(body, FINDING_ID)).toBeNull();
    }
    expect(readLatestObservation(occurrence(), FINDING_ID_2)).toBeNull();
    expect(readLatestObservation(occurrence({ findingId: FINDING_ID_2 }), FINDING_ID)).toBeNull();
    expect(readLatestObservation(occurrence(), 'NOT-A-UUID')).toBeNull();
  });
});
