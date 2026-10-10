import { describe, expect, it } from 'vitest';

import {
  deriveComponentAbsenceClassification,
  deriveRepeatedObservationAggregate,
} from './aggregate.js';
import {
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY,
  classifyInspectionCompatibility,
  classifyInspectionObservationShape,
} from './inspection-compatibility.js';
import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
} from '../controlled-creation/policy.js';
import {
  FINDING_INSPECTION_CREATION_METHOD,
  FINDING_INSPECTION_CREATION_TRANSITION,
} from '../controlled-inspection/policy.js';
import {
  FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_METHOD,
  FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_TRANSITION,
} from './policy.js';
import { repeatedObservationTenantDisclosure } from './persistence.js';
import { classifyFindingRepeatedObservationReplay } from './replay.js';

const OCCURRENCE_A = '30303030-3030-4303-8303-303030303030';
const OCCURRENCE_B = '31313131-3131-4313-8313-313131313131';

function known(
  occurrenceId: string,
  outcome: 'affected' | 'unaffected' | 'unknown',
  directness: 'direct' | 'transitive' | 'unspecified' = 'direct',
): Record<string, unknown> {
  return {
    occurrenceId,
    versionKnown: true,
    directness,
    evidenceStatus: 'one_current',
    outcome,
  };
}

function incomplete(
  occurrenceId: string,
  evidenceStatus: 'missing' | 'multiple',
): Record<string, unknown> {
  return {
    occurrenceId,
    versionKnown: true,
    directness: 'direct',
    evidenceStatus,
  };
}

function unknownVersion(
  occurrenceId: string,
  directness: 'direct' | 'transitive' | 'unspecified' = 'direct',
): Record<string, unknown> {
  return {
    occurrenceId,
    versionKnown: false,
    directness,
  };
}

function occurrenceSet(occurrences: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
    occurrences,
  };
}

function absenceFacts(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
    ingestionStatus: 'completed',
    latestSuccessful: true,
    strictlyLater: true,
    normalizationVersion: 2,
    graphCompleteness: 'complete',
    componentCount: 4,
    liveOccurrenceCardinality: 4,
    dependencyEdgeCount: 3,
    liveDependencyEdgeCardinality: 3,
    findingComponentOccurrenceCount: 0,
    ...overrides,
  };
}

function creationShape(): Record<string, unknown> {
  return {
    method: FINDING_INSPECTION_CREATION_METHOD,
    result: 'present',
    occurrenceId: null,
    transitionClassification: FINDING_INSPECTION_CREATION_TRANSITION,
    creationPurpose: FINDING_CREATION_PURPOSE,
    creationPolicyId: FINDING_CREATION_POLICY_ID,
    creationPolicyVersion: FINDING_CREATION_POLICY_VERSION,
    observationPurpose: null,
    observationPolicyId: null,
    observationPolicyVersion: null,
    aggregate: null,
  };
}

function laterShape(
  aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent',
  result: 'present' | 'absent' | 'inconclusive',
): Record<string, unknown> {
  return {
    method: FINDING_REPEATED_OBSERVATION_METHOD,
    result,
    occurrenceId: null,
    transitionClassification: FINDING_REPEATED_OBSERVATION_TRANSITION,
    creationPurpose: null,
    creationPolicyId: null,
    creationPolicyVersion: null,
    observationPurpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    observationPolicyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    observationPolicyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    aggregate,
  };
}

function replay(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
    observationPresent: true,
    naturalIdentityAgrees: true,
    purposeAgrees: true,
    policyAgrees: true,
    aggregateAgrees: true,
    mappedResultAgrees: true,
    supportFingerprintAgrees: true,
    evidenceLinkSetAgrees: true,
    unknownVersionProofSetAgrees: true,
    absenceProofAgrees: true,
    ingestionAgrees: true,
    findingTargetAgrees: true,
    replayFingerprintAgrees: true,
    persistedStateWellFormed: true,
    uniquenessViolation: false,
    semanticComparisonComplete: true,
    ...overrides,
  };
}

describe('mixed occurrence aggregation', () => {
  it('derives the governed aggregates and keeps per-occurrence facts', () => {
    const affected = deriveRepeatedObservationAggregate(
      occurrenceSet([known(OCCURRENCE_A, 'affected')]),
    );
    expect(affected.status).toBe('derived');
    if (affected.status === 'derived') {
      expect(affected.aggregate).toBe('affected');
      expect(affected.mappedResult).toBe('present');
      expect(affected.findingState).toBe('open');
      expect(affected.persisted).toBe(false);
      expect(affected.perOccurrence).toEqual([
        { occurrenceId: OCCURRENCE_A, directness: 'direct', contribution: 'affected' },
      ]);
    }

    const mixedAffected = deriveRepeatedObservationAggregate(
      occurrenceSet([
        known(OCCURRENCE_A, 'affected', 'transitive'),
        known(OCCURRENCE_B, 'unaffected', 'direct'),
      ]),
    );
    expect(mixedAffected.status).toBe('derived');
    if (mixedAffected.status === 'derived') {
      expect(mixedAffected.aggregate).toBe('affected');
      expect(mixedAffected.perOccurrence.map((row) => row.contribution)).toEqual([
        'affected',
        'unaffected',
      ]);
    }

    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([known(OCCURRENCE_A, 'affected'), known(OCCURRENCE_B, 'unknown')]),
      ).status === 'derived' &&
        deriveRepeatedObservationAggregate(
          occurrenceSet([known(OCCURRENCE_A, 'affected'), known(OCCURRENCE_B, 'unknown')]),
        ).aggregate,
    ).toBe('affected');

    const unaffected = deriveRepeatedObservationAggregate(
      occurrenceSet([
        known(OCCURRENCE_A, 'unaffected', 'direct'),
        known(OCCURRENCE_B, 'unaffected', 'transitive'),
      ]),
    );
    expect(unaffected.status).toBe('derived');
    if (unaffected.status === 'derived') {
      expect(unaffected.aggregate).toBe('unaffected');
      expect(unaffected.mappedResult).toBe('absent');
    }

    const unknownDominates = deriveRepeatedObservationAggregate(
      occurrenceSet([
        known(OCCURRENCE_A, 'unaffected'),
        known(OCCURRENCE_B, 'unknown', 'unspecified'),
      ]),
    );
    expect(unknownDominates.status).toBe('derived');
    if (unknownDominates.status === 'derived') {
      expect(unknownDominates.aggregate).toBe('unknown');
      expect(unknownDominates.mappedResult).toBe('inconclusive');
    }

    const allUnknown = deriveRepeatedObservationAggregate(
      occurrenceSet([known(OCCURRENCE_A, 'unknown'), unknownVersion(OCCURRENCE_B, 'transitive')]),
    );
    expect(allUnknown.status).toBe('derived');
    if (allUnknown.status === 'derived') {
      expect(allUnknown.aggregate).toBe('unknown');
    }

    const unknownVersionOnly = deriveRepeatedObservationAggregate(
      occurrenceSet([unknownVersion(OCCURRENCE_A)]),
    );
    expect(unknownVersionOnly.status).toBe('derived');
    if (unknownVersionOnly.status === 'derived') {
      expect(unknownVersionOnly.aggregate).toBe('unknown');
      expect(unknownVersionOnly.aggregate).not.toBe('component_absent');
    }
  });

  it('classifies missing evidence before any aggregate', () => {
    expect(
      deriveRepeatedObservationAggregate(occurrenceSet([incomplete(OCCURRENCE_A, 'missing')]))
        .status,
    ).toBe('evidence_unavailable');
    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([known(OCCURRENCE_A, 'affected'), incomplete(OCCURRENCE_B, 'missing')]),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveRepeatedObservationAggregate(occurrenceSet([incomplete(OCCURRENCE_A, 'multiple')]))
        .status,
    ).toBe('evidence_unavailable');
    expect(deriveRepeatedObservationAggregate(occurrenceSet([])).status).toBe(
      'evidence_unavailable',
    );
    expect(
      deriveRepeatedObservationAggregate({
        ...occurrenceSet([known(OCCURRENCE_A, 'affected')]),
        aggregate: 'unaffected',
      }).status,
    ).toBe('invalid_command');
    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([
          {
            ...unknownVersion(OCCURRENCE_A),
            evidenceStatus: 'one_current',
            outcome: 'unaffected',
          },
        ]),
      ).status,
    ).toBe('invalid_command');
  });
});

describe('component absence contract', () => {
  it('accepts a complete zero-occurrence proof and rejects weaker graphs', () => {
    const absent = deriveComponentAbsenceClassification(absenceFacts());
    expect(absent.status).toBe('component_absent');
    if (absent.status === 'component_absent') {
      expect(absent.aggregate).toBe('component_absent');
      expect(absent.mappedResult).toBe('absent');
      expect(absent.findingState).toBe('open');
      expect(absent.meansRemediated).toBe(false);
      expect(absent.meansVerified).toBe(false);
      expect(absent.meansResolved).toBe(false);
      expect(absent.meansSafe).toBe(false);
      expect(absent.meansClosed).toBe(false);
      expect(absent.callerEstablishedAbsence).toBe(false);
      expect(absent.persisted).toBe(false);
    }

    const noDependencies = deriveComponentAbsenceClassification(
      absenceFacts({
        graphCompleteness: 'no_dependencies',
        componentCount: 2,
        liveOccurrenceCardinality: 2,
        dependencyEdgeCount: 0,
        liveDependencyEdgeCardinality: 0,
      }),
    );
    expect(noDependencies.status).toBe('component_absent');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ graphCompleteness: 'empty' })).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ graphCompleteness: 'partial' })).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(
        absenceFacts({ componentCount: 3, liveOccurrenceCardinality: 4 }),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(
        absenceFacts({ componentCount: 0, liveOccurrenceCardinality: 0 }),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(
        absenceFacts({ dependencyEdgeCount: 0, liveDependencyEdgeCardinality: 0 }),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ findingComponentOccurrenceCount: 2 }))
        .status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ ingestionStatus: 'processing' })).status,
    ).toBe('ingestion_not_completed');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ latestSuccessful: false })).status,
    ).toBe('ingestion_not_latest');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ strictlyLater: false })).status,
    ).toBe('ingestion_not_later');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ normalizationVersion: 1 })).status,
    ).toBe('unsupported_normalization_version');
    expect(
      deriveComponentAbsenceClassification({ ...absenceFacts(), absenceAuthority: true }).status,
    ).toBe('invalid_command');
    expect(
      deriveComponentAbsenceClassification({ ...absenceFacts(), warningCount: 1 }).status,
    ).toBe('invalid_command');
  });
});

describe('repeated observation replay', () => {
  it('returns already_applied only when semantic inputs agree', () => {
    const applied = classifyFindingRepeatedObservationReplay(replay());
    expect(applied.classification).toBe('already_applied');
    expect(applied.outcome).toBe('already_applied');
    expect(applied.observationInserts).toBe(0);
    expect(applied.evidenceLinkInserts).toBe(0);
    expect(applied.findingRowUpdates).toBe(0);
    expect(applied.timestampChanges).toBe(0);
    expect(applied.auditEvents).toBe(0);
    expect(applied.authorityRenewals).toBe(0);
    expect(applied.correlationRedefinesReplay).toBe(false);
    expect(applied.repairAuthorized).toBe(false);
    expect(applied.writes).toBe(false);

    const conflict = classifyFindingRepeatedObservationReplay(replay({ aggregateAgrees: false }));
    expect(conflict.classification).toBe('immutable_conflict');
    expect(conflict.repairAuthorized).toBe(false);
    expect(
      classifyFindingRepeatedObservationReplay(
        replay({ supportFingerprintAgrees: true, evidenceLinkSetAgrees: false }),
      ).classification,
    ).toBe('immutable_conflict');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ absenceProofAgrees: false }))
        .classification,
    ).toBe('immutable_conflict');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ policyAgrees: false })).classification,
    ).toBe('immutable_conflict');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ mappedResultAgrees: false }))
        .classification,
    ).toBe('immutable_conflict');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ replayFingerprintAgrees: false }))
        .classification,
    ).toBe('immutable_conflict');
  });

  it('does not treat every uniqueness violation or correlation as replay', () => {
    expect(
      classifyFindingRepeatedObservationReplay(replay({ correlationId: OTHER })).classification,
    ).toBe('comparison_rejected');
    const uniqueExact = classifyFindingRepeatedObservationReplay(
      replay({ uniquenessViolation: true }),
    );
    expect(uniqueExact.classification).toBe('already_applied');
    const uniqueUnknown = classifyFindingRepeatedObservationReplay(
      replay({ uniquenessViolation: true, semanticComparisonComplete: false }),
    );
    expect(uniqueUnknown.classification).toBe('uniqueness_not_replay');
    expect(uniqueUnknown.outcome).toBe('concurrency_conflict');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ persistedStateWellFormed: false }))
        .classification,
    ).toBe('malformed_persisted_state');
    const absent = classifyFindingRepeatedObservationReplay(replay({ observationPresent: false }));
    expect(absent.classification).toBe('not_persisted');
    expect(absent.writes).toBe(false);
    expect(absent.outcome).not.toBe('already_applied');
  });
});

const OTHER = '13131313-1313-4131-8131-131313131313';

describe('inspection compatibility', () => {
  it('keeps a legal later observation from invalidating creation', () => {
    expect(classifyInspectionObservationShape(creationShape()).role).toBe('creation_observation');
    const later = classifyInspectionObservationShape(laterShape('unaffected', 'absent'));
    expect(later.role).toBe('later_observation');
    if (later.role === 'later_observation') {
      expect(later.invalidatesCreationObservation).toBe(false);
      expect(later.projected).toBe(false);
      expect(later.historyExposed).toBe(false);
    }
    expect(classifyInspectionObservationShape(laterShape('component_absent', 'absent')).role).toBe(
      'later_observation',
    );
    expect(classifyInspectionObservationShape(laterShape('affected', 'absent')).role).toBe(
      'malformed_persisted_state',
    );

    const compatible = classifyInspectionCompatibility({
      schemaVersion: FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
      creationObservation: creationShape(),
      laterObservations: [laterShape('unknown', 'inconclusive'), laterShape('affected', 'present')],
    });
    expect(compatible.status).toBe('compatible');
    if (compatible.status === 'compatible') {
      expect(compatible.projection).toBe('creation_based');
      expect(compatible.laterHistoryAvailable).toBe(false);
      expect(compatible.creationInvalidated).toBe(false);
      expect(compatible.lengthOtherThanOneIsMalformation).toBe(false);
      expect(compatible.laterObservationCount).toBe(2);
    }
    expect(
      classifyInspectionCompatibility({
        schemaVersion: FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
        creationObservation: null,
        laterObservations: [],
      }).status,
    ).toBe('malformed_persisted_state');
    expect(
      classifyInspectionCompatibility({
        schemaVersion: FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
        creationObservation: creationShape(),
        laterObservations: [laterShape('affected', 'absent')],
      }).status,
    ).toBe('malformed_persisted_state');
    expect(
      FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY.sessionImplementsInspectionCorrection,
    ).toBe(true);
    expect(FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY.laterHistoryAvailable).toBe(false);
  });
});

describe('tenant-safe repeated observation failures', () => {
  it('does not disclose whether a missing target exists in another organization', () => {
    expect(repeatedObservationTenantDisclosure()).toEqual({
      foreignResourceRevealed: false,
      existsInOtherOrganization: false,
      tenantDisclosure: 'indistinguishable',
    });
  });
});
