/**
 * Exact repeated-observation replay classification.
 * This function reloads nothing and writes nothing.
 * Natural identity is organization, Finding, and ingestion.
 * Correlation identity is not a comparison field. A different correlation
 * may require a newly issued authorization and still converges to
 * `already_applied` when persisted semantics agree.
 * A uniqueness violation is not replay unless the semantic comparison agrees.
 * Disagreement is `immutable_conflict`. An incomplete row is
 * `malformed_persisted_state`. This command does not repair either.
 */

import {
  FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
  findingRepeatedObservationOutcomeExplanation,
  type FindingRepeatedObservationOutcome,
} from './policy.js';
import { closedRecord } from './plain.js';

const COMPARISON_KEYS = [
  'schemaVersion',
  'observationPresent',
  'naturalIdentityAgrees',
  'purposeAgrees',
  'policyAgrees',
  'aggregateAgrees',
  'mappedResultAgrees',
  'supportFingerprintAgrees',
  'evidenceLinkSetAgrees',
  'unknownVersionProofSetAgrees',
  'absenceProofAgrees',
  'ingestionAgrees',
  'findingTargetAgrees',
  'replayFingerprintAgrees',
  'persistedStateWellFormed',
  'uniquenessViolation',
  'semanticComparisonComplete',
] as const;

export const FINDING_REPEATED_OBSERVATION_REPLAY_CLASSIFICATIONS = [
  'already_applied',
  'immutable_conflict',
  'malformed_persisted_state',
  'not_persisted',
  'uniqueness_not_replay',
  'comparison_rejected',
] as const;

export type FindingRepeatedObservationReplayClassification =
  (typeof FINDING_REPEATED_OBSERVATION_REPLAY_CLASSIFICATIONS)[number];

export type FindingRepeatedObservationReplayOutcome =
  FindingRepeatedObservationOutcome | 'not_persisted' | 'comparison_rejected';

export type FindingRepeatedObservationReplayResult = {
  readonly classification: FindingRepeatedObservationReplayClassification;
  readonly outcome: FindingRepeatedObservationReplayOutcome;
  readonly writes: false;
  readonly observationInserts: 0;
  readonly evidenceLinkInserts: 0;
  readonly findingRowUpdates: 0;
  readonly timestampChanges: 0;
  readonly auditEvents: 0;
  readonly authorityRenewals: 0;
  readonly repairAuthorized: false;
  readonly correlationRedefinesReplay: false;
  readonly effects: typeof FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS;
  readonly explanation: string;
};

export function classifyFindingRepeatedObservationReplay(
  input: unknown,
): FindingRepeatedObservationReplayResult {
  try {
    return classify(input);
  } catch {
    return replayResult('comparison_rejected', 'internal_failure');
  }
}

function classify(input: unknown): FindingRepeatedObservationReplayResult {
  const values = closedRecord(input, COMPARISON_KEYS);
  if (values === null) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  if (
    values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION
  ) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  const observationPresent = booleanValue(values.get('observationPresent'));
  const naturalIdentityAgrees = booleanValue(values.get('naturalIdentityAgrees'));
  const purposeAgrees = booleanValue(values.get('purposeAgrees'));
  const policyAgrees = booleanValue(values.get('policyAgrees'));
  const aggregateAgrees = booleanValue(values.get('aggregateAgrees'));
  const mappedResultAgrees = booleanValue(values.get('mappedResultAgrees'));
  const supportFingerprintAgrees = booleanValue(values.get('supportFingerprintAgrees'));
  const evidenceLinkSetAgrees = booleanValue(values.get('evidenceLinkSetAgrees'));
  const unknownVersionProofSetAgrees = booleanValue(values.get('unknownVersionProofSetAgrees'));
  const absenceProofAgrees = booleanValue(values.get('absenceProofAgrees'));
  const ingestionAgrees = booleanValue(values.get('ingestionAgrees'));
  const findingTargetAgrees = booleanValue(values.get('findingTargetAgrees'));
  const replayFingerprintAgrees = booleanValue(values.get('replayFingerprintAgrees'));
  const persistedStateWellFormed = booleanValue(values.get('persistedStateWellFormed'));
  const uniquenessViolation = booleanValue(values.get('uniquenessViolation'));
  const semanticComparisonComplete = booleanValue(values.get('semanticComparisonComplete'));
  if (
    observationPresent === null ||
    naturalIdentityAgrees === null ||
    purposeAgrees === null ||
    policyAgrees === null ||
    aggregateAgrees === null ||
    mappedResultAgrees === null ||
    supportFingerprintAgrees === null ||
    evidenceLinkSetAgrees === null ||
    unknownVersionProofSetAgrees === null ||
    absenceProofAgrees === null ||
    ingestionAgrees === null ||
    findingTargetAgrees === null ||
    replayFingerprintAgrees === null ||
    persistedStateWellFormed === null ||
    uniquenessViolation === null ||
    semanticComparisonComplete === null
  ) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  if (!persistedStateWellFormed) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  if (!observationPresent) {
    if (uniquenessViolation) {
      return replayResult('malformed_persisted_state', 'malformed_persisted_state');
    }
    return replayResult('not_persisted', 'not_persisted');
  }
  if (!naturalIdentityAgrees) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  if (!semanticComparisonComplete) {
    if (uniquenessViolation) {
      return replayResult('uniqueness_not_replay', 'concurrency_conflict');
    }
    return replayResult('comparison_rejected', 'invalid_command');
  }
  const exact =
    purposeAgrees &&
    policyAgrees &&
    aggregateAgrees &&
    mappedResultAgrees &&
    supportFingerprintAgrees &&
    evidenceLinkSetAgrees &&
    unknownVersionProofSetAgrees &&
    absenceProofAgrees &&
    ingestionAgrees &&
    findingTargetAgrees &&
    replayFingerprintAgrees;
  if (exact) {
    return replayResult('already_applied', 'already_applied');
  }
  return replayResult('immutable_conflict', 'immutable_conflict');
}

function replayResult(
  classification: FindingRepeatedObservationReplayClassification,
  outcome: FindingRepeatedObservationReplayOutcome,
): FindingRepeatedObservationReplayResult {
  const explanation =
    outcome === 'not_persisted'
      ? 'no repeated observation is persisted'
      : outcome === 'comparison_rejected'
        ? 'repeated-observation comparison was rejected'
        : findingRepeatedObservationOutcomeExplanation(outcome);
  return {
    classification,
    outcome,
    writes: false,
    observationInserts: 0,
    evidenceLinkInserts: 0,
    findingRowUpdates: 0,
    timestampChanges: 0,
    auditEvents: 0,
    authorityRenewals: 0,
    repairAuthorized: false,
    correlationRedefinesReplay: false,
    effects: FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
    explanation,
  };
}

function booleanValue(value: unknown): boolean | null {
  if (value === true || value === false) {
    return value;
  }
  return null;
}
