/**
 * Exact creation replay classification.
 * This function reloads nothing and writes nothing.
 * Correlation identity is not a comparison field. A different correlation
 * may require a newly issued authorization and does not make an identical
 * persisted Finding a different product object.
 * `comparison_rejected` means the comparison input is malformed.
 * `malformed_persisted_state` means a well-typed report describes corrupt rows.
 * A natural-key collision is not exact replay.
 */

import {
  FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_CREATION_ZERO_EFFECTS,
  findingCreationOutcomeExplanation,
  type FindingCreationOutcome,
} from './policy.js';
import { closedRecord } from './plain.js';

const COMPARISON_KEYS = [
  'schemaVersion',
  'findingPresent',
  'creationObservationPresent',
  'evidenceLinksComplete',
  'naturalIdentityAgrees',
  'purposeAgrees',
  'policyAgrees',
  'evidenceFingerprintAgrees',
  'ingestionAgrees',
  'linkSetAgrees',
  'persistedStateWellFormed',
] as const;

export const FINDING_CREATION_REPLAY_CLASSIFICATIONS = [
  'already_applied',
  'immutable_conflict',
  'finding_already_exists',
  'malformed_persisted_state',
  'not_persisted',
  'comparison_rejected',
] as const;

export type FindingCreationReplayClassification =
  (typeof FINDING_CREATION_REPLAY_CLASSIFICATIONS)[number];

export type FindingCreationReplayResult = {
  readonly classification: FindingCreationReplayClassification;
  readonly outcome: FindingCreationOutcome | 'not_persisted';
  readonly writes: false;
  readonly timestampChanged: false;
  readonly observationAdded: false;
  readonly auditEventAdded: false;
  readonly authorityCreated: false;
  readonly effects: typeof FINDING_CREATION_ZERO_EFFECTS;
  readonly explanation: string;
};

export function classifyFindingCreationReplay(input: unknown): FindingCreationReplayResult {
  try {
    return classify(input);
  } catch {
    return replayResult('comparison_rejected', 'internal_failure');
  }
}

function classify(input: unknown): FindingCreationReplayResult {
  const values = closedRecord(input, COMPARISON_KEYS);
  if (values === null) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  if (values.get('schemaVersion') !== FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  const findingPresent = booleanValue(values.get('findingPresent'));
  const creationObservationPresent = booleanValue(values.get('creationObservationPresent'));
  const evidenceLinksComplete = booleanValue(values.get('evidenceLinksComplete'));
  const naturalIdentityAgrees = booleanValue(values.get('naturalIdentityAgrees'));
  const purposeAgrees = booleanValue(values.get('purposeAgrees'));
  const policyAgrees = booleanValue(values.get('policyAgrees'));
  const evidenceFingerprintAgrees = booleanValue(values.get('evidenceFingerprintAgrees'));
  const ingestionAgrees = booleanValue(values.get('ingestionAgrees'));
  const linkSetAgrees = booleanValue(values.get('linkSetAgrees'));
  const persistedStateWellFormed = booleanValue(values.get('persistedStateWellFormed'));
  if (
    findingPresent === null ||
    creationObservationPresent === null ||
    evidenceLinksComplete === null ||
    naturalIdentityAgrees === null ||
    purposeAgrees === null ||
    policyAgrees === null ||
    evidenceFingerprintAgrees === null ||
    ingestionAgrees === null ||
    linkSetAgrees === null ||
    persistedStateWellFormed === null
  ) {
    return replayResult('comparison_rejected', 'invalid_command');
  }
  if (!persistedStateWellFormed) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  if (!findingPresent && (creationObservationPresent || evidenceLinksComplete)) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  if (!findingPresent) {
    return replayResult('not_persisted', 'not_persisted');
  }
  if (!naturalIdentityAgrees) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  if (evidenceFingerprintAgrees !== linkSetAgrees) {
    return replayResult('malformed_persisted_state', 'malformed_persisted_state');
  }
  const exact =
    creationObservationPresent &&
    evidenceLinksComplete &&
    purposeAgrees &&
    policyAgrees &&
    evidenceFingerprintAgrees &&
    ingestionAgrees &&
    linkSetAgrees;
  if (exact) {
    return replayResult('already_applied', 'already_applied');
  }
  if (!purposeAgrees || !policyAgrees || !evidenceFingerprintAgrees || !linkSetAgrees) {
    return replayResult('immutable_conflict', 'immutable_conflict');
  }
  return replayResult('finding_already_exists', 'finding_already_exists');
}

function replayResult(
  classification: FindingCreationReplayClassification,
  outcome: FindingCreationReplayResult['outcome'],
): FindingCreationReplayResult {
  const explanation =
    outcome === 'not_persisted'
      ? 'no creation record is persisted'
      : findingCreationOutcomeExplanation(outcome);
  return {
    classification,
    outcome,
    writes: false,
    timestampChanged: false,
    observationAdded: false,
    auditEventAdded: false,
    authorityCreated: false,
    effects: FINDING_CREATION_ZERO_EFFECTS,
    explanation,
  };
}

function booleanValue(value: unknown): boolean | null {
  if (value === true || value === false) {
    return value;
  }
  return null;
}
