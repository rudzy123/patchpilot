/**
 * Future evidence-eligibility and creation-transaction boundaries.
 * No query, writer, or database adapter is implemented here.
 */

import type { SealedFindingCreationCommand } from './authorization.js';
import {
  FINDING_CREATION_ELIGIBILITY_SCHEMA_VERSION,
  FINDING_CREATION_EVIDENCE_REQUIREMENTS,
  type FindingCreationEvidenceRequirement,
  type FindingCreationOutcome,
} from './policy.js';
import type { ParsedFindingCreationTrustedContext } from './trusted-context.js';

export const FINDING_CREATION_EVIDENCE_ELIGIBILITY_IMPLEMENTED = false as const;

export const FINDING_CREATION_COMPLETE_SET_RULES = Object.freeze({
  requestedSetEqualsCompleteCurrentAffectedSet: true,
  subsetFailsClosed: true,
  supersetFailsClosed: true,
  emptyFailsClosed: true,
  unaffectedOccurrenceVetoesAffected: false,
  representativeOccurrenceIsFindingIdentity: false,
  severalAffectedOccurrencesShareOneFinding: true,
  oneCreationObservation: true,
  oneEvidenceLinkPerQualifyingRow: true,
});

export type FindingCreationEvidenceValidationRequest = {
  readonly schemaVersion: typeof FINDING_CREATION_ELIGIBILITY_SCHEMA_VERSION;
  readonly trustedContext: ParsedFindingCreationTrustedContext;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly expectedProductMatchEvidenceIds: readonly string[];
};

export type FindingCreationEvidenceFailureOutcome = Extract<
  FindingCreationOutcome,
  | 'not_found'
  | 'evidence_unavailable'
  | 'evidence_not_affected'
  | 'evidence_not_current'
  | 'evidence_not_eligible'
  | 'evidence_set_mismatch'
  | 'malformed_persisted_state'
  | 'database_unavailable'
  | 'internal_failure'
>;

export type FindingCreationEvidenceValidationResult =
  | {
      readonly status: 'authorized';
      readonly continuation: 'creation_transaction';
      readonly completeSet: true;
      readonly requirements: readonly FindingCreationEvidenceRequirement[];
      readonly foreignResourceRevealed: false;
      readonly tenantDisclosure: 'indistinguishable';
    }
  | {
      readonly status: FindingCreationEvidenceFailureOutcome;
      readonly continuation: 'stopped';
      readonly completeSet: false;
      readonly foreignResourceRevealed: false;
      readonly existsInOtherOrganization: false;
      readonly tenantDisclosure: 'indistinguishable';
    };

/**
 * Future port. Session 1 does not implement it and does not register it.
 * A missing row and a foreign-organization row share `not_found`.
 */
export type FindingCreationEvidenceEligibilityPort = {
  readonly portId: typeof FINDING_CREATION_ELIGIBILITY_SCHEMA_VERSION;
  readonly implemented: false;
  validateCompleteCurrentAffectedSet(
    request: FindingCreationEvidenceValidationRequest,
  ): Promise<FindingCreationEvidenceValidationResult>;
};

export const FINDING_CREATION_TRANSACTION_SCHEMA_VERSION =
  'finding_creation_transaction_v1' as const;

export type FindingCreationTransactionOutcome = Extract<
  FindingCreationOutcome,
  | 'created'
  | 'already_applied'
  | 'not_found'
  | 'evidence_unavailable'
  | 'evidence_not_affected'
  | 'evidence_not_current'
  | 'evidence_not_eligible'
  | 'target_mismatch'
  | 'evidence_set_mismatch'
  | 'finding_already_exists'
  | 'immutable_conflict'
  | 'malformed_persisted_state'
  | 'transaction_aborted'
  | 'database_unavailable'
  | 'authority_rejected'
  | 'authority_required'
  | 'invalid_command'
  | 'internal_failure'
>;

type FindingCreationTransactionBase = {
  readonly schemaVersion: typeof FINDING_CREATION_TRANSACTION_SCHEMA_VERSION;
  readonly foreignResourceRevealed: false;
  readonly tenantDisclosure: 'indistinguishable';
  readonly authorityCreated: false;
};

export type FindingCreationTransactionResult =
  | (FindingCreationTransactionBase & {
      readonly status: 'created';
      readonly writesPerformed: true;
      readonly observationAdded: true;
      readonly auditEventAdded: true;
      readonly timestampChanged: false;
    })
  | (FindingCreationTransactionBase & {
      readonly status: 'already_applied';
      readonly writesPerformed: false;
      readonly observationAdded: false;
      readonly auditEventAdded: false;
      readonly timestampChanged: false;
    })
  | (FindingCreationTransactionBase & {
      readonly status: Exclude<FindingCreationTransactionOutcome, 'created' | 'already_applied'>;
      readonly writesPerformed: false;
      readonly observationAdded: false;
      readonly auditEventAdded: false;
      readonly timestampChanged: false;
    });

/**
 * Future persistence port. No adapter implements this type in Session 1.
 * The transaction reloads organization and membership, then re-derives the
 * evidence set. A caller-built evidence result is not an input.
 */
export type FutureFindingCreationTransactionPort = {
  readonly portId: typeof FINDING_CREATION_TRANSACTION_SCHEMA_VERSION;
  readonly implemented: false;
  readonly productionRegistration: 'absent';
  applyAuthorizedCreation(input: {
    readonly trustedContext: ParsedFindingCreationTrustedContext;
    readonly command: SealedFindingCreationCommand;
  }): Promise<FindingCreationTransactionResult>;
};

export { FINDING_CREATION_EVIDENCE_REQUIREMENTS };
