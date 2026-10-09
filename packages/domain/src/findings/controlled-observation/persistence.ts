/**
 * Future repeated-observation persistence port.
 * No adapter implements this type. The port accepts trusted context and a
 * sealed command, and returns a bounded outcome. It does not expose a
 * database client, raw rows, authority internals, or a persistence callback.
 */

import type { FindingObservationResult } from '../../lifecycle.js';

import type { SealedFindingRepeatedObservationCommand } from './authorization.js';
import {
  FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY,
  FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
  type FindingRepeatedObservationAggregate,
  type FindingRepeatedObservationOutcome,
} from './policy.js';
import type { ParsedFindingRepeatedObservationTrustedContext } from './trusted-context.js';

export const FINDING_REPEATED_OBSERVATION_PORT_EXCLUSIONS = [
  'prisma_client',
  'transaction_client',
  'sql',
  'raw_finding_row',
  'raw_observation',
  'raw_product_match_evidence',
  'authority_internals',
  'database_constraint',
  'persistence_callback',
] as const;

type RepeatedObservationDisclosure = {
  readonly foreignResourceRevealed: false;
  readonly existsInOtherOrganization: false;
  readonly tenantDisclosure: 'indistinguishable';
};

type RepeatedObservationSuccessBase = RepeatedObservationDisclosure & {
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION;
  readonly findingId: string;
  readonly sbomIngestionId: string;
  readonly aggregate: FindingRepeatedObservationAggregate;
  readonly mappedResult: FindingObservationResult;
  readonly findingState: 'open';
};

export type FindingRepeatedObservationTransactionResult =
  | (RepeatedObservationSuccessBase & {
      readonly status: 'observed';
      readonly observationInserted: true;
      readonly evidenceLinkedOrAbsenceRecorded: true;
      readonly findingTimestampUpdated: true;
      readonly auditEventAdded: true;
    })
  | (RepeatedObservationSuccessBase & {
      readonly status: 'already_applied';
      readonly observationInserted: false;
      readonly evidenceLinkedOrAbsenceRecorded: false;
      readonly findingTimestampUpdated: false;
      readonly auditEventAdded: false;
    })
  | (RepeatedObservationDisclosure & {
      readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION;
      readonly status: Exclude<FindingRepeatedObservationOutcome, 'observed' | 'already_applied'>;
      readonly observationInserted: false;
      readonly evidenceLinkedOrAbsenceRecorded: false;
      readonly findingTimestampUpdated: false;
      readonly auditEventAdded: false;
    });

export type FindingRepeatedObservationTransactionRequest = {
  readonly trustedContext: ParsedFindingRepeatedObservationTrustedContext;
  readonly command: SealedFindingRepeatedObservationCommand;
};

/**
 * Future port. Session 1 does not implement it and does not register it.
 * A missing row and a foreign-organization row share `not_found`.
 */
export type FutureFindingRepeatedObservationPort = {
  readonly portId: typeof FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION;
  readonly implemented: false;
  readonly productionRegistration: 'absent';
  readonly boundary: typeof FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY;
  observe(
    request: FindingRepeatedObservationTransactionRequest,
  ): Promise<FindingRepeatedObservationTransactionResult>;
};

export function repeatedObservationTenantDisclosure(): RepeatedObservationDisclosure {
  return Object.freeze({
    foreignResourceRevealed: false,
    existsInOtherOrganization: false,
    tenantDisclosure: 'indistinguishable',
  });
}

export { FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY };
