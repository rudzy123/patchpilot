/**
 * Future transactional command port. No adapter is bound in this session.
 * The port accepts one parsed command. It does not accept a repository,
 * a transaction callback, SQL, or tenant authority.
 */

import type {
  InstanceAdvisoryAuthorityCommand,
  InstanceAdvisoryAuthorityCommandResult,
} from './command.js';

export const INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS = {
  store: 'postgresql',
  relation: 'instance_advisory_authority_grant',
  organizationColumn: false,
  oneActiveGrantPerUser: true,
  mutualExclusivityEnforcedByDatabase: true,
  revocationAtMostOnce: true,
  revocationTargetsExpectedGrantId: true,
  revokedRowsImmutable: true,
  regrantInsertsNewRow: true,
  reactivationInPlace: false,
  seedGrants: false,
  automaticAuthority: false,
  processLocalCacheIsAuthority: false,
  environmentAllowlistIsAuthority: false,
  databaseUnavailableFailsClosed: true,
  unknownIssuanceIsMalformed: true,
  unknownAuthorityIsMalformed: true,
  twoActiveGrantsAreMalformed: true,
  implemented: false,
  migrationImplemented: false,
  frozenMigrationCount: 25,
  exposesTransactionCallback: false,
  exposesGenericRepository: false,
} as const;

export type InstanceAdvisoryAuthorityCommandPort = {
  readonly execute: (
    command: InstanceAdvisoryAuthorityCommand,
  ) => Promise<InstanceAdvisoryAuthorityCommandResult>;
};
