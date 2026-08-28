import type { Clock } from '../clock.js';
import type { PersistenceUnitOfWork } from '../ports.js';
import { err, ok, type Result } from '../result.js';
import { ASSET_ARCHIVED, ASSET_NOT_FOUND, ASSET_VERSION_CONFLICT } from './errors.js';
import type { AssetCompareAndSetOutcome, AssetDetailRecord } from './types.js';

export type AssetMutationDependencies = {
  unitOfWork: PersistenceUnitOfWork;
  clock: Clock;
};

export type AssetMutationRequest = {
  correlationId: string;
  requestId?: string;
};

export function mapCompareAndSetOutcome(
  outcome: AssetCompareAndSetOutcome,
): Result<AssetDetailRecord> {
  switch (outcome.kind) {
    case 'updated':
      return ok(outcome.asset);
    case 'not_found':
      return err(ASSET_NOT_FOUND);
    case 'version_conflict':
      return err(ASSET_VERSION_CONFLICT);
    case 'archived':
      return err(ASSET_ARCHIVED);
    default: {
      const exhaustive: never = outcome;
      return exhaustive;
    }
  }
}
