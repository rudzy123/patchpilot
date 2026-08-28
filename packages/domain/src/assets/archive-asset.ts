import { err, type Result } from '../result.js';
import { authorizeAssetManage, type AssetActor } from './authorization.js';
import { assetArchivedAudit } from './audit.js';
import {
  ASSET_ARCHIVED,
  ASSET_NOT_FOUND,
  ASSET_VERSION_CONFLICT,
  assetValidationError,
} from './errors.js';
import {
  mapCompareAndSetOutcome,
  type AssetMutationDependencies,
  type AssetMutationRequest,
} from './mutation.js';
import type { AssetDetailRecord } from './types.js';

export type ArchiveAssetUseCaseInput = AssetMutationRequest & {
  actor: AssetActor;
  assetId: string;
  expectedVersion: number;
};

export function createArchiveAssetUseCase(dependencies: AssetMutationDependencies) {
  return {
    execute(input: ArchiveAssetUseCaseInput): Promise<Result<AssetDetailRecord>> {
      return executeArchiveAsset(dependencies, input);
    },
  };
}

async function executeArchiveAsset(
  dependencies: AssetMutationDependencies,
  input: ArchiveAssetUseCaseInput,
): Promise<Result<AssetDetailRecord>> {
  const authorized = authorizeAssetManage(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  if (!Number.isInteger(input.expectedVersion) || input.expectedVersion < 1) {
    return err(assetValidationError('expectedVersion must be an integer of at least 1.'));
  }

  return dependencies.unitOfWork.runInTransaction(async (repos) => {
    const current = await repos.assets.findDetailById(
      authorized.value.organizationId,
      input.assetId,
    );
    if (current === undefined) {
      return err(ASSET_NOT_FOUND);
    }
    if (current.lifecycleStatus === 'archived') {
      return err(ASSET_ARCHIVED);
    }
    if (current.version !== input.expectedVersion) {
      return err(ASSET_VERSION_CONFLICT);
    }

    const occurredAt = dependencies.clock.now();
    const archived = mapCompareAndSetOutcome(
      await repos.assets.compareAndSetArchive(
        authorized.value.organizationId,
        input.assetId,
        input.expectedVersion,
        occurredAt,
      ),
    );
    if (!archived.ok) {
      return archived;
    }

    await repos.auditEvents.append(
      assetArchivedAudit(authorized.value, archived.value, input, occurredAt),
    );
    return archived;
  });
}
