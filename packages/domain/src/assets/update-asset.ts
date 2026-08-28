import { err, type Result } from '../result.js';
import { authorizeAssetManage, type AssetActor } from './authorization.js';
import { assetUpdatedAudits } from './audit.js';
import { diffAssetUpdate, isNoOpAssetUpdate, toCompareAndSetCommand } from './diff.js';
import { ASSET_ARCHIVED, ASSET_NOT_FOUND, ASSET_VERSION_CONFLICT } from './errors.js';
import {
  mapCompareAndSetOutcome,
  type AssetMutationDependencies,
  type AssetMutationRequest,
} from './mutation.js';
import { normalizeUpdateAssetCommand, type UpdateAssetFields } from './normalize.js';
import { validateUpdateAssignments } from './references.js';
import type { AssetDetailRecord } from './types.js';

export type UpdateAssetUseCaseInput = AssetMutationRequest & {
  actor: AssetActor;
  assetId: string;
  fields: UpdateAssetFields;
};

export function createUpdateAssetUseCase(dependencies: AssetMutationDependencies) {
  return {
    execute(input: UpdateAssetUseCaseInput): Promise<Result<AssetDetailRecord>> {
      return executeUpdateAsset(dependencies, input);
    },
  };
}

async function executeUpdateAsset(
  dependencies: AssetMutationDependencies,
  input: UpdateAssetUseCaseInput,
): Promise<Result<AssetDetailRecord>> {
  const authorized = authorizeAssetManage(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const command = normalizeUpdateAssetCommand(input.fields);
  if (!command.ok) {
    return command;
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
    if (current.version !== command.value.expectedVersion) {
      return err(ASSET_VERSION_CONFLICT);
    }

    const assignments = await validateUpdateAssignments(
      repos,
      authorized.value.organizationId,
      command.value,
    );
    if (!assignments.ok) {
      return assignments;
    }

    const diff = diffAssetUpdate(current, command.value);
    if (isNoOpAssetUpdate(diff)) {
      return { ok: true, value: current };
    }

    const cas = await repos.assets.compareAndSetUpdate(
      authorized.value.organizationId,
      input.assetId,
      toCompareAndSetCommand(command.value.expectedVersion, command.value, diff),
    );
    if (!cas.ok) {
      return cas;
    }

    const updated = mapCompareAndSetOutcome(cas.value);
    if (!updated.ok) {
      return updated;
    }

    const occurredAt = dependencies.clock.now();
    for (const event of assetUpdatedAudits(
      authorized.value,
      updated.value,
      diff,
      input,
      occurredAt,
    )) {
      await repos.auditEvents.append(event);
    }

    return updated;
  });
}
