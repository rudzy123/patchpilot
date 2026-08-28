import type { Result } from '../result.js';
import { authorizeAssetManage, type AssetActor } from './authorization.js';
import { assetCreatedAudit } from './audit.js';
import type { AssetMutationDependencies, AssetMutationRequest } from './mutation.js';
import { normalizeCreateAssetCommand, type CreateAssetFields } from './normalize.js';
import { validateCreateAssignments } from './references.js';
import type { AssetDetailRecord } from './types.js';

export type CreateAssetUseCaseInput = AssetMutationRequest & {
  actor: AssetActor;
  fields: CreateAssetFields;
};

export function createCreateAssetUseCase(dependencies: AssetMutationDependencies) {
  return {
    execute(input: CreateAssetUseCaseInput): Promise<Result<AssetDetailRecord>> {
      return executeCreateAsset(dependencies, input);
    },
  };
}

async function executeCreateAsset(
  dependencies: AssetMutationDependencies,
  input: CreateAssetUseCaseInput,
): Promise<Result<AssetDetailRecord>> {
  const authorized = authorizeAssetManage(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const command = normalizeCreateAssetCommand(input.fields);
  if (!command.ok) {
    return command;
  }

  return dependencies.unitOfWork.runInTransaction(async (repos) => {
    const assignments = await validateCreateAssignments(
      repos,
      authorized.value.organizationId,
      command.value,
    );
    if (!assignments.ok) {
      return assignments;
    }

    const created = await repos.assets.createAggregate(
      authorized.value.organizationId,
      command.value,
    );
    if (!created.ok) {
      return created;
    }

    await repos.auditEvents.append(
      assetCreatedAudit(authorized.value, created.value, input, dependencies.clock.now()),
    );
    return created;
  });
}
