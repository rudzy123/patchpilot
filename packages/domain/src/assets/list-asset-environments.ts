import type { EnvironmentRepository } from '../ports.js';
import { boundPageSize, type Page, type PageRequest } from '../pagination.js';
import type { Result } from '../result.js';
import { authorizeAssetRead, type AssetActor } from './authorization.js';
import type { AssetEnvironmentOption } from './types.js';

export type ListAssetEnvironmentsInput = {
  actor: AssetActor;
  page?: PageRequest;
};

export type ListAssetEnvironmentsDependencies = {
  environments: Pick<EnvironmentRepository, 'listActiveOptions'>;
};

export function createListAssetEnvironmentsUseCase(
  dependencies: ListAssetEnvironmentsDependencies,
) {
  return {
    execute(input: ListAssetEnvironmentsInput): Promise<Result<Page<AssetEnvironmentOption>>> {
      return executeListAssetEnvironments(dependencies, input);
    },
  };
}

async function executeListAssetEnvironments(
  dependencies: ListAssetEnvironmentsDependencies,
  input: ListAssetEnvironmentsInput,
): Promise<Result<Page<AssetEnvironmentOption>>> {
  const authorized = authorizeAssetRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const page =
    input.page === undefined
      ? undefined
      : {
          ...input.page,
          ...(input.page.limit === undefined ? {} : { limit: boundPageSize(input.page.limit) }),
        };

  return {
    ok: true,
    value: await dependencies.environments.listActiveOptions(authorized.value.organizationId, page),
  };
}
