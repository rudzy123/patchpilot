import type { TeamRepository } from '../ports.js';
import { boundPageSize, type Page, type PageRequest } from '../pagination.js';
import type { Result } from '../result.js';
import { authorizeAssetRead, type AssetActor } from './authorization.js';
import type { AssetTeamOption } from './types.js';

export type ListAssetTeamsInput = {
  actor: AssetActor;
  page?: PageRequest;
};

export type ListAssetTeamsDependencies = {
  teams: Pick<TeamRepository, 'listActiveOptions'>;
};

export function createListAssetTeamsUseCase(dependencies: ListAssetTeamsDependencies) {
  return {
    execute(input: ListAssetTeamsInput): Promise<Result<Page<AssetTeamOption>>> {
      return executeListAssetTeams(dependencies, input);
    },
  };
}

async function executeListAssetTeams(
  dependencies: ListAssetTeamsDependencies,
  input: ListAssetTeamsInput,
): Promise<Result<Page<AssetTeamOption>>> {
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
    value: await dependencies.teams.listActiveOptions(authorized.value.organizationId, page),
  };
}
