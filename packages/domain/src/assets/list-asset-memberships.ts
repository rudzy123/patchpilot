import type { MembershipRepository } from '../ports.js';
import { boundPageSize, type Page, type PageRequest } from '../pagination.js';
import type { Result } from '../result.js';
import { authorizeAssetRead, type AssetActor } from './authorization.js';
import type { AssetMembershipOption } from './types.js';

export type ListAssetMembershipsInput = {
  actor: AssetActor;
  page?: PageRequest;
};

export type ListAssetMembershipsDependencies = {
  memberships: Pick<MembershipRepository, 'listActiveOptions'>;
};

export function createListAssetMembershipsUseCase(dependencies: ListAssetMembershipsDependencies) {
  return {
    execute(input: ListAssetMembershipsInput): Promise<Result<Page<AssetMembershipOption>>> {
      return executeListAssetMemberships(dependencies, input);
    },
  };
}

async function executeListAssetMemberships(
  dependencies: ListAssetMembershipsDependencies,
  input: ListAssetMembershipsInput,
): Promise<Result<Page<AssetMembershipOption>>> {
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
    value: await dependencies.memberships.listActiveOptions(authorized.value.organizationId, page),
  };
}
