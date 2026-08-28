import type { AssetRepository } from '../ports.js';
import type { Result } from '../result.js';
import { authorizeAssetRead, type AssetActor } from './authorization.js';
import {
  ASSET_LIST_DEFAULT_LIMIT,
  ASSET_LIST_MAX_LIMIT,
  ASSET_LIST_MIN_LIMIT,
  DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
} from './constants.js';
import { normalizeAssetNamePrefix, normalizeAssetTag } from './normalize.js';
import type { AssetListPage, AssetListQuery } from './types.js';

export type ListAssetsInput = {
  actor: AssetActor;
  query?: Partial<AssetListQuery>;
};

export type ListAssetsDependencies = {
  assets: Pick<AssetRepository, 'listForOrganization'>;
};

export function createListAssetsUseCase(dependencies: ListAssetsDependencies) {
  return {
    execute(input: ListAssetsInput): Promise<Result<AssetListPage>> {
      return executeListAssets(dependencies, input);
    },
  };
}

async function executeListAssets(
  dependencies: ListAssetsDependencies,
  input: ListAssetsInput,
): Promise<Result<AssetListPage>> {
  const authorized = authorizeAssetRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const query = resolveListQuery(input.query);
  if (!query.ok) {
    return query;
  }

  return {
    ok: true,
    value: await dependencies.assets.listForOrganization(
      authorized.value.organizationId,
      query.value,
    ),
  };
}

function resolveListQuery(query: Partial<AssetListQuery> | undefined): Result<AssetListQuery> {
  const resolved: AssetListQuery = {
    limit: boundAssetListLimit(query?.limit),
    lifecycleStatus: query?.lifecycleStatus ?? DEFAULT_ASSET_LIFECYCLE_LIST_FILTER,
  };

  if (query?.cursor !== undefined) {
    resolved.cursor = query.cursor;
  }
  if (query?.environmentId !== undefined) {
    resolved.environmentId = query.environmentId;
  }
  if (query?.assetType !== undefined) {
    resolved.assetType = query.assetType;
  }
  if (query?.businessCriticality !== undefined) {
    resolved.businessCriticality = query.businessCriticality;
  }
  if (query?.internetExposure !== undefined) {
    resolved.internetExposure = query.internetExposure;
  }
  if (query?.owningTeamId !== undefined) {
    resolved.owningTeamId = query.owningTeamId;
  }

  if (query?.tag !== undefined) {
    const tag = normalizeAssetTag(query.tag);
    if (!tag.ok) {
      return tag;
    }
    resolved.tag = tag.value;
  }

  if (query?.namePrefix !== undefined) {
    const prefix = normalizeAssetNamePrefix(query.namePrefix);
    if (!prefix.ok) {
      return prefix;
    }
    resolved.namePrefix = prefix.value;
  }

  return { ok: true, value: resolved };
}

function boundAssetListLimit(limit: number | undefined): number {
  if (limit === undefined) {
    return ASSET_LIST_DEFAULT_LIMIT;
  }

  if (!Number.isInteger(limit) || limit < ASSET_LIST_MIN_LIMIT) {
    return ASSET_LIST_MIN_LIMIT;
  }

  if (limit > ASSET_LIST_MAX_LIMIT) {
    return ASSET_LIST_MAX_LIMIT;
  }

  return limit;
}
