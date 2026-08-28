import type { AssetRepository } from '../ports.js';
import { err, type Result } from '../result.js';
import { authorizeAssetRead, type AssetActor } from './authorization.js';
import { ASSET_NOT_FOUND } from './errors.js';
import type { AssetDetailRecord } from './types.js';

export type GetAssetInput = {
  actor: AssetActor;
  assetId: string;
};

export type GetAssetDependencies = {
  assets: Pick<AssetRepository, 'findDetailById'>;
};

export function createGetAssetUseCase(dependencies: GetAssetDependencies) {
  return {
    execute(input: GetAssetInput): Promise<Result<AssetDetailRecord>> {
      return executeGetAsset(dependencies, input);
    },
  };
}

async function executeGetAsset(
  dependencies: GetAssetDependencies,
  input: GetAssetInput,
): Promise<Result<AssetDetailRecord>> {
  const authorized = authorizeAssetRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const asset = await dependencies.assets.findDetailById(
    authorized.value.organizationId,
    input.assetId,
  );
  if (asset === undefined) {
    return err(ASSET_NOT_FOUND);
  }

  return { ok: true, value: asset };
}
