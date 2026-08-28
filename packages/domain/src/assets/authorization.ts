import { err, ok, type Result } from '../result.js';
import { ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from './errors.js';

/** Structural actor accepted by asset use cases. Compatible with auth TrustedActor. */
export type AssetActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string | null;
  readonly membershipId: string | null;
  readonly permissions: readonly string[];
};

export type AuthorizedAssetActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string;
  readonly membershipId: string;
  readonly permissions: readonly string[];
};

export const ASSET_READ_PERMISSION = 'asset:read';
export const ASSET_MANAGE_PERMISSION = 'asset:manage';

export function authorizeAssetRead(actor: AssetActor): Result<AuthorizedAssetActor> {
  return authorizeAssetPermission(actor, ASSET_READ_PERMISSION);
}

export function authorizeAssetManage(actor: AssetActor): Result<AuthorizedAssetActor> {
  return authorizeAssetPermission(actor, ASSET_MANAGE_PERMISSION);
}

function authorizeAssetPermission(
  actor: AssetActor,
  permission: string,
): Result<AuthorizedAssetActor> {
  if (actor.organizationId === null || actor.membershipId === null) {
    return err(ORGANIZATION_CONTEXT_REQUIRED);
  }

  if (!actor.permissions.includes(permission)) {
    return err(PERMISSION_DENIED);
  }

  return ok({
    userId: actor.userId,
    sessionId: actor.sessionId,
    organizationId: actor.organizationId,
    membershipId: actor.membershipId,
    permissions: actor.permissions,
  });
}
