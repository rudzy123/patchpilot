import { err, ok, type Result } from '../result.js';
import { ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from './errors.js';
import { SBOM_UPLOAD_PERMISSION } from './constants.js';

/** Structural actor accepted by SBOM upload. Compatible with auth TrustedActor. */
export type SbomUploadActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string | null;
  readonly membershipId: string | null;
  readonly permissions: readonly string[];
};

export type AuthorizedSbomUploadActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string;
  readonly membershipId: string;
  readonly permissions: readonly string[];
};

export function authorizeSbomUpload(actor: SbomUploadActor): Result<AuthorizedSbomUploadActor> {
  if (actor.organizationId === null || actor.membershipId === null) {
    return err(ORGANIZATION_CONTEXT_REQUIRED);
  }

  if (!actor.permissions.includes(SBOM_UPLOAD_PERMISSION)) {
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
