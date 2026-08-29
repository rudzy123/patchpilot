import type { ComponentIdentityState } from '../lifecycle.js';
import { err, ok, type Result } from '../result.js';
import { SBOM_IDENTITY_KEY_MAX_LENGTH } from './constants.js';
import { SBOM_INVALID_IDENTITY, sbomValidationError } from './errors.js';
import { parseComponentVersion, type ComponentVersion } from './version.js';

const IDENTITY_SEPARATOR = '\u001f';

export type NormalizedComponent = {
  bomRef: string | null;
  name: string;
  namespace: string | null;
  ecosystem: string | null;
  identityState: ComponentIdentityState;
  versionlessPurl: string | null;
  versionedPurl: string | null;
  version: ComponentVersion;
  isDirect: boolean | null;
  /** Persistence-only identity. Never include in public API contracts. */
  identityKey: string;
};

export type ComponentIdentityInput = {
  identityState: ComponentIdentityState;
  versionlessPurl: string | null;
  ecosystem: string | null;
  namespace: string | null;
  name: string;
  bomRef: string | null;
};

export function buildComponentIdentityKey(input: ComponentIdentityInput): Result<string> {
  if (input.name.length === 0) {
    return err(sbomValidationError('Component name is required.'));
  }

  let key: string;
  if (input.versionlessPurl !== null && input.versionlessPurl.length > 0) {
    key = `purl:${input.versionlessPurl}`;
  } else if (
    input.identityState === 'resolved' &&
    input.ecosystem !== null &&
    input.ecosystem.length > 0
  ) {
    key = `eco:${input.ecosystem}${IDENTITY_SEPARATOR}${input.namespace ?? ''}${IDENTITY_SEPARATOR}${input.name}`;
  } else {
    key = `unresolved:${input.identityState}${IDENTITY_SEPARATOR}${input.bomRef ?? ''}${IDENTITY_SEPARATOR}${input.name}`;
  }

  if (key.length > SBOM_IDENTITY_KEY_MAX_LENGTH) {
    return err(sbomValidationError('Component identity key exceeds the persistence bound.'));
  }

  return ok(key);
}

/**
 * Future vulnerability matching must ignore identities that are not resolved.
 */
export function isMatchableComponentIdentity(
  component: Pick<NormalizedComponent, 'identityState'>,
): boolean {
  return component.identityState === 'resolved';
}

export function validateNormalizedComponent(
  component: NormalizedComponent,
): Result<NormalizedComponent> {
  if (component.name.length === 0) {
    return err(SBOM_INVALID_IDENTITY);
  }

  const version = parseComponentVersion(component.version);
  if (!version.ok) {
    return version;
  }

  const identityKey = buildComponentIdentityKey(component);
  if (!identityKey.ok) {
    return identityKey;
  }

  if (identityKey.value !== component.identityKey) {
    return err(sbomValidationError('Component identityKey must match the deterministic identity.'));
  }

  return ok({
    ...component,
    version: version.value,
    identityKey: identityKey.value,
  });
}
