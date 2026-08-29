import { err, ok, type Result } from '../result.js';
import { FORBIDDEN_KNOWN_VERSION_STRINGS } from './constants.js';
import { SBOM_INVALID_VERSION, sbomValidationError } from './errors.js';

/**
 * Observed package version. Callers must not treat an empty string as unknown.
 * Future persistence maps this to versionKnown=true and version=<value>.
 */
export type KnownComponentVersion = {
  kind: 'known';
  value: string;
};

/**
 * Explicit missing version. Future persistence maps this to versionKnown=false
 * and version='' as a placeholder that is not a package version.
 */
export type UnknownComponentVersion = {
  kind: 'unknown';
};

export type ComponentVersion = KnownComponentVersion | UnknownComponentVersion;

export type OccurrenceVersionColumns = {
  versionKnown: boolean;
  version: string;
};

function isForbiddenKnownVersion(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (FORBIDDEN_KNOWN_VERSION_STRINGS as readonly string[]).includes(normalized);
}

export function knownComponentVersion(value: string): Result<KnownComponentVersion> {
  if (value.length === 0) {
    return err(sbomValidationError('Known component versions must be non-empty.'));
  }

  if (value.trim() !== value) {
    return err(
      sbomValidationError('Known component versions must not include surrounding whitespace.'),
    );
  }

  if (isForbiddenKnownVersion(value)) {
    return err(
      sbomValidationError(
        'Known component versions must not use *, latest, unknown, or guessed placeholders.',
      ),
    );
  }

  return ok({ kind: 'known', value });
}

export function unknownComponentVersion(): UnknownComponentVersion {
  return { kind: 'unknown' };
}

export function parseComponentVersion(input: ComponentVersion): Result<ComponentVersion> {
  if (input.kind === 'unknown') {
    if ('value' in input && input.value !== undefined) {
      return err(
        sbomValidationError('Unknown component versions must not carry an observed value.'),
      );
    }
    return ok({ kind: 'unknown' });
  }

  if (input.kind === 'known') {
    return knownComponentVersion(input.value);
  }

  return err(SBOM_INVALID_VERSION);
}

export function toOccurrenceVersionColumns(
  version: ComponentVersion,
): Result<OccurrenceVersionColumns> {
  const parsed = parseComponentVersion(version);
  if (!parsed.ok) {
    return parsed;
  }

  if (parsed.value.kind === 'unknown') {
    return ok({ versionKnown: false, version: '' });
  }

  return ok({ versionKnown: true, version: parsed.value.value });
}

export function fromOccurrenceVersionColumns(
  columns: OccurrenceVersionColumns,
): Result<ComponentVersion> {
  if (columns.versionKnown) {
    return knownComponentVersion(columns.version);
  }

  if (columns.version.length !== 0) {
    return err(
      sbomValidationError(
        'Unknown versions must persist an empty placeholder, not an observed value.',
      ),
    );
  }

  return ok(unknownComponentVersion());
}

export function isResolvedMatchingVersion(
  version: ComponentVersion,
): version is KnownComponentVersion {
  return version.kind === 'known';
}
