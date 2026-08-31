import { PackageURL } from 'packageurl-js';
import { err, ok, type Result } from '@patchpilot/domain';

export type NormalizedPackageUrl = {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  versionless: string;
  versioned: string | null;
};

function optionalPurlPart(value: string | undefined): string | undefined {
  return value === undefined || value.length === 0 ? undefined : value;
}

export function parsePackageUrl(value: string): PackageURL {
  return PackageURL.fromString(value);
}

/**
 * Canonicalize a PURL. Versionless identity never includes version, qualifiers,
 * or subpath. Versioned identity keeps the listed version only (no qualifiers
 * or subpath) so Component vs ComponentOccurrence stay distinct.
 */
export function normalizePackageUrl(value: string): Result<NormalizedPackageUrl> {
  try {
    const parsed = parsePackageUrl(value);
    const namespace = optionalPurlPart(parsed.namespace);
    const versionless = new PackageURL(
      parsed.type,
      namespace,
      parsed.name,
      undefined,
      undefined,
      undefined,
    ).toString();
    const listedVersion = optionalPurlPart(parsed.version);
    const versioned =
      listedVersion === undefined
        ? null
        : new PackageURL(
            parsed.type,
            namespace,
            parsed.name,
            listedVersion,
            undefined,
            undefined,
          ).toString();
    return ok({
      type: parsed.type,
      namespace: namespace ?? null,
      name: parsed.name,
      version: listedVersion ?? null,
      versionless,
      versioned,
    });
  } catch {
    return err({ code: 'validation', message: 'Package URL is not valid.' });
  }
}

export function versionedPackageUrl(
  identity: NormalizedPackageUrl,
  version: string,
): Result<string> {
  try {
    return ok(
      new PackageURL(
        identity.type,
        identity.namespace ?? undefined,
        identity.name,
        version,
        undefined,
        undefined,
      ).toString(),
    );
  } catch {
    return err({ code: 'validation', message: 'Package URL is not valid.' });
  }
}
