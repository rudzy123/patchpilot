import { PackageURL } from 'packageurl-js';

export function parsePackageUrl(value: string): PackageURL {
  return PackageURL.fromString(value);
}
