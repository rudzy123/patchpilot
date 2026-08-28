import type { PublicAuthOrganization } from '@patchpilot/contracts';

/**
 * Presentation-only. The API still authorizes asset mutations.
 * Interim ADR 0019 mapping: admin and owner may manage assets.
 */
export function canMutateAssets(role: PublicAuthOrganization['role'] | null | undefined): boolean {
  return role === 'admin' || role === 'owner';
}
