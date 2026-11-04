import type { PublicAuthOrganization } from '@patchpilot/contracts';

/**
 * Presentation-only check for the owner product-match candidate page.
 * The API remains authoritative. This helper does not grant evaluation.
 */
type PresentationRole = PublicAuthOrganization['role'] | null | undefined;

export function canPresentProductMatchCandidates(role: PresentationRole): boolean {
  return role === 'owner';
}
