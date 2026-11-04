import type { PublicAuthOrganization } from '@patchpilot/contracts';

/**
 * Presentation-only role checks for the controlled Finding web workflow.
 * The API remains authoritative for discovery, creation, replay, inspection,
 * and latest-observation inspection. Latest observation reuses inspection
 * presentation. It is not a separate permission.
 * These helpers are not `finding:read`, `finding:triage`, asset mutation ability,
 * or organization administration. A client-supplied role string is not authority.
 */
type PresentationRole = PublicAuthOrganization['role'] | null | undefined;

export function canPresentControlledFindingTargets(role: PresentationRole): boolean {
  return role === 'owner' || role === 'admin';
}

export function canPresentControlledFindingCreation(role: PresentationRole): boolean {
  return role === 'owner';
}

export function canPresentControlledFindingInspection(role: PresentationRole): boolean {
  return role === 'owner' || role === 'admin';
}

/** Owner and admin may see the priority section. The API remains authoritative. */
export function canPresentFindingPriority(role: PresentationRole): boolean {
  return role === 'owner' || role === 'admin';
}

/** Only an owner sees the calculate control. The API remains authoritative. */
export function canPresentFindingPriorityCalculation(role: PresentationRole): boolean {
  return role === 'owner';
}

/** Owner and admin may see the remediation queue. The API remains authoritative. */
export function canPresentRemediationQueue(role: PresentationRole): boolean {
  return role === 'owner' || role === 'admin';
}
