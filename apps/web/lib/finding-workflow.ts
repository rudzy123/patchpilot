import type {
  ControlledFindingCreationRequest,
  ControlledFindingDiscoveryResponse,
} from '@patchpilot/contracts';

import { isAuthRequestError, type AuthRequestError } from './auth-api';

export const CONTROLLED_FINDING_UNAVAILABLE =
  'Controlled Finding targets are unavailable for your role in this organization.';

export const CREATION_REQUIRES_OWNER = 'Creation requires an owner.';

export const EXACT_REPLAY_OWNER_NOTE =
  'The server may return the existing Finding and will not create a duplicate when the lineage matches.';

export const EXISTING_FINDING_NOTE =
  'A Finding already exists for this target. Updating it is not available here.';

export const EMPTY_TARGETS_NOTE =
  'No controlled Finding targets are available for this asset right now. This page lists only targets the current creation policy can describe.';

export const OVERSIZED_TARGETS_NOTE =
  'Some targets were omitted because their evidence set is larger than the creation policy allows.';

export const STALE_EVIDENCE_SUMMARY = 'The request conflicts with the current evidence.';

export const STALE_EVIDENCE_GUIDANCE =
  'This target changed before a Finding could be recorded from this acknowledgement. Refresh the targets and review the new acknowledgement.';

export const UNPROCESSABLE_EVIDENCE_NOTE = 'The evidence cannot be used for this request.';

export const COMMIT_UNCERTAINTY_NOTE =
  'Creation result could not be confirmed. Refresh the targets, or retry this same acknowledgement.';

export const CREATED_NOTE = 'One Finding was created.';

export const ALREADY_APPLIED_NOTE =
  'This Finding was already recorded with the same creation lineage.';

export const STALE_CURSOR_NOTE = 'The page is no longer current.';

export const RATE_LIMITED_NOTE = 'Too many requests. Try again later.';

export const SERVICE_UNAVAILABLE_NOTE = 'Finding inspection is temporarily unavailable.';

export const TARGETS_UNAVAILABLE_NOTE = 'Controlled Finding targets are temporarily unavailable.';

export const ASSET_NOT_FOUND_NOTE = 'Asset not found.';

export const FINDING_NOT_FOUND_NOTE = 'Not found.';

export const LIFECYCLE_UNAVAILABLE_NOTE =
  'Updating this Finding, assignment, risk, priority, due dates, suppression, accepted risk, false-positive decisions, remediation, verification, ticketing, and notifications are unavailable in this workflow.';

export const ACKNOWLEDGEMENT_MISMATCH_NOTE = 'The acknowledgement does not match this asset.';

export type AcknowledgedDiscoveryCandidate = Extract<
  ControlledFindingDiscoveryResponse['candidates'][number],
  { acknowledgement: ControlledFindingCreationRequest }
>;

export type CreationFailureKind =
  | 'expired'
  | 'unavailable'
  | 'not_found'
  | 'rate_limited'
  | 'stale'
  | 'unprocessable'
  | 'uncertain'
  | 'bounded';

/**
 * Copies the acknowledgement fields the owner is about to review.
 * Evidence ids stay in server order. Extra properties are not copied.
 */
export function snapshotAcknowledgement(
  acknowledgement: ControlledFindingCreationRequest,
): ControlledFindingCreationRequest {
  const expectedProductMatchEvidenceIds = acknowledgement.expectedProductMatchEvidenceIds.slice();
  const snapshot: ControlledFindingCreationRequest = {
    assetId: acknowledgement.assetId,
    componentId: acknowledgement.componentId,
    vulnerabilityId: acknowledgement.vulnerabilityId,
    expectedSbomIngestionId: acknowledgement.expectedSbomIngestionId,
    expectedProductMatchEvidenceIds,
  };
  Object.freeze(expectedProductMatchEvidenceIds);
  return Object.freeze(snapshot);
}

export function readCreationCsrf(token: string | null): string | 'session_expired' {
  if (token === null || token.length === 0) {
    return 'session_expired';
  }
  return token;
}

/**
 * A parsed documented refusal is confirmed. Transport loss, an unparsed body,
 * HTTP 500, and HTTP 503 stay unconfirmed because the server may have committed.
 */
export function classifyCreationFailure(error: unknown): CreationFailureKind {
  if (!isAuthRequestError(error)) {
    return 'uncertain';
  }
  if (error.status === 0 || error.status === 500 || error.status === 503) {
    return 'uncertain';
  }
  if (error.status === 401) {
    return 'expired';
  }
  if (error.status === 403) {
    return 'unavailable';
  }
  if (error.status === 404) {
    return 'not_found';
  }
  if (error.status === 429 || error.code === 'rate_limited') {
    return 'rate_limited';
  }
  if (error.requestId === undefined) {
    return 'uncertain';
  }
  if (error.status === 409 && error.code === 'conflict') {
    return 'stale';
  }
  if (error.status === 422 && error.code === 'unprocessable_evidence') {
    return 'unprocessable';
  }
  return 'bounded';
}

export function confirmationActionLabel(candidate: AcknowledgedDiscoveryCandidate): string {
  if (candidate.classification === 'exact_replay_available') {
    return `Submit exact replay acknowledgement for ${candidate.vulnerabilityPublicId}`;
  }
  return `Create Finding for ${candidate.vulnerabilityPublicId}`;
}

export function discoveryExplanationText(code: string): string {
  switch (code) {
    case 'several_affected_occurrences':
      return 'Several affected occurrences are included in this target.';
    case 'affected_version_summary_truncated':
      return 'The affected-version summary is truncated.';
    case 'other_occurrences_present':
      return 'Other occurrences are present and are not part of this acknowledgement.';
    case 'lifecycle_update_unavailable':
      return 'Updating an existing Finding is not available here.';
    default:
      return code;
  }
}

export function inspectionExplanationText(code: string): string {
  switch (code) {
    case 'finding_created_from_affected_product_match_evidence':
      return 'This Finding was recorded from affected product-match evidence.';
    case 'maintainer_reviewed_advisory_source':
      return 'The recorded source is a maintainer-reviewed advisory.';
    case 'independent_reviewer_approval':
      return 'An independent approval is part of the recorded evidence.';
    case 'affected_within_introduced_fixed_range':
      return 'The recorded range evaluation treated the observed versions as affected.';
    case 'several_affected_occurrences':
      return 'Several affected occurrences are included.';
    case 'other_occurrences_not_in_creation_evidence':
      return 'Other occurrences are not part of the creation evidence.';
    case 'creation_evidence_historical':
      return 'The creation evidence is historical.';
    default:
      return code;
  }
}

export function inspectionApplicabilityText(value: 'current' | 'historical'): string {
  return value === 'current' ? 'Current' : 'Historical';
}

export function otherOccurrenceClassificationText(value: string): string {
  switch (value) {
    case 'other_occurrences_not_in_creation_evidence':
      return 'Other occurrences are not in the creation evidence.';
    case 'no_other_occurrences_in_creation_ingestion':
      return 'No other occurrences were in the creation ingestion.';
    default:
      return value;
  }
}

export function requestIdentifiers(error: AuthRequestError): {
  requestId: string | null;
  correlationId: string | null;
} {
  return {
    requestId: error.requestId ?? null,
    correlationId: error.correlationId ?? null,
  };
}
