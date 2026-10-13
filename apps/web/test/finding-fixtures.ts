import type {
  ControlledFindingCreationRequest,
  ControlledFindingDiscoveryResponse,
  ControlledFindingInspectionResponse,
  ControlledFindingLatestObservationResponse,
} from '@patchpilot/contracts';

import { ASSET_ID } from './auth-fixtures';

export const COMPONENT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const COMPONENT_ID_2 = 'aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const VULNERABILITY_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
export const VULNERABILITY_ID_2 = 'bbbbbbb1-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
export const INGESTION_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
export const EVIDENCE_A = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
export const EVIDENCE_B = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
export const FINDING_ID = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
export const FINDING_ID_2 = 'ffffffff-ffff-4fff-8fff-fffffffffffe';
export const LATEST_OBSERVED_AT = '2026-10-08T12:00:00.000000Z';

export const acknowledgementFixture: ControlledFindingCreationRequest = {
  assetId: ASSET_ID,
  componentId: COMPONENT_ID,
  vulnerabilityId: VULNERABILITY_ID,
  expectedSbomIngestionId: INGESTION_ID,
  expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
};

export function discoveryPage(
  candidates: ControlledFindingDiscoveryResponse['candidates'],
  nextCursor: string | null = null,
  oversizedCandidateCount = 0,
): ControlledFindingDiscoveryResponse {
  return { candidates, nextCursor, oversizedCandidateCount };
}

export function eligibleCandidate(
  publicId = 'CVE-2024-0001',
  acknowledgement: ControlledFindingCreationRequest = acknowledgementFixture,
): Extract<
  ControlledFindingDiscoveryResponse['candidates'][number],
  { classification: 'eligible_for_creation' }
> {
  return {
    classification: 'eligible_for_creation',
    componentId: acknowledgement.componentId,
    vulnerabilityId: acknowledgement.vulnerabilityId,
    vulnerabilityPublicId: publicId,
    affectedVersions: {
      values: ['1.0.0', '2.0.0'],
      truncated: true,
      omittedDistinctCount: 3,
      distinctCount: 5,
    },
    affectedOccurrenceCount: 2,
    otherOccurrenceCount: 4,
    explanationCodes: ['several_affected_occurrences'],
    acknowledgement,
  };
}

export function replayCandidate(
  publicId = 'CVE-2024-0002',
): Extract<
  ControlledFindingDiscoveryResponse['candidates'][number],
  { classification: 'exact_replay_available' }
> {
  return {
    ...eligibleCandidate(publicId),
    classification: 'exact_replay_available',
  };
}

export function existingCandidate(
  publicId = 'CVE-2024-0003',
): Extract<
  ControlledFindingDiscoveryResponse['candidates'][number],
  { classification: 'existing_finding' }
> {
  return {
    classification: 'existing_finding',
    componentId: COMPONENT_ID_2,
    vulnerabilityId: VULNERABILITY_ID_2,
    vulnerabilityPublicId: publicId,
    affectedVersions: {
      values: ['9.9.9'],
      truncated: false,
      omittedDistinctCount: 0,
      distinctCount: 1,
    },
    affectedOccurrenceCount: 1,
    otherOccurrenceCount: 0,
    explanationCodes: ['lifecycle_update_unavailable'],
    lifecycleUpdate: 'unavailable',
  };
}

export const inspectionFixture: ControlledFindingInspectionResponse = {
  schemaVersion: 'finding_inspection_projection_v1',
  findingId: FINDING_ID,
  state: 'open',
  asset: { id: ASSET_ID, displayName: '<script>asset</script>' },
  component: {
    id: COMPONENT_ID,
    ecosystem: 'npm',
    namespace: '<namespace>',
    name: '<component>',
  },
  vulnerability: { id: VULNERABILITY_ID, publicId: '<img src=x onerror=alert(1)>' },
  affectedVersions: {
    values: ['1.0.0', '<version>'],
    truncated: true,
    omittedDistinctCount: 2,
    distinctCount: 4,
  },
  affectedOccurrenceCount: 2,
  otherOccurrenceCount: 3,
  otherOccurrenceClassification: 'other_occurrences_not_in_creation_evidence',
  createdAt: '2026-08-28T13:00:00.000Z',
  creationObservationPolicy: {
    policyId: 'finding_creation_policy_v1',
    policyVersion: 1,
  },
  explanationCodes: [
    'finding_created_from_affected_product_match_evidence',
    'independent_reviewer_approval',
  ],
  creationEvidenceApplicability: 'historical',
};

export function latestOccurrenceObservation(input: {
  findingId?: string;
  observationSource: 'creation' | 'latest_repeated';
  aggregate: 'affected' | 'unaffected' | 'unknown';
  observedAt?: string;
  affectedSupportCount?: number;
  unaffectedSupportCount?: number;
  unknownSupportCount?: number;
  unknownVersionSupportCount?: number;
  knownVersions?: {
    values: string[];
    truncated: boolean;
    omittedDistinctCount: number;
    distinctCount: number;
  };
}): ControlledFindingLatestObservationResponse {
  const observation = {
    schemaVersion: 'finding_latest_observation_transport_v1' as const,
    findingId: input.findingId ?? FINDING_ID,
    observationSource: input.observationSource,
    observedAt: input.observedAt ?? LATEST_OBSERVED_AT,
    aggregate: input.aggregate,
    evidence: {
      kind: 'occurrence_support' as const,
      affectedSupportCount: input.affectedSupportCount ?? 0,
      unaffectedSupportCount: input.unaffectedSupportCount ?? 0,
      unknownSupportCount: input.unknownSupportCount ?? 0,
      unknownVersionSupportCount: input.unknownVersionSupportCount ?? 0,
      knownVersions: input.knownVersions ?? {
        values: [],
        truncated: false,
        omittedDistinctCount: 0,
        distinctCount: 0,
      },
    },
  };
  return observation as ControlledFindingLatestObservationResponse;
}

export function creationLatestObservation(
  findingId = FINDING_ID,
): ControlledFindingLatestObservationResponse {
  return latestOccurrenceObservation({
    findingId,
    observationSource: 'creation',
    aggregate: 'affected',
    affectedSupportCount: 1,
    knownVersions: {
      values: ['1.0.0'],
      truncated: false,
      omittedDistinctCount: 0,
      distinctCount: 1,
    },
  });
}

export function componentAbsentLatestObservation(
  graphCompleteness: 'complete' | 'no_dependencies' = 'complete',
  findingId = FINDING_ID,
): ControlledFindingLatestObservationResponse {
  return {
    schemaVersion: 'finding_latest_observation_transport_v1',
    findingId,
    observationSource: 'latest_repeated',
    observedAt: LATEST_OBSERVED_AT,
    aggregate: 'component_absent',
    evidence: { kind: 'component_absence', graphCompleteness },
  };
}
