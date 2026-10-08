/**
 * Read-only discovery persistence port.
 * The adapter returns examined pairs. It does not classify or write.
 */

export type FindingDiscoveryCursorPosition = {
  readonly ingestionId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
};

export type FindingDiscoveryReadQuery = {
  readonly organizationId: string;
  readonly membershipId: string;
  readonly actorId: string;
  readonly assetId: string;
  readonly cursor: FindingDiscoveryCursorPosition | null;
};

export type FindingDiscoveryQualifyingRow = {
  readonly id: string;
  readonly occurrenceId: string;
  readonly version: string | null;
};

export type FindingDiscoveryObservationFact = {
  readonly method: string;
  readonly result: string;
  readonly occurrenceId: string | null;
  readonly transitionClassification: string | null;
  readonly creationPurpose: string | null;
  readonly creationPolicyId: string | null;
  readonly creationPolicyVersion: number | null;
  readonly replayFingerprint: string | null;
  readonly affectedEvidenceCount: number | null;
  readonly sbomIngestionId: string;
};

export type FindingDiscoveryLineageFact = {
  readonly findingId: string;
  readonly state: string;
  readonly componentOccurrenceId: string | null;
  readonly resolvedAt: string | null;
  readonly reopenedAt: string | null;
  readonly assignedMembershipId: string | null;
  readonly assignedTeamId: string | null;
  readonly dueAt: string | null;
  readonly currentRiskCalculationId: string | null;
  readonly version: number;
  readonly observationCount: number;
  readonly observation: FindingDiscoveryObservationFact | null;
  readonly linkEvidenceIds: readonly string[];
};

export type FindingDiscoveryPairFact = {
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly vulnerabilityPublicId: string | null;
  readonly qualifyingCount: number;
  readonly qualifying: readonly FindingDiscoveryQualifyingRow[];
  readonly otherOccurrenceCount: number;
  readonly lineage: FindingDiscoveryLineageFact | null;
};

export type FindingDiscoveryRead =
  | { readonly status: 'authority_rejected' }
  | { readonly status: 'not_found' }
  | { readonly status: 'stale_cursor' }
  | { readonly status: 'database_unavailable' }
  | { readonly status: 'internal_failure' }
  | {
      readonly status: 'ready';
      readonly ingestionId: string | null;
      readonly pairs: readonly FindingDiscoveryPairFact[];
      readonly pairSpaceContinues: boolean;
    };

export type FindingDiscoveryPort = {
  read(query: FindingDiscoveryReadQuery): Promise<FindingDiscoveryRead>;
};
