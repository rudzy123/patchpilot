/**
 * Bounded read port for one organization-scoped Finding inspection.
 * The bundle is untrusted adapter output. It is not a tenant response.
 */

export type FindingInspectionLoadQuery = {
  readonly organizationId: string;
  readonly findingId: string;
};

export type FindingInspectionObservationRecord = {
  readonly id: string;
  readonly sbomIngestionId: string;
  readonly occurrenceId: string | null;
  readonly result: string;
  readonly method: string;
  readonly transitionClassification: string | null;
  readonly creationPurpose: string | null;
  readonly creationPolicyId: string | null;
  readonly creationPolicyVersion: number | null;
  readonly affectedEvidenceCount: number | null;
  readonly replayAgrees: boolean;
  readonly evidenceRecordAgrees: boolean;
};

export type FindingInspectionLinkRecord = {
  readonly evidenceId: string;
  readonly findingObservationId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly componentOccurrenceId: string;
  readonly linkOutcome: string;
  readonly evidencePresent: boolean;
  /**
   * False when an evidence row in the trusted organization uses this evidence
   * id but its asset, component, vulnerability, ingestion, or occurrence does
   * not match the link. Absence of the row is not a target contradiction.
   */
  readonly evidenceTargetAligned: boolean;
  readonly evidenceOutcome: string | null;
  readonly productOrigin: string | null;
  readonly evaluatorId: string | null;
  readonly evaluatorVersion: string | null;
  readonly matchingPolicyId: string | null;
  readonly matchingPolicyVersion: string | null;
  readonly productEvidencePolicyId: string | null;
  readonly productEvidencePolicyVersion: number | null;
  readonly evidenceSchemaVersion: string | null;
  readonly findingCreation: string | null;
  readonly suppressionAuthority: boolean | null;
  readonly rawObservedVersion: string | null;
  readonly occurrencePresent: boolean;
  readonly occurrenceVersion: string | null;
  readonly occurrenceVersionKnown: boolean | null;
  readonly occurrenceAssetId: string | null;
  readonly occurrenceComponentId: string | null;
  readonly occurrenceIngestionId: string | null;
  readonly revisionPresent: boolean;
  readonly withdrawal: string | null;
  readonly quarantine: string | null;
  readonly hasSuccessor: boolean;
  readonly approvalPresent: boolean;
  readonly approvalPurpose: string | null;
  readonly approvalRevisionMatches: boolean;
  readonly approvalVulnerabilityMatches: boolean;
  readonly bindingPresent: boolean;
  readonly bindingReviewed: boolean;
  readonly normalizationVersion: string | null;
  readonly ingestionState: string | null;
  readonly ingestionPresent: boolean;
  readonly explanationCodes: readonly string[];
};

export type FindingInspectionEvidenceBundle = {
  readonly findingId: string;
  readonly state: string;
  readonly createdAt: string | null;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly componentOccurrenceId: string | null;
  readonly resolvedAt: string | null;
  readonly reopenedAt: string | null;
  readonly assignedMembershipId: string | null;
  readonly assignedTeamId: string | null;
  readonly dueAt: string | null;
  readonly currentRiskCalculationId: string | null;
  readonly version: number;
  readonly assetPresent: boolean;
  readonly assetDisplayName: string | null;
  readonly assetCurrentIngestionId: string | null;
  readonly componentPresent: boolean;
  readonly componentEcosystem: string | null;
  readonly componentNamespace: string | null;
  readonly componentName: string | null;
  readonly vulnerabilityPresent: boolean;
  readonly vulnerabilityPublicId: string | null;
  readonly remediationTaskCount: number;
  readonly riskAcceptanceCount: number;
  readonly riskCalculationCount: number;
  readonly genericEvidenceCount: number;
  readonly creationIngestionOccurrenceCount: number;
  readonly otherOccurrenceCount: number;
  readonly observations: readonly FindingInspectionObservationRecord[];
  readonly links: readonly FindingInspectionLinkRecord[];
};

export type FindingInspectionLoad =
  | { readonly status: 'not_found' }
  | { readonly status: 'evidence_unavailable' }
  | { readonly status: 'malformed_persisted_state' }
  | { readonly status: 'database_unavailable' }
  | { readonly status: 'internal_failure' }
  | { readonly status: 'ready'; readonly bundle: FindingInspectionEvidenceBundle };

export type FindingInspectionPort = {
  load(query: FindingInspectionLoadQuery): Promise<FindingInspectionLoad>;
};
