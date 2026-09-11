/**
 * Session 13 Batch 3D-A-R mapping from Prisma protected listing-observation
 * evidence rows to public records. Public projections omit envelope BYTEA,
 * opaque key alias, plaintext identity, ciphertext, nonce, and tag.
 * Unknown persisted enums fail closed. No repair.
 */

import type {
  OsvListingObservationEvidencePublicObservation,
  OsvListingObservationEvidencePublicRecord,
  OsvProtectedListingObservationCandidateSelectionEligibility,
  OsvProtectedListingObservationDuplicateClassification,
  OsvProtectedListingObservationEvidenceState,
  OsvProtectedListingObservationImmutableConflictClassification,
  OsvProtectedListingObservationSetCandidateReadiness,
} from '@patchpilot/vulnerability-intelligence';

export class OsvListingObservationEvidenceMappingError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvListingObservationEvidenceMappingError';
  }
}

const EVIDENCE_STATES = new Set<string>([
  'constructed',
  'incomplete',
  'overflow_rejected',
  'conflict_quarantine_required',
  'duplicate_ambiguous',
  'malformed_rejected',
  'review_pending',
  'review_accepted',
  'review_rejected',
  'failed',
  'purged',
]);

const CANDIDATE_READINESS = new Set<string>([
  'metadata_complete_selection_not_authorized',
  'empty_page_not_candidate_ready',
  'ineligible_incomplete',
  'ineligible_overflow',
  'ineligible_conflict',
  'ineligible_duplicate_ambiguity',
  'ineligible_binding_mismatch',
  'review_not_accepted',
]);

const DUPLICATE_CLASSIFICATIONS = new Set<string>([
  'none',
  'exact_duplicate',
  'duplicate_across_translator_positions',
  'malformed_duplicate',
]);

const IMMUTABLE_CONFLICT_CLASSIFICATIONS = new Set<string>([
  'none',
  'declared_size_mismatch_same_object_generation',
  'source_family_mismatch_same_object_generation',
  'classification_mismatch_same_object_generation',
  'binding_mismatch_same_object_generation',
  'provider_key_digest_collision',
  'cross_object_generation_substitution',
]);

const ELIGIBILITIES = new Set<string>([
  'eligible_for_later_selection_evaluation',
  'ineligible_unknown_or_ambiguous_family',
  'ineligible_unclassifiable_family',
  'ineligible_declared_size',
  'ineligible_missing_protected_identity',
  'ineligible_missing_generation',
  'ineligible_duplicate',
  'ineligible_conflict',
  'ineligible_set_incomplete',
]);

const CLASSIFICATION_STATUSES = new Set<string>([
  'eligible',
  'ineligible',
  'legal_review_required',
  'unknown',
  'ambiguous',
]);

const LEGAL_HOLD_CLASSIFICATIONS = new Set<string>([
  'hold_absent',
  'legal_hold_active',
  'hold_released',
]);

const GENERATION = /^[1-9][0-9]{0,19}$/;
const SOURCE_FAMILY =
  /^(known:[A-Z][A-Z0-9._-]{0,63}|unknown_uppercase:[A-Z][A-Z0-9._-]{0,63}|unclassifiable)$/;
const SHA256 = /^[a-f0-9]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const RESTRICTED_FIELDS = [
  'protectedIdentityEnvelope',
  'opaqueKeyAlias',
  'ciphertext',
  'nonce',
  'authenticationTag',
  'providerObjectKey',
  'organizationId',
  'tenantId',
  'findingId',
] as const;

export function toIsoUtc(value: Date): string {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new OsvListingObservationEvidenceMappingError('timestamp mapping failed.');
  }
  return value.toISOString().replace(/\.000Z$/, 'Z');
}

export function bigintToDecimalString(value: bigint, field: string): string {
  if (typeof value !== 'bigint' || value < 0n) {
    throw new OsvListingObservationEvidenceMappingError(`${field} mapping failed.`);
  }
  return value.toString(10);
}

function requireUuid(value: string, field: string): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) {
    throw new OsvListingObservationEvidenceMappingError(`${field} mapping failed.`);
  }
  return value;
}

function requireMember<T extends string>(
  value: string,
  allowed: ReadonlySet<string>,
  field: string,
): T {
  if (!allowed.has(value)) {
    throw new OsvListingObservationEvidenceMappingError(`${field} mapping failed.`);
  }
  return value as T;
}

type ObservationRow = {
  readonly id: string;
  readonly observationOrdinal: number;
  readonly listingObservationIdentity: string;
  readonly providerGeneration: string;
  readonly declaredListingByteCount: bigint;
  readonly sourceFamilyClassification: string;
  readonly classificationStatus: string;
  readonly duplicateClassification: string;
  readonly immutableConflictClassification: string;
  readonly candidateSelectionEligibility: string;
};

type SetRow = {
  readonly id: string;
  readonly evidenceSchemaVersion: string;
  readonly listingExecutionId: string;
  readonly providerContactAuthorizationId: string;
  readonly synchronizationRequestId: string;
  readonly synchronizationRunId: string;
  readonly provider: string;
  readonly approvedPrefix: string;
  readonly listingProtocolId: string;
  readonly listingPolicyId: string;
  readonly budgetProfileId: string;
  readonly runtimeVersionSetFingerprint: string;
  readonly pageOrdinal: number;
  readonly canonicalEvidenceSetDigest: string;
  readonly translatorObservationCount: number;
  readonly acceptedObservationCount: number;
  readonly protectedObservationCount: number;
  readonly rejectedObservationCount: number;
  readonly exactDuplicateCount: number;
  readonly duplicateAmbiguityCount: number;
  readonly immutableConflictCount: number;
  readonly evidenceState: string;
  readonly candidateSelectionReadiness: string;
  readonly legalHoldActive: boolean;
  readonly legalHoldClassification: string;
  readonly rowRevision: bigint;
  readonly capturedAt: Date;
  readonly reviewRecordedAt: Date | null;
  readonly observations?: readonly ObservationRow[];
};

function assertNoRestrictedFields(row: object): void {
  for (const field of RESTRICTED_FIELDS) {
    if (Object.hasOwn(row, field)) {
      throw new OsvListingObservationEvidenceMappingError('restricted envelope field present.');
    }
  }
}

function requireNonNegativeCount(value: number, field: string, maximum: number): number {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new OsvListingObservationEvidenceMappingError(`${field} mapping failed.`);
  }
  return value;
}

export function mapPublicObservation(
  row: ObservationRow,
): OsvListingObservationEvidencePublicObservation {
  assertNoRestrictedFields(row);
  if (!Number.isInteger(row.observationOrdinal) || row.observationOrdinal < 1) {
    throw new OsvListingObservationEvidenceMappingError('observation ordinal mapping failed.');
  }
  if (
    typeof row.listingObservationIdentity !== 'string' ||
    !SHA256.test(row.listingObservationIdentity)
  ) {
    throw new OsvListingObservationEvidenceMappingError(
      'listing observation identity mapping failed.',
    );
  }
  if (!GENERATION.test(row.providerGeneration)) {
    throw new OsvListingObservationEvidenceMappingError('generation mapping failed.');
  }
  if (
    typeof row.sourceFamilyClassification !== 'string' ||
    !SOURCE_FAMILY.test(row.sourceFamilyClassification)
  ) {
    throw new OsvListingObservationEvidenceMappingError('source family mapping failed.');
  }
  if (row.declaredListingByteCount < 0n || row.declaredListingByteCount > 1_048_576n) {
    throw new OsvListingObservationEvidenceMappingError('declared size mapping failed.');
  }
  return {
    observationId: requireUuid(row.id, 'observationId'),
    observationOrdinal: row.observationOrdinal,
    listingObservationIdentity: row.listingObservationIdentity,
    providerGeneration: row.providerGeneration,
    declaredListingByteCount: bigintToDecimalString(
      row.declaredListingByteCount,
      'declaredListingByteCount',
    ),
    sourceFamilyClassification: row.sourceFamilyClassification,
    classificationStatus: requireMember(
      row.classificationStatus,
      CLASSIFICATION_STATUSES,
      'classificationStatus',
    ),
    duplicateClassification: requireMember<OsvProtectedListingObservationDuplicateClassification>(
      row.duplicateClassification,
      DUPLICATE_CLASSIFICATIONS,
      'duplicateClassification',
    ),
    immutableConflictClassification:
      requireMember<OsvProtectedListingObservationImmutableConflictClassification>(
        row.immutableConflictClassification,
        IMMUTABLE_CONFLICT_CLASSIFICATIONS,
        'immutableConflictClassification',
      ),
    candidateSelectionEligibility:
      requireMember<OsvProtectedListingObservationCandidateSelectionEligibility>(
        row.candidateSelectionEligibility,
        ELIGIBILITIES,
        'candidateSelectionEligibility',
      ),
    candidateSelectionAuthorized: false,
    bodyRetrievalAuthorized: false,
    batch4pPermitted: false,
  };
}

export function mapPublicEvidenceSet(row: SetRow): OsvListingObservationEvidencePublicRecord {
  assertNoRestrictedFields(row);
  if (row.pageOrdinal !== 1) {
    throw new OsvListingObservationEvidenceMappingError('page ordinal mapping failed.');
  }
  if (
    !SHA256.test(row.canonicalEvidenceSetDigest) ||
    !SHA256.test(row.runtimeVersionSetFingerprint)
  ) {
    throw new OsvListingObservationEvidenceMappingError('digest mapping failed.');
  }
  const legalHoldClassification = requireMember(
    row.legalHoldClassification,
    LEGAL_HOLD_CLASSIFICATIONS,
    'legalHoldClassification',
  );
  if (row.legalHoldActive !== (legalHoldClassification === 'legal_hold_active')) {
    throw new OsvListingObservationEvidenceMappingError('legal hold mapping failed.');
  }
  const translatorObservationCount = requireNonNegativeCount(
    row.translatorObservationCount,
    'translatorObservationCount',
    1000,
  );
  const acceptedObservationCount = requireNonNegativeCount(
    row.acceptedObservationCount,
    'acceptedObservationCount',
    1000,
  );
  const protectedObservationCount = requireNonNegativeCount(
    row.protectedObservationCount,
    'protectedObservationCount',
    1000,
  );
  const rejectedObservationCount = requireNonNegativeCount(
    row.rejectedObservationCount,
    'rejectedObservationCount',
    1000,
  );
  if (translatorObservationCount !== acceptedObservationCount + rejectedObservationCount) {
    throw new OsvListingObservationEvidenceMappingError('count mapping failed.');
  }
  if (protectedObservationCount > acceptedObservationCount) {
    throw new OsvListingObservationEvidenceMappingError('count mapping failed.');
  }
  const observations = [...(row.observations ?? [])]
    .sort((left, right) => left.observationOrdinal - right.observationOrdinal)
    .map(mapPublicObservation);
  if (observations.length !== protectedObservationCount) {
    throw new OsvListingObservationEvidenceMappingError('observation count mapping failed.');
  }
  return {
    evidenceSetId: requireUuid(row.id, 'evidenceSetId'),
    evidenceSchemaVersion: row.evidenceSchemaVersion,
    listingExecutionId: requireUuid(row.listingExecutionId, 'listingExecutionId'),
    providerContactAuthorizationId: requireUuid(
      row.providerContactAuthorizationId,
      'providerContactAuthorizationId',
    ),
    synchronizationRequestId: requireUuid(row.synchronizationRequestId, 'synchronizationRequestId'),
    synchronizationRunId: requireUuid(row.synchronizationRunId, 'synchronizationRunId'),
    provider: row.provider,
    approvedPrefix: row.approvedPrefix,
    listingProtocolId: row.listingProtocolId,
    listingPolicyId: row.listingPolicyId,
    budgetProfileId: row.budgetProfileId,
    runtimeVersionSetFingerprint: row.runtimeVersionSetFingerprint,
    pageOrdinal: 1,
    canonicalEvidenceSetDigest: row.canonicalEvidenceSetDigest,
    translatorObservationCount,
    acceptedObservationCount,
    protectedObservationCount,
    rejectedObservationCount,
    exactDuplicateCount: requireNonNegativeCount(
      row.exactDuplicateCount,
      'exactDuplicateCount',
      1000,
    ),
    duplicateAmbiguityCount: requireNonNegativeCount(
      row.duplicateAmbiguityCount,
      'duplicateAmbiguityCount',
      1000,
    ),
    immutableConflictCount: requireNonNegativeCount(
      row.immutableConflictCount,
      'immutableConflictCount',
      1000,
    ),
    evidenceState: requireMember<OsvProtectedListingObservationEvidenceState>(
      row.evidenceState,
      EVIDENCE_STATES,
      'evidenceState',
    ),
    candidateSelectionReadiness: requireMember<OsvProtectedListingObservationSetCandidateReadiness>(
      row.candidateSelectionReadiness,
      CANDIDATE_READINESS,
      'candidateSelectionReadiness',
    ),
    candidateSelectionAuthorized: false,
    bodyRetrievalAuthorized: false,
    batch4pPermitted: false,
    paginationAuthorized: false,
    activationAuthorized: false,
    matchingAuthorized: false,
    findingWritesAuthorized: false,
    providerContactAuthorized: false,
    legalHoldActive: row.legalHoldActive,
    legalHoldClassification,
    rowRevision: bigintToDecimalString(row.rowRevision, 'rowRevision'),
    capturedAt: toIsoUtc(row.capturedAt),
    reviewRecordedAt: row.reviewRecordedAt === null ? null : toIsoUtc(row.reviewRecordedAt),
    observations,
  };
}
