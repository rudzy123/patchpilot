/**
 * Public repeated-observation contracts.
 * The issuer module's minting function is not re-exported. Relative imports
 * of that module are an internal same-package trust boundary, not a supported
 * package export. This entry has no observation writer and no Finding mutator.
 */

export {
  FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY,
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT,
  FINDING_REPEATED_OBSERVATION_AGGREGATES,
  FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS,
  FINDING_REPEATED_OBSERVATION_AUDIT_ACTION,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_OUTCOMES,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_CALLER_SUPPLIED_FIELDS,
  FINDING_REPEATED_OBSERVATION_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_DERIVED_FIELDS,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_FINDING_IDENTITY_FIELDS,
  FINDING_REPEATED_OBSERVATION_FINDING_MUTATION,
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_INVARIANTS,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_METHOD,
  FINDING_REPEATED_OBSERVATION_NATURAL_IDENTITY_FIELDS,
  FINDING_REPEATED_OBSERVATION_NON_AGGREGATE_FAILURES,
  FINDING_REPEATED_OBSERVATION_NON_FINDING_IDENTITY_FIELDS,
  FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION,
  FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_OUTCOMES,
  FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION,
  FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_REASONS,
  FINDING_REPEATED_OBSERVATION_REJECTED_GENERIC_PURPOSES,
  FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS,
  FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS,
  FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT,
  FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_TRANSITION,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS,
  FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
  findingRepeatedObservationOutcomeExplanation,
  findingRepeatedObservationOutcomeForReason,
  isFindingRepeatedObservationAggregate,
  isFindingRepeatedObservationOutcome,
  mapRepeatedObservationAggregate,
  type FindingRepeatedObservationAggregate,
  type FindingRepeatedObservationAuthorizationOutcome,
  type FindingRepeatedObservationNonAggregateFailure,
  type FindingRepeatedObservationOutcome,
  type FindingRepeatedObservationReason,
} from './policy.js';

export {
  parseTrustedFindingRepeatedObservationContext,
  type FindingRepeatedObservationTrustedContextParse,
  type ParsedFindingRepeatedObservationTrustedContext,
} from './trusted-context.js';

export {
  classifyFindingRepeatedObservationAuthorizationReuse,
  openFindingRepeatedObservationCommand,
  presentFindingRepeatedObservationAuthorization,
  type FindingRepeatedObservationAuthorizationHandle,
  type FindingRepeatedObservationDenied,
  type FindingRepeatedObservationOpenResult,
  type FindingRepeatedObservationPresentationResult,
  type FindingRepeatedObservationReuseResult,
  type SealedFindingRepeatedObservationAbsenceCommand,
  type SealedFindingRepeatedObservationCommand,
  type SealedFindingRepeatedObservationEvidenceCommand,
} from './authorization.js';

export {
  FINDING_REPEATED_OBSERVATION_REPLAY_FINGERPRINT_SCHEMA,
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
  canonicalRepeatedObservationReplayFingerprint,
} from './support.js';

export {
  deriveComponentAbsenceClassification,
  deriveRepeatedObservationAggregate,
  type ComponentAbsenceClassification,
  type RepeatedObservationAggregateDerivation,
  type RepeatedObservationOccurrenceContribution,
} from './aggregate.js';

export {
  FINDING_REPEATED_OBSERVATION_REPLAY_CLASSIFICATIONS,
  classifyFindingRepeatedObservationReplay,
  type FindingRepeatedObservationReplayClassification,
  type FindingRepeatedObservationReplayOutcome,
  type FindingRepeatedObservationReplayResult,
} from './replay.js';

export {
  FINDING_REPEATED_OBSERVATION_PORT_EXCLUSIONS,
  repeatedObservationTenantDisclosure,
  type FindingRepeatedObservationTransactionRequest,
  type FindingRepeatedObservationTransactionResult,
  type FutureFindingRepeatedObservationPort,
} from './persistence.js';

export {
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY,
  classifyInspectionCompatibility,
  classifyInspectionObservationShape,
  type FindingInspectionCompatibilityResult,
  type FindingObservationInspectionShape,
} from './inspection-compatibility.js';
