/**
 * Controlled Finding inspection contracts.
 * Read-time explanation only. This module does not persist, compose
 * production, or authorize a Finding lifecycle transition.
 */

import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
} from '../controlled-creation/policy.js';

export const FINDING_INSPECTION_COMMAND_SCHEMA_VERSION = 'finding_inspection_command_v1' as const;

export const FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION =
  'finding_inspection_trusted_context_v1' as const;

export const FINDING_INSPECTION_RESULT_SCHEMA_VERSION = 'finding_inspection_result_v1' as const;

export const FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION =
  'finding_inspection_projection_v1' as const;

export const FINDING_INSPECTION_PRODUCTION_REGISTRATION = 'absent' as const;

/**
 * Safe display ceiling for distinct affected-version strings.
 * The creation policy may link up to 16 occurrences. Inspection still
 * reports the full affected-occurrence count when this ceiling truncates
 * the displayed values.
 */
export const FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT = 8 as const;

export const FINDING_INSPECTION_STATUSES = [
  'found',
  'not_found',
  'evidence_unavailable',
  'malformed_persisted_state',
  'database_unavailable',
  'internal_failure',
] as const;

export type FindingInspectionStatus = (typeof FINDING_INSPECTION_STATUSES)[number];

export const FINDING_INSPECTION_APPLICABILITY = ['current', 'historical'] as const;

export type FindingInspectionApplicability = (typeof FINDING_INSPECTION_APPLICABILITY)[number];

export const FINDING_INSPECTION_EXPLANATION_CODES = [
  'finding_created_from_affected_product_match_evidence',
  'maintainer_reviewed_advisory_source',
  'independent_reviewer_approval',
  'affected_within_introduced_fixed_range',
  'several_affected_occurrences',
  'other_occurrences_not_in_creation_evidence',
  'creation_evidence_historical',
] as const;

export type FindingInspectionExplanationCode =
  (typeof FINDING_INSPECTION_EXPLANATION_CODES)[number];

export const FINDING_INSPECTION_OTHER_OCCURRENCE_CLASSIFICATIONS = [
  'other_occurrences_not_in_creation_evidence',
  'no_other_occurrences_in_creation_ingestion',
] as const;

export type FindingInspectionOtherOccurrenceClassification =
  (typeof FINDING_INSPECTION_OTHER_OCCURRENCE_CLASSIFICATIONS)[number];

export const FINDING_INSPECTION_WITHHELD_POWERS = [
  'finding_update',
  'repeated_observation',
  'risk',
  'priority',
  'assignment',
  'due_date',
  'suppression',
  'accepted_risk',
  'false_positive',
  'remediation',
  'verification',
  'notification',
  'dashboard',
  'export',
  'ticketing',
  'ai_authority',
  'lifecycle_transition',
] as const;

export const FINDING_INSPECTION_CREATION_METHOD = 'controlled_finding_creation' as const;

export const FINDING_INSPECTION_CREATION_TRANSITION = 'initial_creation' as const;

export const FINDING_INSPECTION_ACCEPTED_EVALUATOR_ID =
  'osv_first_ecosystem_affected_version_evaluator_v1' as const;

export const FINDING_INSPECTION_ACCEPTED_EVALUATOR_VERSION =
  'session_14_batch_2_in_memory' as const;

export const FINDING_INSPECTION_ACCEPTED_MATCHING_POLICY_ID =
  'osv_first_ecosystem_matching_architecture_v1' as const;

export const FINDING_INSPECTION_ACCEPTED_ORIGIN = 'maintainer_reviewed_advisory' as const;

export const FINDING_INSPECTION_ACCEPTED_APPROVAL_PURPOSE =
  'approve_maintainer_reviewed_advisory_for_product_evaluation' as const;

export const FINDING_INSPECTION_ACCEPTED_EVIDENCE_SCHEMA =
  'product_match_evaluation_evidence_v1' as const;

export const FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_ID =
  'product_match_evaluation_policy_v1' as const;

export const FINDING_INSPECTION_ACCEPTED_PRODUCT_POLICY_VERSION = 1 as const;

export const FINDING_INSPECTION_ACCEPTED_RANGE_CODE =
  'affected_within_introduced_fixed_range' as const;

export const FINDING_INSPECTION_NORMALIZATION_VERSION = '2' as const;

export const FINDING_INSPECTION_CREATION_POLICY_ID = FINDING_CREATION_POLICY_ID;

export const FINDING_INSPECTION_CREATION_POLICY_VERSION = FINDING_CREATION_POLICY_VERSION;

export const FINDING_INSPECTION_CREATION_PURPOSE = FINDING_CREATION_PURPOSE;

export const FINDING_INSPECTION_AMBIENT_CLAIMS = [
  'administrator',
  'admin',
  'owner',
  'maintainer',
  'role',
  'permission',
  'permissions',
  'membershipRole',
  'isAdmin',
  'authorized',
] as const;
