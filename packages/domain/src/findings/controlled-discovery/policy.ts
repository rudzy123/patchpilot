/**
 * Read-only controlled Finding target discovery contracts.
 * These constants do not issue creation authority and do not persist a Finding.
 */

import { FINDING_CREATION_MAX_EVIDENCE_SET_SIZE } from '../controlled-creation/policy.js';

export const FINDING_DISCOVERY_CURSOR_SCHEMA_VERSION = 'finding_discovery_cursor_v1' as const;

export const FINDING_DISCOVERY_DEFAULT_PAGE_SIZE = 10 as const;

export const FINDING_DISCOVERY_MIN_PAGE_SIZE = 1 as const;

export const FINDING_DISCOVERY_MAX_PAGE_SIZE = 20 as const;

export const FINDING_DISCOVERY_MAX_EXAMINED_PAIRS = 100 as const;

export const FINDING_DISCOVERY_MAX_CURSOR_LENGTH = 4096 as const;

export const FINDING_DISCOVERY_AFFECTED_VERSION_DISPLAY_LIMIT = 8 as const;

export const FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE = FINDING_CREATION_MAX_EVIDENCE_SET_SIZE;

export const FINDING_DISCOVERY_MAX_OVERSIZED_COUNT = FINDING_DISCOVERY_MAX_EXAMINED_PAIRS;

export const FINDING_DISCOVERY_CLASSIFICATIONS = [
  'eligible_for_creation',
  'exact_replay_available',
  'existing_finding',
] as const;

export type FindingDiscoveryClassification = (typeof FINDING_DISCOVERY_CLASSIFICATIONS)[number];

export const FINDING_DISCOVERY_LIFECYCLE_UPDATE = 'unavailable' as const;

export const FINDING_DISCOVERY_EXPLANATION_CODES = [
  'several_affected_occurrences',
  'affected_version_summary_truncated',
  'other_occurrences_present',
  'lifecycle_update_unavailable',
] as const;

export type FindingDiscoveryExplanationCode = (typeof FINDING_DISCOVERY_EXPLANATION_CODES)[number];

export const FINDING_DISCOVERY_CREATION_METHOD = 'controlled_finding_creation' as const;

export const FINDING_DISCOVERY_CREATION_TRANSITION = 'initial_creation' as const;

export const FINDING_DISCOVERY_PRODUCTION_REGISTRATION = 'api_process' as const;

export const FINDING_DISCOVERY_VERSION_DISPLAY_MAX_LENGTH = 256 as const;

export const FINDING_DISCOVERY_PUBLIC_ID_MAX_LENGTH = 128 as const;
