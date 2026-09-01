import { SHA256_HEX_PATTERN, UUID_PATTERN } from '../sbom/constants.js';

export { SHA256_HEX_PATTERN, UUID_PATTERN };

export const intelligenceProviders = ['cisa_kev', 'osv'] as const;
export type IntelligenceProvider = (typeof intelligenceProviders)[number];

export const intelligenceRuntimeProviders = ['cisa_kev'] as const;
export type IntelligenceRuntimeProvider = (typeof intelligenceRuntimeProviders)[number];

export const intelligenceDeferredProviders = ['osv'] as const;
export type IntelligenceDeferredProvider = (typeof intelligenceDeferredProviders)[number];

export const CISA_KEV_SOURCE_IDENTIFIER = 'cisa_kev_json_catalog' as const;
export const intelligenceSourceIdentifiers = [CISA_KEV_SOURCE_IDENTIFIER] as const;
export type IntelligenceSourceIdentifier = (typeof intelligenceSourceIdentifiers)[number];

export const intelligenceProviderDisplayNames = {
  cisa_kev: 'CISA Known Exploited Vulnerabilities',
  osv: 'OSV',
} as const;

export const intelligenceProviderRuntimeCapabilities = {
  cisa_kev: 'planned',
  osv: 'deferred_fail_closed',
} as const;

export const intelligenceProviderImplementationStatuses = [
  'available',
  'disabled',
  'deferred',
] as const;
export type IntelligenceProviderImplementationStatus =
  (typeof intelligenceProviderImplementationStatuses)[number];

export const intelligenceProviderHealthStatuses = [
  'current',
  'stale',
  'never_synchronized',
  'disabled',
  'deferred',
] as const;
export type IntelligenceProviderHealthStatus = (typeof intelligenceProviderHealthStatuses)[number];

export const intelligenceSyncRunStates = [
  'requested',
  'fetching',
  'retry_wait',
  'stored',
  'parsing',
  'staging',
  'activating',
  'completed',
  'not_modified',
  'failed',
  'quarantined',
] as const;
export type IntelligenceSyncRunState = (typeof intelligenceSyncRunStates)[number];

export const intelligenceSyncRunTerminalStates = [
  'completed',
  'not_modified',
  'failed',
  'quarantined',
] as const;
export type IntelligenceSyncRunTerminalState = (typeof intelligenceSyncRunTerminalStates)[number];

export const intelligenceSyncRunStages = [
  'fetch',
  'store_snapshot',
  'validate',
  'parse',
  'stage_generation',
  'activate_generation',
  'finalize',
] as const;
export type IntelligenceSyncRunStage = (typeof intelligenceSyncRunStages)[number];

export const intelligenceForbiddenSyncStages = [
  'match',
  'correlate',
  'enrich_findings',
  'score',
  'remediate',
] as const;

export const kevGenerationStates = [
  'staging',
  'complete',
  'active',
  'superseded',
  'abandoned',
] as const;
export type KevGenerationState = (typeof kevGenerationStates)[number];

export const knownRansomwareCampaignUseValues = ['known', 'unknown', 'other'] as const;
export type KnownRansomwareCampaignUse = (typeof knownRansomwareCampaignUseValues)[number];

export const intelligenceNotModifiedReasons = [
  'content_sha256_unchanged',
  'http_not_modified',
] as const;
export type IntelligenceNotModifiedReason = (typeof intelligenceNotModifiedReasons)[number];

export const INTELLIGENCE_VERSION_LABEL_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/;
export const INTELLIGENCE_VERSION_LABEL_MAX_LENGTH = 64;
export const INTELLIGENCE_CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
export const INTELLIGENCE_CORRELATION_ID_MAX_LENGTH = 128;
export const INTELLIGENCE_CATALOG_VERSION_MAX_LENGTH = 128;
export const INTELLIGENCE_CONTENT_TYPE_MAX_LENGTH = 128;
export const INTELLIGENCE_TEXT_FIELD_MAX_BYTES = 16_384;
export const INTELLIGENCE_CWE_MAX_COUNT = 16;
export const INTELLIGENCE_CWE_MAX_LENGTH = 32;
export const INTELLIGENCE_RAW_RANSOMWARE_MAX_LENGTH = 64;
export const INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH = 512;
export const INTELLIGENCE_DEDUPE_KEY_MAX_LENGTH = 256;
export const INTELLIGENCE_SCHEDULE_WINDOW_MAX_LENGTH = 64;
export const INTELLIGENCE_REQUEST_TOKEN_MAX_LENGTH = 128;
export const INTELLIGENCE_PARSER_RESULT_MAX_SERIALIZED_BYTES = 16_777_216;
export const INTELLIGENCE_ACTIVE_ENTRY_LIST_DEFAULT_LIMIT = 20;
export const INTELLIGENCE_ACTIVE_ENTRY_LIST_MIN_LIMIT = 1;
export const INTELLIGENCE_ACTIVE_ENTRY_LIST_MAX_LIMIT = 100;

export const INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS = [
  'application/json',
  'application/json; charset=utf-8',
] as const;
export type IntelligenceSafeContentTypeLabel =
  (typeof INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS)[number];

export const CANONICAL_CVE_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,19}$/;
export const CANONICAL_CWE_PATTERN = /^CWE-[0-9]{1,8}$/;
export const CALENDAR_DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
export const UTC_INSTANT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

export const INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE = 'intelligence.sync.requested.v1' as const;
export const INTELLIGENCE_SYNC_JOB_TYPE = 'intelligence.sync' as const;
export const INTELLIGENCE_OUTBOX_PAYLOAD_SCHEMA_VERSION = 1;
export const INTELLIGENCE_AUDIT_PAYLOAD_SCHEMA_VERSION = 1;

export const INTELLIGENCE_AUDIT_SUBJECT_TYPE = 'intelligence_sync_run' as const;
export const INTELLIGENCE_SNAPSHOT_AUDIT_SUBJECT_TYPE = 'intelligence_snapshot' as const;
export const INTELLIGENCE_GENERATION_AUDIT_SUBJECT_TYPE = 'intelligence_generation' as const;
export const INTELLIGENCE_PROVIDER_AUDIT_SUBJECT_TYPE = 'intelligence_provider' as const;
export const INTELLIGENCE_SOURCE_AUDIT_SUBJECT_TYPE = 'intelligence_source' as const;

export const INTELLIGENCE_PROVIDERS_PATH = '/intelligence/providers' as const;
export const INTELLIGENCE_PROVIDER_STATUS_PATH =
  '/intelligence/providers/:provider/status' as const;
export const INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL = 'private, no-store' as const;

export const INTELLIGENCE_SNAPSHOT_OBJECT_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~/-]{0,511}$/;
