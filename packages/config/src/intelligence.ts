import { z } from 'zod';

import { parseBoolean, parseInteger, readRequired } from './read-env.js';
import { sbomVersionLabelPattern } from './sbom.js';

/**
 * Session 9 Batch 2C typed vulnerability-intelligence limits. Session 9 is
 * KEV-first. These values are PatchPilot operational defaults and safety
 * margins from one complete KEV snapshot measured on 2026-08-31, not CISA
 * service-level guarantees. Loading this module does not contact providers.
 *
 * OSV runtime synchronization does not ship in Session 9.
 * `INTELLIGENCE_OSV_ENABLED=true` is rejected in every deployment environment.
 * Observed OSV archive size is documented elsewhere and is not encoded here.
 */

export const INTELLIGENCE_KEV_ORIGIN = 'https://www.cisa.gov';
export const INTELLIGENCE_KEV_HOSTNAME = 'www.cisa.gov';
export const INTELLIGENCE_KEV_PATH =
  '/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const INTELLIGENCE_HTTP_REDIRECT_MAX = 0;
export const INTELLIGENCE_OSV_RUNTIME_STATUS = 'deferred' as const;

export const INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR =
  'INTELLIGENCE_OSV_ENABLED must be false. Session 9 does not ship OSV runtime synchronization.';

export const INTELLIGENCE_VERSION_LABEL_MAX_LENGTH = 64;
export const intelligenceVersionLabelPattern = sbomVersionLabelPattern;

export const INTELLIGENCE_KEV_ENABLED_DEFAULT = true;
export const INTELLIGENCE_OSV_ENABLED_DEFAULT = false;

export const INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_DEFAULT = 86_400;
export const INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MIN = 3_600;
export const INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MAX = 604_800;

export const INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT = 259_200;
export const INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MIN = 7_200;
export const INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MAX = 1_209_600;

export const INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_DEFAULT = 5_000;
export const INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MIN = 250;
export const INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MAX = 15_000;

export const INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_DEFAULT = 60_000;
export const INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MIN = 5_000;
export const INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MAX = 180_000;

export const INTELLIGENCE_HTTP_RETRY_COUNT_DEFAULT = 3;
export const INTELLIGENCE_HTTP_RETRY_COUNT_MIN = 0;
export const INTELLIGENCE_HTTP_RETRY_COUNT_MAX = 5;

export const INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_DEFAULT = 1_000;
export const INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MIN = 250;
export const INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MAX = 10_000;

export const INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_DEFAULT = 30_000;
export const INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MIN = 1_000;
export const INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MAX = 120_000;

export const INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_DEFAULT = 4_194_304;
export const INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MIN = 65_536;
export const INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MAX = 8_388_608;

export const INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_DEFAULT = 4_096;
export const INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MIN = 1;
export const INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX = 8_192;

export const INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_DEFAULT = 4_096;
export const INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MIN = 256;
export const INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MAX = 16_384;

export const INTELLIGENCE_KEV_MAX_CWE_COUNT_DEFAULT = 8;
export const INTELLIGENCE_KEV_MAX_CWE_COUNT_MIN = 1;
export const INTELLIGENCE_KEV_MAX_CWE_COUNT_MAX = 16;

export const INTELLIGENCE_KEV_JSON_MAX_DEPTH_DEFAULT = 8;
export const INTELLIGENCE_KEV_JSON_MAX_DEPTH_MIN = 4;
export const INTELLIGENCE_KEV_JSON_MAX_DEPTH_MAX = 16;

export const INTELLIGENCE_KEV_JSON_MAX_NODES_DEFAULT = 100_000;
export const INTELLIGENCE_KEV_JSON_MAX_NODES_MIN = 1_000;
export const INTELLIGENCE_KEV_JSON_MAX_NODES_MAX = 250_000;

export const INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_DEFAULT = 8_192;
export const INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MIN = 256;
export const INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MAX = 16_384;

export const INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_DEFAULT = 10_000;
export const INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MIN = 1_000;
export const INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MAX = 30_000;

export const INTELLIGENCE_PARSER_VERSION_DEFAULT = '0.1.0';
export const INTELLIGENCE_NORMALIZATION_VERSION_DEFAULT = '1';

export const INTELLIGENCE_KEV_JOB_LEASE_MS_DEFAULT = 600_000;
export const INTELLIGENCE_KEV_JOB_LEASE_MS_MIN = 120_000;
export const INTELLIGENCE_KEV_JOB_LEASE_MS_MAX = 1_800_000;

export const INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_DEFAULT = 30_000;
export const INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MIN = 1_000;
export const INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MAX = 120_000;

export const INTELLIGENCE_ORPHAN_GRACE_SECONDS_DEFAULT = 259_200;
export const INTELLIGENCE_ORPHAN_GRACE_SECONDS_MIN = 7_200;
export const INTELLIGENCE_ORPHAN_GRACE_SECONDS_MAX = 2_592_000;

export const INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_DEFAULT = 14;
export const INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MIN = 2;
export const INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MAX = 90;

export const INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_DEFAULT = 86_400;
export const INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MIN = 3_600;
export const INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MAX = 604_800;

export const INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_DEFAULT = 500;
export const INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MIN = 50;
export const INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX = 2_000;

export type IntelligenceCompiledKevSource = {
  origin: typeof INTELLIGENCE_KEV_ORIGIN;
  path: typeof INTELLIGENCE_KEV_PATH;
  href: string;
};

export const intelligenceConfigSchema = z.object({
  kevEnabled: z.boolean(),
  osvEnabled: z.boolean(),
  kevSource: z.object({
    origin: z.literal(INTELLIGENCE_KEV_ORIGIN),
    path: z.literal(INTELLIGENCE_KEV_PATH),
    href: z.string().url(),
  }),
  osvRuntime: z.literal(INTELLIGENCE_OSV_RUNTIME_STATUS),
  httpRedirectMax: z.literal(INTELLIGENCE_HTTP_REDIRECT_MAX),
  kevSyncIntervalSeconds: z.number().int().positive(),
  kevStaleThresholdSeconds: z.number().int().positive(),
  httpConnectTimeoutMs: z.number().int().positive(),
  httpTotalTimeoutMs: z.number().int().positive(),
  httpRetryCount: z.number().int().nonnegative(),
  httpBackoffFloorMs: z.number().int().positive(),
  httpBackoffCeilingMs: z.number().int().positive(),
  kevResponseMaxBytes: z.number().int().positive(),
  kevMaxVulnerabilityCount: z.number().int().positive(),
  kevMaxTextFieldBytes: z.number().int().positive(),
  kevMaxCweCount: z.number().int().positive(),
  kevJsonMaxDepth: z.number().int().positive(),
  kevJsonMaxNodes: z.number().int().positive(),
  kevJsonMaxStringBytes: z.number().int().positive(),
  kevParserTimeoutMs: z.number().int().positive(),
  parserVersion: z
    .string()
    .min(1)
    .max(INTELLIGENCE_VERSION_LABEL_MAX_LENGTH)
    .regex(intelligenceVersionLabelPattern, 'Parser version must be a safe database label.'),
  normalizationVersion: z
    .string()
    .min(1)
    .max(INTELLIGENCE_VERSION_LABEL_MAX_LENGTH)
    .regex(intelligenceVersionLabelPattern, 'Normalization version must be a safe database label.'),
  kevJobLeaseMs: z.number().int().positive(),
  objectStorageTimeoutMs: z.number().int().positive(),
  orphanGraceSeconds: z.number().int().positive(),
  snapshotRetentionCount: z.number().int().positive(),
  stagingGenerationMaxAgeSeconds: z.number().int().positive(),
  maxStagedRowsPerTransaction: z.number().int().positive(),
});

export type IntelligenceConfig = z.infer<typeof intelligenceConfigSchema>;

export type IntelligenceRelationshipIssue = {
  path: Array<string | number>;
  message: string;
};

export function compiledIntelligenceKevSource(): IntelligenceCompiledKevSource {
  const url = new URL(INTELLIGENCE_KEV_PATH, INTELLIGENCE_KEV_ORIGIN);
  return {
    origin: INTELLIGENCE_KEV_ORIGIN,
    path: INTELLIGENCE_KEV_PATH,
    href: url.href,
  };
}

export function intelligenceKevSourceIssues(
  source: IntelligenceCompiledKevSource,
): IntelligenceRelationshipIssue[] {
  const issues: IntelligenceRelationshipIssue[] = [];
  let parsed: URL;
  try {
    parsed = new URL(source.href);
  } catch {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must be a valid HTTPS URL.',
    });
    return issues;
  }

  if (parsed.protocol !== 'https:') {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must use HTTPS.',
    });
  }

  if (parsed.hostname !== INTELLIGENCE_KEV_HOSTNAME) {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL hostname must be www.cisa.gov.',
    });
  }

  if (parsed.pathname !== INTELLIGENCE_KEV_PATH) {
    issues.push({
      path: ['kevSource', 'path'],
      message: 'Compiled KEV source URL path must be the official JSON feed path.',
    });
  }

  if (parsed.username !== '' || parsed.password !== '') {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must not include credentials or userinfo.',
    });
  }

  if (parsed.search !== '') {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must not include a query string.',
    });
  }

  if (parsed.hash !== '') {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must not include a fragment.',
    });
  }

  if (parsed.port !== '') {
    issues.push({
      path: ['kevSource', 'href'],
      message: 'Compiled KEV source URL must use the default HTTPS port.',
    });
  }

  if (source.origin !== INTELLIGENCE_KEV_ORIGIN || source.path !== INTELLIGENCE_KEV_PATH) {
    issues.push({
      path: ['kevSource'],
      message: 'Compiled KEV source identity must match the approved origin and path.',
    });
  }

  return issues;
}

/**
 * Worst-case HTTP retry wall-clock:
 * `(retryCount + 1) * totalTimeout + retryCount * backoffCeiling`.
 * Returns `undefined` when the product overflows JavaScript safe integers.
 */
export function intelligenceHttpWorstCaseBudgetMs(
  intelligence: IntelligenceConfig,
): number | undefined {
  const attemptCount = checkedIntegerAdd(intelligence.httpRetryCount, 1);
  if (attemptCount === undefined) {
    return undefined;
  }

  const timeoutBudget = checkedIntegerMultiply(attemptCount, intelligence.httpTotalTimeoutMs);
  const backoffBudget = checkedIntegerMultiply(
    intelligence.httpRetryCount,
    intelligence.httpBackoffCeilingMs,
  );
  if (timeoutBudget === undefined || backoffBudget === undefined) {
    return undefined;
  }

  return checkedIntegerAdd(timeoutBudget, backoffBudget);
}

export function intelligenceRelationshipIssues(
  intelligence: IntelligenceConfig,
): IntelligenceRelationshipIssue[] {
  const issues: IntelligenceRelationshipIssue[] = [];

  if (intelligence.osvEnabled) {
    issues.push({
      path: ['osvEnabled'],
      message: INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR,
    });
  }

  if (intelligence.httpConnectTimeoutMs >= intelligence.httpTotalTimeoutMs) {
    issues.push({
      path: ['httpConnectTimeoutMs'],
      message:
        'INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS must be strictly less than INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS.',
    });
  }

  if (intelligence.httpBackoffFloorMs > intelligence.httpBackoffCeilingMs) {
    issues.push({
      path: ['httpBackoffFloorMs'],
      message:
        'INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS must be less than or equal to INTELLIGENCE_HTTP_BACKOFF_CEILING_MS.',
    });
  }

  if (intelligence.kevStaleThresholdSeconds <= intelligence.kevSyncIntervalSeconds) {
    issues.push({
      path: ['kevStaleThresholdSeconds'],
      message:
        'INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS must be strictly greater than INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS.',
    });
  }

  if (intelligence.kevParserTimeoutMs >= intelligence.kevJobLeaseMs) {
    issues.push({
      path: ['kevParserTimeoutMs'],
      message:
        'INTELLIGENCE_KEV_PARSER_TIMEOUT_MS must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS.',
    });
  }

  if (intelligence.objectStorageTimeoutMs >= intelligence.kevJobLeaseMs) {
    issues.push({
      path: ['objectStorageTimeoutMs'],
      message:
        'INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS.',
    });
  }

  const orphanGraceMs = checkedIntegerMultiply(intelligence.orphanGraceSeconds, 1_000);
  if (orphanGraceMs === undefined || orphanGraceMs <= intelligence.kevJobLeaseMs) {
    issues.push({
      path: ['orphanGraceSeconds'],
      message:
        'INTELLIGENCE_ORPHAN_GRACE_SECONDS in milliseconds must be strictly greater than INTELLIGENCE_KEV_JOB_LEASE_MS.',
    });
  }

  const stagingGenerationMaxAgeMs = checkedIntegerMultiply(
    intelligence.stagingGenerationMaxAgeSeconds,
    1_000,
  );
  if (
    stagingGenerationMaxAgeMs === undefined ||
    stagingGenerationMaxAgeMs <= intelligence.kevJobLeaseMs
  ) {
    issues.push({
      path: ['stagingGenerationMaxAgeSeconds'],
      message:
        'INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS in milliseconds must be strictly greater than INTELLIGENCE_KEV_JOB_LEASE_MS.',
    });
  }

  if (intelligence.kevJsonMaxStringBytes < intelligence.kevMaxTextFieldBytes) {
    issues.push({
      path: ['kevJsonMaxStringBytes'],
      message:
        'INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES must be greater than or equal to INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES.',
    });
  }

  const httpBudget = intelligenceHttpWorstCaseBudgetMs(intelligence);
  if (httpBudget === undefined) {
    issues.push({
      path: ['httpRetryCount'],
      message: 'HTTP worst-case retry budget overflows JavaScript safe integers.',
    });
  } else {
    if (httpBudget >= intelligence.kevJobLeaseMs) {
      issues.push({
        path: ['httpRetryCount'],
        message:
          'HTTP worst-case retry budget must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS.',
      });
    }

    const parserAndStorage = checkedIntegerAdd(
      intelligence.kevParserTimeoutMs,
      intelligence.objectStorageTimeoutMs,
    );
    const fullBudget =
      parserAndStorage === undefined ? undefined : checkedIntegerAdd(httpBudget, parserAndStorage);
    if (fullBudget === undefined) {
      issues.push({
        path: ['kevJobLeaseMs'],
        message: 'HTTP worst-case retry budget overflows JavaScript safe integers.',
      });
    } else if (fullBudget >= intelligence.kevJobLeaseMs) {
      issues.push({
        path: ['kevJobLeaseMs'],
        message:
          'HTTP worst-case retry budget plus parser timeout and object-storage timeout must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS.',
      });
    }
  }

  if (intelligence.httpRedirectMax !== INTELLIGENCE_HTTP_REDIRECT_MAX) {
    issues.push({
      path: ['httpRedirectMax'],
      message: 'Intelligence HTTP redirects are fixed at zero and cannot be enabled.',
    });
  }

  issues.push(...intelligenceKevSourceIssues(intelligence.kevSource));

  return issues;
}

export function intelligenceDefaultEnvironmentVariables(): Record<string, string> {
  return {
    INTELLIGENCE_KEV_ENABLED: String(INTELLIGENCE_KEV_ENABLED_DEFAULT),
    INTELLIGENCE_OSV_ENABLED: String(INTELLIGENCE_OSV_ENABLED_DEFAULT),
    INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS: String(INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_DEFAULT),
    INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS: String(
      INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
    ),
    INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS: String(INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_DEFAULT),
    INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS: String(INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_DEFAULT),
    INTELLIGENCE_HTTP_RETRY_COUNT: String(INTELLIGENCE_HTTP_RETRY_COUNT_DEFAULT),
    INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS: String(INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_DEFAULT),
    INTELLIGENCE_HTTP_BACKOFF_CEILING_MS: String(INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_DEFAULT),
    INTELLIGENCE_KEV_RESPONSE_MAX_BYTES: String(INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_DEFAULT),
    INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT: String(
      INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_DEFAULT,
    ),
    INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES: String(INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_DEFAULT),
    INTELLIGENCE_KEV_MAX_CWE_COUNT: String(INTELLIGENCE_KEV_MAX_CWE_COUNT_DEFAULT),
    INTELLIGENCE_KEV_JSON_MAX_DEPTH: String(INTELLIGENCE_KEV_JSON_MAX_DEPTH_DEFAULT),
    INTELLIGENCE_KEV_JSON_MAX_NODES: String(INTELLIGENCE_KEV_JSON_MAX_NODES_DEFAULT),
    INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES: String(INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_DEFAULT),
    INTELLIGENCE_KEV_PARSER_TIMEOUT_MS: String(INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_DEFAULT),
    INTELLIGENCE_PARSER_VERSION: INTELLIGENCE_PARSER_VERSION_DEFAULT,
    INTELLIGENCE_NORMALIZATION_VERSION: INTELLIGENCE_NORMALIZATION_VERSION_DEFAULT,
    INTELLIGENCE_KEV_JOB_LEASE_MS: String(INTELLIGENCE_KEV_JOB_LEASE_MS_DEFAULT),
    INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS: String(INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_DEFAULT),
    INTELLIGENCE_ORPHAN_GRACE_SECONDS: String(INTELLIGENCE_ORPHAN_GRACE_SECONDS_DEFAULT),
    INTELLIGENCE_SNAPSHOT_RETENTION_COUNT: String(INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_DEFAULT),
    INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS: String(
      INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_DEFAULT,
    ),
    INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION: String(
      INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_DEFAULT,
    ),
  };
}

export function loadIntelligenceConfigFrom(
  env: Readonly<Record<string, string | undefined>>,
): IntelligenceConfig {
  return {
    kevEnabled: parseBoolean(
      readRequired(env, 'INTELLIGENCE_KEV_ENABLED'),
      'INTELLIGENCE_KEV_ENABLED',
    ),
    osvEnabled: parseBoolean(
      readRequired(env, 'INTELLIGENCE_OSV_ENABLED'),
      'INTELLIGENCE_OSV_ENABLED',
    ),
    kevSource: compiledIntelligenceKevSource(),
    osvRuntime: INTELLIGENCE_OSV_RUNTIME_STATUS,
    httpRedirectMax: INTELLIGENCE_HTTP_REDIRECT_MAX,
    kevSyncIntervalSeconds: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS'),
      'INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS',
    ),
    kevStaleThresholdSeconds: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS'),
      'INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS',
    ),
    httpConnectTimeoutMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'),
      'INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS',
    ),
    httpTotalTimeoutMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'),
      'INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS',
    ),
    httpRetryCount: parseInteger(
      readRequired(env, 'INTELLIGENCE_HTTP_RETRY_COUNT'),
      'INTELLIGENCE_HTTP_RETRY_COUNT',
    ),
    httpBackoffFloorMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS'),
      'INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS',
    ),
    httpBackoffCeilingMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_HTTP_BACKOFF_CEILING_MS'),
      'INTELLIGENCE_HTTP_BACKOFF_CEILING_MS',
    ),
    kevResponseMaxBytes: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_RESPONSE_MAX_BYTES'),
      'INTELLIGENCE_KEV_RESPONSE_MAX_BYTES',
    ),
    kevMaxVulnerabilityCount: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT'),
      'INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT',
    ),
    kevMaxTextFieldBytes: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES'),
      'INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES',
    ),
    kevMaxCweCount: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_MAX_CWE_COUNT'),
      'INTELLIGENCE_KEV_MAX_CWE_COUNT',
    ),
    kevJsonMaxDepth: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_JSON_MAX_DEPTH'),
      'INTELLIGENCE_KEV_JSON_MAX_DEPTH',
    ),
    kevJsonMaxNodes: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_JSON_MAX_NODES'),
      'INTELLIGENCE_KEV_JSON_MAX_NODES',
    ),
    kevJsonMaxStringBytes: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES'),
      'INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES',
    ),
    kevParserTimeoutMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_PARSER_TIMEOUT_MS'),
      'INTELLIGENCE_KEV_PARSER_TIMEOUT_MS',
    ),
    parserVersion: readRequired(env, 'INTELLIGENCE_PARSER_VERSION'),
    normalizationVersion: readRequired(env, 'INTELLIGENCE_NORMALIZATION_VERSION'),
    kevJobLeaseMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_KEV_JOB_LEASE_MS'),
      'INTELLIGENCE_KEV_JOB_LEASE_MS',
    ),
    objectStorageTimeoutMs: parseInteger(
      readRequired(env, 'INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS'),
      'INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS',
    ),
    orphanGraceSeconds: parseInteger(
      readRequired(env, 'INTELLIGENCE_ORPHAN_GRACE_SECONDS'),
      'INTELLIGENCE_ORPHAN_GRACE_SECONDS',
    ),
    snapshotRetentionCount: parseInteger(
      readRequired(env, 'INTELLIGENCE_SNAPSHOT_RETENTION_COUNT'),
      'INTELLIGENCE_SNAPSHOT_RETENTION_COUNT',
    ),
    stagingGenerationMaxAgeSeconds: parseInteger(
      readRequired(env, 'INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS'),
      'INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS',
    ),
    maxStagedRowsPerTransaction: parseInteger(
      readRequired(env, 'INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION'),
      'INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION',
    ),
  };
}

export function refineIntelligenceNumericBounds(
  intelligence: IntelligenceConfig,
  addIssue: (issue: IntelligenceRelationshipIssue) => void,
): void {
  bound(
    intelligence.kevSyncIntervalSeconds,
    'kevSyncIntervalSeconds',
    INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MIN,
    INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MAX,
    addIssue,
  );
  bound(
    intelligence.kevStaleThresholdSeconds,
    'kevStaleThresholdSeconds',
    INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MIN,
    INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MAX,
    addIssue,
  );
  bound(
    intelligence.httpConnectTimeoutMs,
    'httpConnectTimeoutMs',
    INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MIN,
    INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.httpTotalTimeoutMs,
    'httpTotalTimeoutMs',
    INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MIN,
    INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.httpRetryCount,
    'httpRetryCount',
    INTELLIGENCE_HTTP_RETRY_COUNT_MIN,
    INTELLIGENCE_HTTP_RETRY_COUNT_MAX,
    addIssue,
  );
  bound(
    intelligence.httpBackoffFloorMs,
    'httpBackoffFloorMs',
    INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MIN,
    INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.httpBackoffCeilingMs,
    'httpBackoffCeilingMs',
    INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MIN,
    INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.kevResponseMaxBytes,
    'kevResponseMaxBytes',
    INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MIN,
    INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MAX,
    addIssue,
  );
  bound(
    intelligence.kevMaxVulnerabilityCount,
    'kevMaxVulnerabilityCount',
    INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MIN,
    INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX,
    addIssue,
  );
  bound(
    intelligence.kevMaxTextFieldBytes,
    'kevMaxTextFieldBytes',
    INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MIN,
    INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MAX,
    addIssue,
  );
  bound(
    intelligence.kevMaxCweCount,
    'kevMaxCweCount',
    INTELLIGENCE_KEV_MAX_CWE_COUNT_MIN,
    INTELLIGENCE_KEV_MAX_CWE_COUNT_MAX,
    addIssue,
  );
  bound(
    intelligence.kevJsonMaxDepth,
    'kevJsonMaxDepth',
    INTELLIGENCE_KEV_JSON_MAX_DEPTH_MIN,
    INTELLIGENCE_KEV_JSON_MAX_DEPTH_MAX,
    addIssue,
  );
  bound(
    intelligence.kevJsonMaxNodes,
    'kevJsonMaxNodes',
    INTELLIGENCE_KEV_JSON_MAX_NODES_MIN,
    INTELLIGENCE_KEV_JSON_MAX_NODES_MAX,
    addIssue,
  );
  bound(
    intelligence.kevJsonMaxStringBytes,
    'kevJsonMaxStringBytes',
    INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MIN,
    INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MAX,
    addIssue,
  );
  bound(
    intelligence.kevParserTimeoutMs,
    'kevParserTimeoutMs',
    INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MIN,
    INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.kevJobLeaseMs,
    'kevJobLeaseMs',
    INTELLIGENCE_KEV_JOB_LEASE_MS_MIN,
    INTELLIGENCE_KEV_JOB_LEASE_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.objectStorageTimeoutMs,
    'objectStorageTimeoutMs',
    INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MIN,
    INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    intelligence.orphanGraceSeconds,
    'orphanGraceSeconds',
    INTELLIGENCE_ORPHAN_GRACE_SECONDS_MIN,
    INTELLIGENCE_ORPHAN_GRACE_SECONDS_MAX,
    addIssue,
  );
  bound(
    intelligence.snapshotRetentionCount,
    'snapshotRetentionCount',
    INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MIN,
    INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MAX,
    addIssue,
  );
  bound(
    intelligence.stagingGenerationMaxAgeSeconds,
    'stagingGenerationMaxAgeSeconds',
    INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MIN,
    INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MAX,
    addIssue,
  );
  bound(
    intelligence.maxStagedRowsPerTransaction,
    'maxStagedRowsPerTransaction',
    INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MIN,
    INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX,
    addIssue,
  );
}

function bound(
  value: number,
  key: string,
  min: number,
  max: number,
  addIssue: (issue: IntelligenceRelationshipIssue) => void,
): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    addIssue({
      path: [key],
      message: `${key} must be between ${min} and ${max}.`,
    });
  }
}

function checkedIntegerAdd(left: number, right: number): number | undefined {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right)) {
    return undefined;
  }

  const sum = left + right;
  if (!Number.isSafeInteger(sum)) {
    return undefined;
  }

  return sum;
}

function checkedIntegerMultiply(left: number, right: number): number | undefined {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right)) {
    return undefined;
  }

  const product = left * right;
  if (!Number.isSafeInteger(product)) {
    return undefined;
  }

  return product;
}
