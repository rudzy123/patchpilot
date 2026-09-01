import { createServer } from 'node:net';

export type FrozenClock = {
  now: () => Date;
  nowIso: () => string;
};

export function createFrozenClock(isoUtc: string): FrozenClock {
  const date = new Date(isoUtc);
  if (Number.isNaN(date.getTime())) {
    throw new Error('createFrozenClock requires a valid UTC ISO 8601 timestamp.');
  }

  return {
    now: () => new Date(date.getTime()),
    nowIso: () => date.toISOString(),
  };
}

function foundationSbomEnv(): Record<string, string> {
  return {
    SBOM_UPLOAD_MAX_BYTES: '20971520',
    SBOM_JSON_MAX_DEPTH: '32',
    SBOM_JSON_MAX_NODES: '200000',
    SBOM_JSON_MAX_STRING_BYTES: '65536',
    SBOM_MAX_COMPONENTS: '10000',
    SBOM_MAX_DEPENDENCY_EDGES: '50000',
    SBOM_MAX_BOM_REF_BYTES: '2048',
    SBOM_MAX_PURL_BYTES: '2048',
    SBOM_MAX_COMPONENT_NAME_CHARS: '512',
    SBOM_MAX_VERSION_CHARS: '256',
    SBOM_MAX_METADATA_TOOLS: '64',
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT: '32',
    SBOM_MAX_PROPERTIES_PER_COMPONENT: '64',
    SBOM_PARSER_TIMEOUT_MS: '60000',
    SBOM_PROCESSING_LEASE_MS: '900000',
    SBOM_IDEMPOTENCY_TTL_SECONDS: '86400',
    SBOM_UPLOAD_RATE_LIMIT_MAX: '10',
    SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS: '900',
    OBJECT_STORAGE_OPERATION_TIMEOUT_MS: '30000',
    OBJECT_STORAGE_CONNECTION_TIMEOUT_MS: '3000',
    OBJECT_STORAGE_REGION: 'us-east-1',
    SBOM_ORPHAN_GRACE_SECONDS: '604800',
    SBOM_PARSER_VERSION: '0.1.0',
    SBOM_NORMALIZATION_VERSION: '1',
  };
}

function foundationIntelligenceEnv(): Record<string, string> {
  return {
    INTELLIGENCE_KEV_ENABLED: 'true',
    INTELLIGENCE_OSV_ENABLED: 'false',
    INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS: '86400',
    INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS: '259200',
    INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS: '5000',
    INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS: '60000',
    INTELLIGENCE_HTTP_RETRY_COUNT: '3',
    INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS: '1000',
    INTELLIGENCE_HTTP_BACKOFF_CEILING_MS: '30000',
    INTELLIGENCE_KEV_RESPONSE_MAX_BYTES: '4194304',
    INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT: '4096',
    INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES: '4096',
    INTELLIGENCE_KEV_MAX_CWE_COUNT: '8',
    INTELLIGENCE_KEV_JSON_MAX_DEPTH: '8',
    INTELLIGENCE_KEV_JSON_MAX_NODES: '100000',
    INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES: '8192',
    INTELLIGENCE_KEV_PARSER_TIMEOUT_MS: '10000',
    INTELLIGENCE_PARSER_VERSION: '0.1.0',
    INTELLIGENCE_NORMALIZATION_VERSION: '1',
    INTELLIGENCE_KEV_JOB_LEASE_MS: '600000',
    INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS: '30000',
    INTELLIGENCE_ORPHAN_GRACE_SECONDS: '259200',
    INTELLIGENCE_SNAPSHOT_RETENTION_COUNT: '14',
    INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS: '86400',
    INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION: '500',
    INTELLIGENCE_SYNC_MAX_ATTEMPTS: '5',
    INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS: '30000',
    INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS: '300000',
    INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS: '60000',
    INTELLIGENCE_KEV_SCHEDULER_POLL_INTERVAL_MS: '30000',
    INTELLIGENCE_KEV_SCHEDULER_STARTUP_DELAY_MS: '5000',
    INTELLIGENCE_RETRY_RECONCILE_INTERVAL_MS: '15000',
    INTELLIGENCE_RETRY_RECONCILE_MIN_AGE_MS: '15000',
  };
}

export function createFoundationTestEnv(): Readonly<Record<string, string>> {
  return Object.freeze({
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'test',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'true',
    LOG_LEVEL: 'silent',
    LOG_PRETTY: 'false',
    API_HOST: '127.0.0.1',
    API_PORT: '3001',
    WEB_PORT: '3000',
    CORS_ALLOWED_ORIGINS: 'http://127.0.0.1:3000',
    DATABASE_URL:
      'postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot',
    REDIS_URL: 'redis://127.0.0.1:16379',
    OBJECT_STORAGE_ENDPOINT: 'http://127.0.0.1:19000',
    OBJECT_STORAGE_ACCESS_KEY: 'patchpilot-dev-access',
    OBJECT_STORAGE_SECRET_KEY: 'patchpilot-dev-secret-not-for-production',
    OBJECT_STORAGE_BUCKET: 'patchpilot-dev',
    OBJECT_STORAGE_USE_SSL: 'false',
    OTEL_ENABLED: 'false',
    READINESS_TIMEOUT_MS: '500',
    SHUTDOWN_TIMEOUT_MS: '1000',
    REQUEST_BODY_LIMIT_BYTES: '4096',
    REQUEST_ID_HEADER: 'x-request-id',
    CORRELATION_ID_HEADER: 'x-correlation-id',
    NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'test',
    NEXT_PUBLIC_API_BASE_URL: 'http://127.0.0.1:3001',
    PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE: 'true',
    ...foundationSbomEnv(),
    ...foundationIntelligenceEnv(),
    ...foundationAuthEnv('test'),
  });
}

export function createFoundationProductionTestEnv(): Readonly<Record<string, string>> {
  return Object.freeze({
    ...createFoundationTestEnv(),
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'false',
    LOG_PRETTY: 'false',
    CORS_ALLOWED_ORIGINS: 'https://patchpilot.example',
    DATABASE_URL: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
    REDIS_URL: 'redis://:operator-redis-secret@redis.internal:6379',
    OBJECT_STORAGE_ENDPOINT: 'https://objects.internal:9000',
    OBJECT_STORAGE_ACCESS_KEY: 'operator-supplied-access-key',
    OBJECT_STORAGE_SECRET_KEY: 'operator-supplied-secret-key-value',
    OBJECT_STORAGE_BUCKET: 'patchpilot',
    OBJECT_STORAGE_USE_SSL: 'true',
    NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'production',
    NEXT_PUBLIC_API_BASE_URL: 'https://api.patchpilot.example',
    ...foundationAuthEnv('production'),
  });
}

function foundationAuthEnv(mode: 'test' | 'production'): Record<string, string> {
  const shared = {
    AUTH_SESSION_ABSOLUTE_TTL_SECONDS: '604800',
    AUTH_SESSION_IDLE_TTL_SECONDS: '43200',
    AUTH_SESSION_LAST_SEEN_MIN_INTERVAL_SECONDS: '60',
    AUTH_CSRF_HEADER_NAME: 'x-csrf-token',
    AUTH_PASSWORD_MIN_LENGTH: '12',
    AUTH_PASSWORD_MAX_BYTES: '128',
    AUTH_LOGIN_RATE_LIMIT_IP_MAX: '10',
    AUTH_LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS: '900',
    AUTH_LOGIN_RATE_LIMIT_ACCOUNT_MAX: '5',
    AUTH_LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS: '900',
    AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS: '200',
  };

  if (mode === 'production') {
    return {
      ...shared,
      AUTH_COOKIE_NAME: '__Host-patchpilot.sid',
      AUTH_COOKIE_SECURE: 'true',
      AUTH_ARGON2_MEMORY_KIB: '19456',
      AUTH_ARGON2_TIME_COST: '2',
      AUTH_ARGON2_PARALLELISM: '1',
    };
  }

  return {
    ...shared,
    AUTH_COOKIE_NAME: 'patchpilot.sid',
    AUTH_COOKIE_SECURE: 'false',
    AUTH_ARGON2_MEMORY_KIB: '8192',
    AUTH_ARGON2_TIME_COST: '1',
    AUTH_ARGON2_PARALLELISM: '1',
  };
}

export function createSyntheticTenantPair(): {
  organizationA: { slug: string; displayName: string };
  organizationB: { slug: string; displayName: string };
  userA: { email: string; displayName: string };
  userB: { email: string; displayName: string };
  vulnerabilityIdentity: string;
} {
  return {
    organizationA: {
      slug: 'synthetic-org-a',
      displayName: 'Synthetic Organization A',
    },
    organizationB: {
      slug: 'synthetic-org-b',
      displayName: 'Synthetic Organization B',
    },
    userA: {
      email: 'owner-a@synthetic.patchpilot.test',
      displayName: 'Synthetic Owner A',
    },
    userB: {
      email: 'owner-b@synthetic.patchpilot.test',
      displayName: 'Synthetic Owner B',
    },
    vulnerabilityIdentity: 'PATCHPILOT-SYNTH-VULN-1',
  };
}

export async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close();
        reject(new Error('Failed to allocate an ephemeral port.'));
        return;
      }

      const port = address.port;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(port);
      });
    });
  });
}
