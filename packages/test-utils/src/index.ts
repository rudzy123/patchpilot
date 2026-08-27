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
    PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE: 'true',
  });
}

export function createFoundationProductionTestEnv(): Readonly<Record<string, string>> {
  return Object.freeze({
    ...createFoundationTestEnv(),
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'false',
    LOG_PRETTY: 'false',
    DATABASE_URL: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
    REDIS_URL: 'redis://:operator-redis-secret@redis.internal:6379',
    OBJECT_STORAGE_ENDPOINT: 'https://objects.internal:9000',
    OBJECT_STORAGE_ACCESS_KEY: 'operator-supplied-access-key',
    OBJECT_STORAGE_SECRET_KEY: 'operator-supplied-secret-key-value',
    OBJECT_STORAGE_BUCKET: 'patchpilot',
    OBJECT_STORAGE_USE_SSL: 'true',
    NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'production',
  });
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
