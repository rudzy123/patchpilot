const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const ALLOWED_DATABASE_NAME = /^patchpilot(?:_[a-z0-9]+)?$/;
const DESTRUCTIVE_CONFIRMATION = 'PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE';

export type DatabaseUrlSafety = {
  host: string;
  databaseName: string;
};

export class DatabaseCommandSafetyError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'DatabaseCommandSafetyError';
  }
}

export function inspectDatabaseUrl(databaseUrl: string): DatabaseUrlSafety {
  let parsed: URL;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new DatabaseCommandSafetyError('DATABASE_URL is not a valid URL.');
  }

  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    throw new DatabaseCommandSafetyError('DATABASE_URL must use the postgresql scheme.');
  }

  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (databaseName.length === 0) {
    throw new DatabaseCommandSafetyError('DATABASE_URL must include a database name.');
  }

  return {
    host: parsed.hostname,
    databaseName,
  };
}

export function redactDatabaseUrl(databaseUrl: string): string {
  try {
    const parsed = new URL(databaseUrl);
    parsed.password = parsed.password.length > 0 ? 'REDACTED' : '';
    return `${parsed.protocol}//${parsed.username}:${parsed.password}@${parsed.host}/<redacted-database>`;
  } catch {
    return '<invalid-database-url>';
  }
}

export function assertDevelopmentSeedAllowed(
  env: Readonly<Record<string, string | undefined>>,
): void {
  if (
    env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] === 'production' ||
    env['NODE_ENV'] === 'production'
  ) {
    throw new DatabaseCommandSafetyError(
      'Development seed is disabled when PATCHPILOT_DEPLOYMENT_ENVIRONMENT or NODE_ENV is production. NODE_ENV alone is never a safety grant.',
    );
  }
}

export function assertDestructiveDatabaseCommandAllowed(
  env: Readonly<Record<string, string | undefined>>,
  databaseUrl: string,
): DatabaseUrlSafety {
  if (
    env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] === 'production' ||
    env['NODE_ENV'] === 'production'
  ) {
    throw new DatabaseCommandSafetyError(
      'Refusing a destructive database command when PATCHPILOT_DEPLOYMENT_ENVIRONMENT or NODE_ENV is production. NODE_ENV alone is never a safety grant.',
    );
  }

  const inspected = inspectDatabaseUrl(databaseUrl);

  if (!LOOPBACK_HOSTS.has(inspected.host)) {
    throw new DatabaseCommandSafetyError(
      'Destructive database commands require a loopback host (127.0.0.1, localhost, or ::1).',
    );
  }

  if (!ALLOWED_DATABASE_NAME.test(inspected.databaseName)) {
    throw new DatabaseCommandSafetyError(
      'Destructive database commands require a database name matching patchpilot or patchpilot_<label>.',
    );
  }

  if (env[DESTRUCTIVE_CONFIRMATION] !== 'true') {
    throw new DatabaseCommandSafetyError(
      `Set ${DESTRUCTIVE_CONFIRMATION}=true to confirm a destructive database command against an allowed development or test database.`,
    );
  }

  return inspected;
}

export function assertEphemeralTestDatabaseName(databaseName: string): void {
  if (
    !databaseName.startsWith('patchpilot_it_') &&
    !databaseName.startsWith('patchpilot_migrate_')
  ) {
    throw new DatabaseCommandSafetyError(
      'Ephemeral test databases must be named patchpilot_it_* or patchpilot_migrate_*.',
    );
  }
}

export function cloneProcessEnv(
  overrides: Readonly<Record<string, string | undefined>> = {},
): NodeJS.ProcessEnv {
  return { ...process.env, ...overrides };
}
