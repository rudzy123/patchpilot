import { DatabaseCommandSafetyError, inspectDatabaseUrl } from './database-safety.js';

const SERVER_ENV = 'PATCHPILOT_INTEGRATION_SERVER_URL';
const DATABASE_ENV = 'PATCHPILOT_INTEGRATION_DATABASE_URL';
const STATE_ENV = 'PATCHPILOT_INTEGRATION_DATABASE_STATE_FILE';

export function assertIntegrationTestProcessAllowed(): void {
  if (
    process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] === 'production' ||
    process.env['NODE_ENV'] === 'production'
  ) {
    throw new DatabaseCommandSafetyError(
      'Integration test database lifecycle is disabled when PATCHPILOT_DEPLOYMENT_ENVIRONMENT or NODE_ENV is production.',
    );
  }
}

function readNonEmpty(key: string): string | undefined {
  const value = process.env[key];
  if (value === undefined || value.length === 0) {
    return undefined;
  }

  return value;
}

export function rememberIntegrationServerTemplate(fallbackUrl: string | undefined): void {
  assertIntegrationTestProcessAllowed();
  if (readNonEmpty(SERVER_ENV) !== undefined) {
    return;
  }

  const template = readNonEmpty('DATABASE_URL') ?? fallbackUrl;
  if (template !== undefined) {
    process.env[SERVER_ENV] = template;
  }
}

export function readIntegrationServerDatabaseUrl(fallbackUrl: string | undefined): string {
  assertIntegrationTestProcessAllowed();
  const candidate = readNonEmpty(SERVER_ENV) ?? readNonEmpty('DATABASE_URL') ?? fallbackUrl;
  if (candidate === undefined) {
    throw new DatabaseCommandSafetyError('Test DATABASE_URL is missing.');
  }

  return candidate;
}

export function setIntegrationDatabaseStateFile(stateFile: string): void {
  process.env[STATE_ENV] = stateFile;
}

export function readIntegrationDatabaseStateFile(): string {
  const stateFile = readNonEmpty(STATE_ENV);
  if (stateFile === undefined) {
    throw new DatabaseCommandSafetyError(
      'Integration database cleanup could not find its state file.',
    );
  }

  return stateFile;
}

export function publishDisposableIntegrationDatabase(databaseUrl: string): void {
  assertIntegrationTestProcessAllowed();
  const databaseName = disposableIntegrationDatabaseName(databaseUrl);
  if (databaseName === 'patchpilot' || !databaseName.startsWith('patchpilot_it_')) {
    throw new DatabaseCommandSafetyError(
      'Refusing to publish the persistent development database to integration tests.',
    );
  }

  process.env[DATABASE_ENV] = databaseUrl;
  process.env['DATABASE_URL'] = databaseUrl;
}

export function readDisposableIntegrationDatabaseUrl(): string {
  assertIntegrationTestProcessAllowed();
  const databaseUrl = readNonEmpty(DATABASE_ENV);
  if (databaseUrl === undefined) {
    throw new DatabaseCommandSafetyError(
      'PATCHPILOT_INTEGRATION_DATABASE_URL is missing. Integration suites require a disposable database and do not fall back to the persistent development database.',
    );
  }

  disposableIntegrationDatabaseName(databaseUrl);
  return databaseUrl;
}

function disposableIntegrationDatabaseName(databaseUrl: string): string {
  let databaseName: string;
  try {
    databaseName = inspectDatabaseUrl(databaseUrl).databaseName;
  } catch (error) {
    if (error instanceof DatabaseCommandSafetyError) {
      throw new DatabaseCommandSafetyError(
        'PATCHPILOT_INTEGRATION_DATABASE_URL is not a valid database URL.',
      );
    }

    throw error;
  }

  if (
    databaseName === 'patchpilot' ||
    databaseName === 'postgres' ||
    !databaseName.startsWith('patchpilot_it_')
  ) {
    throw new DatabaseCommandSafetyError(
      'Integration suites refuse the persistent development database. The disposable database name must start with patchpilot_it_.',
    );
  }

  return databaseName;
}
