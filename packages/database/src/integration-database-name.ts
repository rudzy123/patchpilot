import { randomBytes } from 'node:crypto';

import { assertEphemeralTestDatabaseName, DatabaseCommandSafetyError } from '@patchpilot/config';

export const EPHEMERAL_DATABASE_LABELS = ['it', 'migrate'] as const;
export type EphemeralDatabaseLabel = (typeof EPHEMERAL_DATABASE_LABELS)[number];

export const INTEGRATION_PROCESS_SCOPES = ['api', 'worker'] as const;
export type IntegrationProcessScope = (typeof INTEGRATION_PROCESS_SCOPES)[number];

const SCOPE_PATTERN = /^[a-z][a-z0-9]{0,11}$/;
const STALE_DATABASE_NAME =
  /^patchpilot_(?:it|migrate)_(?:[a-z][a-z0-9]{0,11}_)?(\d{10})_[a-f0-9]{12}$/;
const RANDOM_HEX_BYTES = 6;

export const STALE_EPHEMERAL_DATABASE_AGE_MS = 2 * 60 * 60 * 1000;
export const MAX_STALE_EPHEMERAL_DATABASES_PER_RUN = 8;

export function createEphemeralDatabaseName(
  label: EphemeralDatabaseLabel,
  options?: { scope?: string; nowMs?: number },
): string {
  const scope = options?.scope;
  if (scope !== undefined && !SCOPE_PATTERN.test(scope)) {
    throw new DatabaseCommandSafetyError('Ephemeral database scope is not allowed.');
  }

  const nowMs = options?.nowMs ?? Date.now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new DatabaseCommandSafetyError('Ephemeral database timestamp is not allowed.');
  }

  const stamp = Math.floor(nowMs / 1000).toString(10);
  const random = randomBytes(RANDOM_HEX_BYTES).toString('hex');
  const scopePart = scope === undefined ? '' : `${scope}_`;
  const databaseName = `patchpilot_${label}_${scopePart}${stamp}_${random}`;
  assertEphemeralTestDatabaseName(databaseName);
  return databaseName;
}

export function ephemeralDatabaseAgeMs(databaseName: string, nowMs: number): number | undefined {
  const match = STALE_DATABASE_NAME.exec(databaseName);
  const stamp = match?.[1];
  if (stamp === undefined) {
    return undefined;
  }

  const createdMs = Number(stamp) * 1000;
  if (!Number.isSafeInteger(createdMs)) {
    return undefined;
  }

  return nowMs - createdMs;
}

export function selectStaleEphemeralDatabases(
  names: readonly string[],
  nowMs: number,
  limit = MAX_STALE_EPHEMERAL_DATABASES_PER_RUN,
): string[] {
  if (!Number.isSafeInteger(limit) || limit < 0) {
    throw new DatabaseCommandSafetyError('Stale database cleanup limit is not allowed.');
  }

  const ranked: Array<{ name: string; ageMs: number }> = [];
  for (const name of names) {
    const ageMs = ephemeralDatabaseAgeMs(name, nowMs);
    if (ageMs === undefined || ageMs < STALE_EPHEMERAL_DATABASE_AGE_MS) {
      continue;
    }

    assertEphemeralTestDatabaseName(name);
    ranked.push({ name, ageMs });
  }

  ranked.sort((left, right) => right.ageMs - left.ageMs);
  return ranked.slice(0, limit).map((entry) => entry.name);
}

export function quoteEphemeralDatabaseIdentifier(databaseName: string): string {
  assertEphemeralTestDatabaseName(databaseName);
  return `"${databaseName}"`;
}

export function assertIntegrationProcessScope(scope: string): IntegrationProcessScope {
  if (scope === 'api' || scope === 'worker') {
    return scope;
  }

  throw new DatabaseCommandSafetyError('Integration database process scope is not allowed.');
}

export function assertDatabaseOwnedByScope(
  scope: IntegrationProcessScope,
  databaseName: string,
): void {
  assertEphemeralTestDatabaseName(databaseName);
  const prefix = `patchpilot_it_${scope}_`;
  if (!databaseName.startsWith(prefix)) {
    throw new DatabaseCommandSafetyError(
      'Refusing to drop a database that this integration process does not own.',
    );
  }
}
