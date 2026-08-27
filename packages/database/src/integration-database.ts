import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  assertDestructiveDatabaseCommandAllowed,
  assertEphemeralTestDatabaseName,
  cloneProcessEnv,
  inspectDatabaseUrl,
} from '@patchpilot/config';
import { PrismaClient } from '@prisma/client';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

const execFileAsync = promisify(execFile);
const databasePackageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const session3Migration = path.join(
  databasePackageRoot,
  'prisma/migrations/20260826120000_schema_foundation/migration.sql',
);

export function testDatabaseUrl(): string {
  const env = createFoundationTestEnv();
  const url = env['DATABASE_URL'];
  if (url === undefined) {
    throw new Error('Test DATABASE_URL is missing.');
  }

  return url;
}

export function withDatabaseName(databaseUrl: string, databaseName: string): string {
  const parsed = new URL(databaseUrl);
  parsed.pathname = `/${databaseName}`;
  return parsed.toString();
}

export async function createEphemeralDatabase(label: 'it' | 'migrate'): Promise<{
  databaseName: string;
  databaseUrl: string;
  admin: PrismaClient;
}> {
  const env = createFoundationTestEnv();
  const baseUrl = testDatabaseUrl();
  assertDestructiveDatabaseCommandAllowed(env, baseUrl);

  const databaseName = `patchpilot_${label}_${randomBytes(6).toString('hex')}`;
  assertEphemeralTestDatabaseName(databaseName);

  const admin = new PrismaClient({
    datasources: { db: { url: withDatabaseName(baseUrl, 'postgres') } },
  });

  await admin.$executeRawUnsafe(`CREATE DATABASE "${databaseName}"`);
  return {
    databaseName,
    databaseUrl: withDatabaseName(baseUrl, databaseName),
    admin,
  };
}

export async function dropEphemeralDatabase(
  admin: PrismaClient,
  databaseName: string,
): Promise<void> {
  assertEphemeralTestDatabaseName(databaseName);
  await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await admin.$disconnect();
}

export async function deployMigrations(databaseUrl: string): Promise<void> {
  inspectDatabaseUrl(databaseUrl);
  await execFileAsync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: databasePackageRoot,
    env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
  });
}

export async function applySession3Schema(databaseUrl: string): Promise<void> {
  const sql = await readFile(session3Migration, 'utf8');
  const client = new PrismaClient({
    datasources: { db: { url: databaseUrl } },
  });

  try {
    await client.$executeRawUnsafe(sql);
  } finally {
    await client.$disconnect();
  }

  await execFileAsync(
    'pnpm',
    ['exec', 'prisma', 'migrate', 'resolve', '--applied', '20260826120000_schema_foundation'],
    {
      cwd: databasePackageRoot,
      env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
    },
  );
}
