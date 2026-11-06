/**
 * Deterministic data for the one Playwright release smoke.
 * The browser does not upload an SBOM. This fixture prepares one synthetic
 * organization, asset, approved advisory, product-match evidence row, and open
 * Finding through the existing controlled-creation helper. Production startup
 * does not call it.
 */

import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createRequire } from 'node:module';

import { PrismaClient } from '@prisma/client';

import { loadBuiltinPriorityPolicyPublication } from './builtin-priority-policy-publication-command-main.js';
import { publishBuiltinPriorityPolicy } from './builtin-priority-policy-publication.js';
import { insertOpenFindingForConstraintTest } from './finding-constraint-fixture.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createAsset, createOrg } from './sbom-test-fixture.js';

const require = createRequire(new URL('../../auth/package.json', import.meta.url));
const argon2 = require('argon2') as {
  hash: (
    password: string,
    options: {
      type: number;
      memoryCost: number;
      timeCost: number;
      parallelism: number;
    },
  ) => Promise<string>;
  argon2id: number;
};

const STATE_PATH = fileURLToPath(new URL('../../../apps/web/e2e/.state.json', import.meta.url));

const EMAIL = 'release-smoke-owner@synthetic.patchpilot.test';
const PASSWORD = 'release-smoke-password';
const ASSET_NAME = 'Release smoke asset';

type ReleaseSmokeState = {
  databaseName: string;
  databaseUrl: string;
  email: string;
  password: string;
  assetId: string;
  assetName: string;
  findingId: string;
  vulnerabilityPublicId: string;
  organizationName: string;
};

const command = process.argv[2];
if (command === 'prepare') {
  await prepare();
} else if (command === 'drop') {
  await drop();
} else {
  process.stderr.write('release smoke fixture command must be prepare or drop\n');
  process.exit(1);
}

async function prepare(): Promise<void> {
  const ephemeral = await createEphemeralDatabase('it');
  await ephemeral.admin.$disconnect();
  writeState({
    databaseName: ephemeral.databaseName,
    databaseUrl: ephemeral.databaseUrl,
    email: EMAIL,
    password: PASSWORD,
    assetId: '',
    assetName: ASSET_NAME,
    findingId: '',
    vulnerabilityPublicId: '',
    organizationName: '',
  });
  const client = new PrismaClient({
    datasources: { db: { url: ephemeral.databaseUrl } },
  });
  try {
    await deployMigrations(ephemeral.databaseUrl);
    const seeded = await seed(client);
    writeState({
      databaseName: ephemeral.databaseName,
      databaseUrl: ephemeral.databaseUrl,
      ...seeded,
    });
  } finally {
    await client.$disconnect();
  }
}

async function seed(
  client: PrismaClient,
): Promise<Omit<ReleaseSmokeState, 'databaseName' | 'databaseUrl'>> {
  const organization = await createOrg(client, `release-smoke-${randomUUID().slice(0, 8)}`);
  const asset = await createAsset(client, organization.id, ASSET_NAME);
  const passwordHash = await argon2.hash(PASSWORD, {
    type: argon2.argon2id,
    memoryCost: 8192,
    timeCost: 1,
    parallelism: 1,
  });
  const user = await client.user.create({
    data: {
      email: EMAIL,
      displayName: 'Release smoke owner',
      localCredential: {
        create: {
          passwordHash,
          algorithm: 'argon2id',
          passwordRevision: 1,
        },
      },
    },
  });
  await client.membership.create({
    data: {
      organizationId: organization.id,
      userId: user.id,
      role: 'owner',
      joinedAt: new Date(),
    },
  });
  const vulnerabilityPublicId = `SMOKE-${randomUUID().replaceAll('-', '').slice(0, 16)}`;
  const vulnerability = await client.vulnerability.create({
    data: { osvId: vulnerabilityPublicId },
  });
  const component = await client.component.create({
    data: {
      organizationId: organization.id,
      identityKey: `npm|release-smoke-${randomUUID()}`,
      ecosystem: 'npm',
      name: 'reviewed-npm-widget',
    },
  });
  const created = await insertOpenFindingForConstraintTest(client, {
    organizationId: organization.id,
    assetId: asset.id,
    vulnerabilityId: vulnerability.id,
    componentId: component.id,
  });
  const publication = loadBuiltinPriorityPolicyPublication();
  const published = await publishBuiltinPriorityPolicy(client, {
    correlationId: randomUUID(),
    definition: publication.definition,
    canonicalJson: publication.canonicalJson,
    admittedPairs: publication.admittedPairs,
    engineVersion: publication.engineVersion,
  });
  if (published.outcome !== 'inserted' && published.outcome !== 'already_applied') {
    throw new Error(`release smoke policy publication ${published.outcome}`);
  }
  return {
    email: EMAIL,
    password: PASSWORD,
    assetId: asset.id,
    assetName: ASSET_NAME,
    findingId: created.finding.id,
    vulnerabilityPublicId,
    organizationName: organization.name,
  };
}

async function drop(): Promise<void> {
  const state = readState();
  if (state === null) {
    return;
  }
  const adminUrl = new URL(state.databaseUrl);
  adminUrl.pathname = '/postgres';
  const admin = new PrismaClient({
    datasources: { db: { url: adminUrl.toString() } },
  });
  await dropEphemeralDatabase(admin, state.databaseName);
  rmSync(STATE_PATH, { force: true });
}

function writeState(state: ReleaseSmokeState): void {
  mkdirSync(path.dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(state)}\n`, { encoding: 'utf8', mode: 0o600 });
}

function readState(): ReleaseSmokeState | null {
  try {
    return JSON.parse(readFileSync(STATE_PATH, 'utf8')) as ReleaseSmokeState;
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}
