import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma } from '@prisma/client';
import { describe, expect, it, vi } from 'vitest';

import type { PrismaClientLike } from '../guards.js';
import { isUuid } from '../guards.js';
import {
  BuiltinPriorityPolicyImmutableConflictError,
  developmentSeedIds,
  ensurePublishedBuiltinPriorityPolicy,
  seedDevelopmentData,
  type BuiltinPriorityPolicySeedRow,
} from './development.js';

const DEV_ENV = { PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'development' };
const DISPLAY_NAME = 'PatchPilot built-in P1-P4 priority policy';
const VERSION_2_ID = '55555555-5555-4555-8555-555555555502';

const suppliedDefinition = {
  schemaVersion: 2,
  policyKey: 'patchpilot.builtin.v0',
  marker: 'version-2',
};

type StoredPolicy = BuiltinPriorityPolicySeedRow & {
  publishedAt?: Date | null;
};

type PolicyWhere = {
  id?: string;
  scope?: string;
  organizationId?: string | null;
  policyKey?: string;
  version?: number;
};

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortJson(entry));
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortJson(record[key]);
    }
    return sorted;
  }
  return value;
}

function reorder(value: Record<string, unknown>): Record<string, unknown> {
  const reordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).reverse()) {
    reordered[key] = value[key];
  }
  return reordered;
}

function policyRow(overrides: Partial<StoredPolicy> = {}): StoredPolicy {
  return {
    id: developmentSeedIds.builtinPriorityPolicyVersion2,
    organizationId: null,
    createdByMembershipId: null,
    scope: 'builtin',
    policyKey: 'patchpilot.builtin.v0',
    name: DISPLAY_NAME,
    version: 2,
    status: 'published',
    policySchemaVersion: 2,
    definition: suppliedDefinition,
    ...overrides,
  };
}

function matchesWhere(row: StoredPolicy, where: PolicyWhere): boolean {
  if (where.id !== undefined && row.id !== where.id) {
    return false;
  }
  if (where.scope !== undefined && row.scope !== where.scope) {
    return false;
  }
  if (where.organizationId !== undefined && row.organizationId !== where.organizationId) {
    return false;
  }
  if (where.policyKey !== undefined && row.policyKey !== where.policyKey) {
    return false;
  }
  if (where.version !== undefined && row.version !== where.version) {
    return false;
  }
  return true;
}

function materialize(data: {
  id?: string;
  organizationId?: string | null;
  createdByMembershipId?: string | null;
  scope: StoredPolicy['scope'];
  policyKey: string;
  name: string;
  version: number;
  status: StoredPolicy['status'];
  policySchemaVersion: number;
  definition: unknown;
  publishedAt?: Date | null;
}): StoredPolicy {
  return {
    id: data.id ?? 'missing-id',
    organizationId: data.organizationId ?? null,
    createdByMembershipId: data.createdByMembershipId ?? null,
    scope: data.scope,
    policyKey: data.policyKey,
    name: data.name,
    version: data.version,
    status: data.status,
    policySchemaVersion: data.policySchemaVersion,
    definition: data.definition,
    publishedAt: data.publishedAt ?? null,
  };
}

function createPolicyMemory() {
  const rows: StoredPolicy[] = [];
  const riskPolicy = {
    findFirst: vi.fn(async ({ where }: { where: PolicyWhere }) => {
      const matches = rows
        .filter((row) => matchesWhere(row, where))
        .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
      return matches[0] ?? null;
    }),
    findUnique: vi.fn(async ({ where }: { where: { id: string } }) => {
      return rows.find((row) => row.id === where.id) ?? null;
    }),
    create: vi.fn(async ({ data }: { data: Parameters<typeof materialize>[0] }) => {
      const row = materialize(data);
      rows.push(row);
      return row;
    }),
    update: vi.fn(() => {
      throw new Error('risk policy update is forbidden');
    }),
    delete: vi.fn(() => {
      throw new Error('risk policy delete is forbidden');
    }),
  };
  return { rows, riskPolicy };
}

function createSeedClient() {
  const policy = createPolicyMemory();
  const client = {
    user: { upsert: vi.fn(async () => ({})) },
    organization: { upsert: vi.fn(async () => ({})) },
    membership: { upsert: vi.fn(async () => ({ id: 'membership-a' })) },
    riskPolicy: policy.riskPolicy,
    vulnerability: { upsert: vi.fn(async () => ({})) },
    vulnerabilityAlias: { upsert: vi.fn(async () => ({})) },
    vulnerabilitySourceRecord: { upsert: vi.fn(async () => ({})) },
  };
  return {
    client: client as unknown as PrismaClientLike,
    rows: policy.rows,
    riskPolicy: policy.riskPolicy,
    vulnerability: client.vulnerability,
    user: client.user,
  };
}

function asClient(riskPolicy: object): PrismaClientLike {
  return { riskPolicy } as unknown as PrismaClientLike;
}

function uniqueConflict(): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
    code: 'P2002',
    clientVersion: '6.19.0',
    meta: { target: ['policy_key', 'version'] },
  });
}

function version1Placeholder(): StoredPolicy {
  return {
    id: developmentSeedIds.builtinRiskPolicy,
    organizationId: null,
    createdByMembershipId: null,
    scope: 'builtin',
    policyKey: 'patchpilot.builtin.v0',
    name: 'Synthetic built-in risk policy',
    version: 1,
    status: 'published',
    policySchemaVersion: 1,
    definition: {
      schemaVersion: 1,
      policyKey: 'patchpilot.builtin.v0',
      factorCatalog: [],
      weights: {},
    },
  };
}

describe('development seed ids', () => {
  it('reserves a new UUID for builtin priority policy version 2', () => {
    const ids = Object.values(developmentSeedIds);
    expect(new Set(ids).size).toBe(ids.length);
    expect(developmentSeedIds.builtinPriorityPolicyVersion2).toBe(VERSION_2_ID);
    expect(isUuid(developmentSeedIds.builtinPriorityPolicyVersion2)).toBe(true);
    expect(developmentSeedIds.builtinPriorityPolicyVersion2).not.toBe(
      developmentSeedIds.builtinRiskPolicy,
    );
  });
});

describe('ensurePublishedBuiltinPriorityPolicy', () => {
  it('inserts published version 2 when the builtin key is absent', async () => {
    const { rows, riskPolicy } = createPolicyMemory();
    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result.outcome).toBe('inserted');
    expect(result.policy).toMatchObject({
      id: developmentSeedIds.builtinPriorityPolicyVersion2,
      organizationId: null,
      createdByMembershipId: null,
      scope: 'builtin',
      policyKey: 'patchpilot.builtin.v0',
      name: DISPLAY_NAME,
      version: 2,
      status: 'published',
      policySchemaVersion: 2,
    });
    expect(result.policy.definition).toBe(suppliedDefinition);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.publishedAt).toEqual(new Date('2026-01-01T00:00:00.000Z'));
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('returns already_applied for the same canonical JSON without rewriting the row', async () => {
    const { rows, riskPolicy } = createPolicyMemory();
    const stored = policyRow({
      name: 'Older display name',
      status: 'draft',
      policySchemaVersion: 1,
      definition: reorder(suppliedDefinition),
    });
    rows.push(stored);

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result).toEqual({ outcome: 'already_applied', policy: stored });
    expect(rows).toEqual([stored]);
    expect(riskPolicy.create).not.toHaveBeenCalled();
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('reports an immutable conflict when the stored definition differs', async () => {
    const { rows, riskPolicy } = createPolicyMemory();
    const stored = policyRow({
      definition: { schemaVersion: 2, policyKey: 'patchpilot.builtin.v0', marker: 'other' },
    });
    rows.push(stored);

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result).toEqual({ outcome: 'immutable_conflict', policy: stored });
    expect(rows).toEqual([stored]);
    expect(riskPolicy.create).not.toHaveBeenCalled();
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('reports an immutable conflict when the stored definition cannot be canonicalized', async () => {
    const { riskPolicy } = createPolicyMemory();
    const stored = policyRow({ definition: { schemaVersion: 2, unexpected: true } });
    riskPolicy.findFirst.mockResolvedValueOnce(stored);
    const canonicalize = (value: unknown): string => {
      if (value !== suppliedDefinition) {
        throw new Error('stored document rejected');
      }
      return canonicalJson(value);
    };

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson: canonicalize,
    });

    expect(result.outcome).toBe('immutable_conflict');
    expect(result.policy.id).toBe(stored.id);
    expect(riskPolicy.create).not.toHaveBeenCalled();
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('does not query or insert when the supplied definition cannot be canonicalized', async () => {
    const { riskPolicy } = createPolicyMemory();
    const canonicalize = (): string => {
      throw new Error('supplied document rejected');
    };

    await expect(
      ensurePublishedBuiltinPriorityPolicy({
        client: asClient(riskPolicy),
        definition: suppliedDefinition,
        canonicalJson: canonicalize,
      }),
    ).rejects.toThrow(/supplied document rejected/);
    expect(riskPolicy.findFirst).not.toHaveBeenCalled();
    expect(riskPolicy.create).not.toHaveBeenCalled();
  });

  it('rejects a canonicalJson result that is not a string before querying', async () => {
    const { riskPolicy } = createPolicyMemory();
    const canonicalize = (() => 1) as unknown as (value: unknown) => string;

    await expect(
      ensurePublishedBuiltinPriorityPolicy({
        client: asClient(riskPolicy),
        definition: suppliedDefinition,
        canonicalJson: canonicalize,
      }),
    ).rejects.toThrow(/must return a string/);
    expect(riskPolicy.findFirst).not.toHaveBeenCalled();
    expect(riskPolicy.create).not.toHaveBeenCalled();
  });

  it('treats a non-string canonical form of the stored row as a conflict', async () => {
    const { riskPolicy } = createPolicyMemory();
    const stored = policyRow({
      definition: { ...suppliedDefinition },
    });
    riskPolicy.findFirst.mockResolvedValueOnce(stored);
    const canonicalize = ((value: unknown) =>
      value === suppliedDefinition ? canonicalJson(value) : 1) as unknown as (
      value: unknown,
    ) => string;

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson: canonicalize,
    });

    expect(result.outcome).toBe('immutable_conflict');
    expect(riskPolicy.create).not.toHaveBeenCalled();
    expect(riskPolicy.update).not.toHaveBeenCalled();
  });

  it('replays a unique conflict when the winning row matches', async () => {
    const { riskPolicy } = createPolicyMemory();
    const stored = policyRow({ definition: reorder(suppliedDefinition) });
    riskPolicy.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(stored);
    riskPolicy.create.mockRejectedValueOnce(uniqueConflict());

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result).toEqual({ outcome: 'already_applied', policy: stored });
    expect(riskPolicy.create).toHaveBeenCalledTimes(1);
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('keeps a conflicting winner after a unique conflict', async () => {
    const { riskPolicy } = createPolicyMemory();
    const stored = policyRow({
      definition: { schemaVersion: 2, policyKey: 'patchpilot.builtin.v0', marker: 'winner' },
    });
    riskPolicy.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce(stored);
    riskPolicy.create.mockRejectedValueOnce(uniqueConflict());

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result).toEqual({ outcome: 'immutable_conflict', policy: stored });
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('does not treat another row that holds the fixed id as a replay', async () => {
    const { riskPolicy } = createPolicyMemory();
    const occupant = policyRow({
      policyKey: 'other.key',
      version: 9,
      scope: 'organization',
      organizationId: developmentSeedIds.organizationA,
      definition: suppliedDefinition,
    });
    riskPolicy.findFirst.mockResolvedValue(null);
    riskPolicy.findUnique.mockResolvedValue(occupant);
    riskPolicy.create.mockRejectedValueOnce(uniqueConflict());

    const result = await ensurePublishedBuiltinPriorityPolicy({
      client: asClient(riskPolicy),
      definition: suppliedDefinition,
      canonicalJson,
    });

    expect(result).toEqual({ outcome: 'immutable_conflict', policy: occupant });
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('throws a sanitized error when a unique conflict cannot be reloaded', async () => {
    const { riskPolicy } = createPolicyMemory();
    riskPolicy.findFirst.mockResolvedValue(null);
    riskPolicy.findUnique.mockResolvedValue(null);
    riskPolicy.create.mockRejectedValueOnce(uniqueConflict());

    await expect(
      ensurePublishedBuiltinPriorityPolicy({
        client: asClient(riskPolicy),
        definition: suppliedDefinition,
        canonicalJson,
      }),
    ).rejects.toThrow(/could not be reloaded/);
    expect(riskPolicy.update).not.toHaveBeenCalled();
    expect(riskPolicy.delete).not.toHaveBeenCalled();
  });
});

describe('seedDevelopmentData builtin priority policy', () => {
  it('refuses production before any write, including when version 2 is requested', async () => {
    const seeded = createSeedClient();
    await expect(
      seedDevelopmentData({
        env: { PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production' },
        client: seeded.client,
        builtinPriorityDefinition: suppliedDefinition,
        canonicalJson,
      }),
    ).rejects.toThrow(/Development seed is disabled/);
    await expect(
      seedDevelopmentData({
        env: { NODE_ENV: 'production' },
        client: seeded.client,
        builtinPriorityDefinition: suppliedDefinition,
        canonicalJson,
      }),
    ).rejects.toThrow(/Development seed is disabled/);
    expect(seeded.user.upsert).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.create).not.toHaveBeenCalled();
  });

  it('rejects a partial version 2 request before any write', async () => {
    const seeded = createSeedClient();
    await expect(
      seedDevelopmentData({
        env: DEV_ENV,
        client: seeded.client,
        builtinPriorityDefinition: suppliedDefinition,
      }),
    ).rejects.toThrow(/requires both builtinPriorityDefinition and canonicalJson/);
    await expect(
      seedDevelopmentData({
        env: DEV_ENV,
        client: seeded.client,
        canonicalJson,
      }),
    ).rejects.toThrow(/requires both builtinPriorityDefinition and canonicalJson/);
    expect(seeded.user.upsert).not.toHaveBeenCalled();
  });

  it('skips version 2 when the engine definition is omitted and still seeds version 1 once', async () => {
    const seeded = createSeedClient();
    await seedDevelopmentData({ env: DEV_ENV, client: seeded.client });
    await seedDevelopmentData({ env: DEV_ENV, client: seeded.client });

    const builtin = seeded.rows.filter((row) => row.policyKey === 'patchpilot.builtin.v0');
    expect(builtin.map((row) => row.version)).toEqual([1]);
    expect(builtin[0]).toMatchObject(version1Placeholder());
    expect(seeded.rows.filter((row) => row.version === 2)).toEqual([]);
    expect(seeded.riskPolicy.update).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('publishes version 2 from a normal seed and replays it without a second insert', async () => {
    const seeded = createSeedClient();
    const options = {
      env: DEV_ENV,
      client: seeded.client,
      builtinPriorityDefinition: suppliedDefinition,
      canonicalJson,
    };
    await seedDevelopmentData(options);
    await seedDevelopmentData(options);

    const version1 = seeded.rows.find((row) => row.version === 1 && row.scope === 'builtin');
    const version2 = seeded.rows.filter((row) => row.version === 2);
    expect(version1).toMatchObject(version1Placeholder());
    expect(version2).toHaveLength(1);
    expect(version2[0]).toMatchObject({
      id: developmentSeedIds.builtinPriorityPolicyVersion2,
      organizationId: null,
      createdByMembershipId: null,
      scope: 'builtin',
      policyKey: 'patchpilot.builtin.v0',
      name: DISPLAY_NAME,
      version: 2,
      status: 'published',
      policySchemaVersion: 2,
      definition: suppliedDefinition,
    });
    expect(seeded.riskPolicy.create).toHaveBeenCalledTimes(3);
    expect(seeded.riskPolicy.update).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.delete).not.toHaveBeenCalled();
  });

  it('fails the seed on an immutable conflict and leaves version 1 and version 2 unchanged', async () => {
    const seeded = createSeedClient();
    const version1 = version1Placeholder();
    const conflicting = policyRow({
      name: 'Not the display name',
      status: 'draft',
      policySchemaVersion: 1,
      definition: { schemaVersion: 2, policyKey: 'patchpilot.builtin.v0', marker: 'other' },
    });
    seeded.rows.push(version1, conflicting);

    const error = await seedDevelopmentData({
      env: DEV_ENV,
      client: seeded.client,
      builtinPriorityDefinition: suppliedDefinition,
      canonicalJson,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(BuiltinPriorityPolicyImmutableConflictError);
    if (!(error instanceof BuiltinPriorityPolicyImmutableConflictError)) {
      return;
    }
    expect(error.outcome).toBe('immutable_conflict');
    expect(error.policyId).toBe(developmentSeedIds.builtinPriorityPolicyVersion2);
    expect(error.message).not.toContain('marker');
    expect(seeded.rows).toEqual([version1, conflicting]);
    expect(seeded.vulnerability.upsert).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.create).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.update).not.toHaveBeenCalled();
    expect(seeded.riskPolicy.delete).not.toHaveBeenCalled();
  });
});

describe('policy engine seed boundary', () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');

  it('keeps the engine as a database devDependency only', () => {
    const databaseManifest = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/database/package.json'), 'utf8'),
    ) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(databaseManifest.dependencies?.['@patchpilot/policy-engine']).toBeUndefined();
    expect(databaseManifest.devDependencies?.['@patchpilot/policy-engine']).toBe('workspace:*');

    for (const relative of [
      'apps/api/package.json',
      'apps/web/package.json',
      'apps/worker/package.json',
      'packages/domain/package.json',
    ]) {
      const manifest = JSON.parse(readFileSync(path.join(repoRoot, relative), 'utf8')) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
      };
      const declared = [
        ...Object.keys(manifest.dependencies ?? {}),
        ...Object.keys(manifest.devDependencies ?? {}),
        ...Object.keys(manifest.peerDependencies ?? {}),
      ];
      expect(declared, relative).not.toContain('@patchpilot/policy-engine');
    }
  });

  it('imports the engine only from the seed entrypoint', () => {
    const databaseSrc = path.join(repoRoot, 'packages/database/src');
    const offenders: string[] = [];
    for (const filePath of productionSources(databaseSrc)) {
      const relative = path.relative(repoRoot, filePath);
      if (relative === 'packages/database/src/seed/run.ts') {
        continue;
      }
      if (importSpecifiers(readFileSync(filePath, 'utf8')).some(importsPolicyEngine)) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);

    const entrypoint = readFileSync(path.join(databaseSrc, 'seed/run.ts'), 'utf8');
    expect(importSpecifiers(entrypoint)).toContain('@patchpilot/policy-engine');
    expect(entrypoint).toContain('BUILTIN_PRIORITY_POLICY_DEFINITION');
    expect(entrypoint).toContain('builtinPriorityDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION');
    expect(entrypoint).toContain('canonicalJson,');
  });
});

function productionSources(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === 'generated') {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      productionSources(fullPath, files);
    } else if (/\.(ts|tsx|mjs|js)$/.test(entry) && !entry.endsWith('.test.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

function importSpecifiers(source: string): string[] {
  const withoutComments = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of withoutComments.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) {
        specifiers.push(specifier);
      }
    }
  }
  return specifiers;
}

function importsPolicyEngine(specifier: string): boolean {
  return specifier === '@patchpilot/policy-engine' || specifier.includes('policy-engine');
}
