import { describe, expect, it, vi } from 'vitest';

import { parseExactCanonicalCve, type CanonicalCve } from '@patchpilot/domain';

import { createActiveKevMembershipPersistence } from './active-kev-membership.js';
import type { PrismaClientLike } from './guards.js';

const CVE_A = 'CVE-1900-00001';
const CATALOG_VERSION = '2099.01.01';
const RELEASED_AT = new Date('2026-09-01T12:00:00.000Z');
const SUCCESS_AT = new Date('2026-09-01T12:00:00.000Z');
const GENERATION_ID = '11111111-1111-4111-8111-111111111111';

function requireCve(): CanonicalCve {
  const parsed = parseExactCanonicalCve(CVE_A);
  if (!parsed.ok) {
    throw new Error('expected synthetic canonical CVE');
  }
  return parsed.value;
}

function entryRow(
  overrides?: Partial<{
    normalizedCve: string;
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
  }>,
) {
  return {
    normalizedCve: overrides?.normalizedCve ?? CVE_A,
    dateAdded: overrides?.dateAdded ?? '2024-01-15',
    dueDate: overrides?.dueDate ?? '2024-02-15',
    knownRansomwareCampaignUse: overrides?.knownRansomwareCampaignUse ?? 'known',
  };
}

function generationRow(overrides?: {
  state?: string;
  providerKey?: string;
  sourceIdentifier?: string;
  catalogVersion?: string | null;
  catalogReleasedAt?: Date | null;
  expectedEntryCount?: number;
  entries?: ReturnType<typeof entryRow>[];
}) {
  return {
    id: GENERATION_ID,
    providerKey: overrides?.providerKey ?? 'cisa_kev',
    sourceIdentifier: overrides?.sourceIdentifier ?? 'cisa_kev_json_catalog',
    state: overrides?.state ?? 'active',
    catalogVersion:
      overrides?.catalogVersion === undefined ? CATALOG_VERSION : overrides.catalogVersion,
    catalogReleasedAt:
      overrides?.catalogReleasedAt === undefined ? RELEASED_AT : overrides.catalogReleasedAt,
    expectedEntryCount: overrides?.expectedEntryCount ?? 1,
    entries: overrides?.entries ?? [entryRow()],
  };
}

function sourceRow(overrides?: {
  activeGenerationId?: string | null;
  activeGeneration?: ReturnType<typeof generationRow> | null;
  lastSuccessfulSyncAt?: Date | null;
  providerKey?: string;
}) {
  const activeGenerationId =
    overrides?.activeGenerationId === undefined ? GENERATION_ID : overrides.activeGenerationId;
  return {
    providerKey: overrides?.providerKey ?? 'cisa_kev',
    state: 'enabled',
    lastSuccessfulSyncAt:
      overrides?.lastSuccessfulSyncAt === undefined ? SUCCESS_AT : overrides.lastSuccessfulSyncAt,
    activeGenerationId,
    activeGeneration:
      overrides?.activeGeneration === undefined
        ? activeGenerationId === null
          ? null
          : generationRow()
        : overrides.activeGeneration,
  };
}

function createFakePrisma() {
  return {
    intelligenceSource: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
      upsert: vi.fn(),
      delete: vi.fn(),
      count: vi.fn(),
    },
    kevGeneration: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      count: vi.fn(),
    },
    kevEntry: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      count: vi.fn(),
      aggregate: vi.fn(),
    },
    cveIdentity: {
      findUnique: vi.fn(),
      create: vi.fn(),
      findMany: vi.fn(),
    },
    vulnerability: {
      findUnique: vi.fn(),
      create: vi.fn(),
    },
    finding: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      count: vi.fn(),
    },
    listActiveEntries: vi.fn(),
  };
}

function persistenceFor(fake: ReturnType<typeof createFakePrisma>) {
  return createActiveKevMembershipPersistence(fake as unknown as PrismaClientLike);
}

function prototypeMethods(value: object): string[] {
  return Object.getOwnPropertyNames(Object.getPrototypeOf(value)).filter(
    (name) => name !== 'constructor',
  );
}

describe('createActiveKevMembershipPersistence', () => {
  it('returns a read port with only the snapshot loader', () => {
    const port = persistenceFor(createFakePrisma());
    expect(prototypeMethods(port)).toEqual(['loadActiveKevMembershipSnapshot']);
    expect(port).not.toHaveProperty('listActiveEntries');
    expect(port).not.toHaveProperty('create');
    expect(port).not.toHaveProperty('update');
  });
});

describe('active KEV membership adapter queries', () => {
  it('looks up the fixed cisa_kev source with nested exact CVE entries and take 2', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(sourceRow());
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result.ok && result.value.kind).toBe('present');
    expect(fake.intelligenceSource.findUnique).toHaveBeenCalledTimes(1);
    const args = fake.intelligenceSource.findUnique.mock.calls[0]?.[0] as {
      where: { providerKey: string };
      select: {
        activeGeneration: {
          select: {
            entries: {
              where: { normalizedCve: string };
              take: number;
              select: Record<string, boolean>;
            };
          };
        };
      };
    };
    expect(args.where).toEqual({ providerKey: 'cisa_kev' });
    expect(args.select.activeGeneration.select.entries.where).toEqual({ normalizedCve: CVE_A });
    expect(args.select.activeGeneration.select.entries.take).toBe(2);
    expect(Object.keys(args.select.activeGeneration.select.entries.select).sort()).toEqual([
      'dateAdded',
      'dueDate',
      'knownRansomwareCampaignUse',
      'normalizedCve',
    ]);
    expect(args.select.activeGeneration.select.entries.select).not.toHaveProperty('vendorProject');
    expect(args.select.activeGeneration.select.entries.select).not.toHaveProperty(
      'rawKnownRansomwareCampaignUse',
    );
    expect(fake.kevEntry.findMany).not.toHaveBeenCalled();
    expect(fake.kevEntry.count).not.toHaveBeenCalled();
    expect(fake.listActiveEntries).not.toHaveBeenCalled();
    expect(fake.cveIdentity.findUnique).not.toHaveBeenCalled();
    expect(fake.vulnerability.findUnique).not.toHaveBeenCalled();
    expect(fake.finding.findMany).not.toHaveBeenCalled();
    expect(fake.intelligenceSource.create).not.toHaveBeenCalled();
    expect(fake.intelligenceSource.update).not.toHaveBeenCalled();
    expect(fake.intelligenceSource.delete).not.toHaveBeenCalled();
  });

  it('does not accept a provider override and rejects lowercase before SQL', async () => {
    const fake = createFakePrisma();
    const lowercase = 'cve-1900-00001' as CanonicalCve;
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(lowercase);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('validation');
    }
    expect(fake.intelligenceSource.findUnique).not.toHaveBeenCalled();
    expect(createActiveKevMembershipPersistence.length).toBe(1);
  });

  it('returns source_missing when the CISA source row is absent', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(null);
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result).toEqual({ ok: true, value: { kind: 'source_missing' } });
  });

  it('returns no_active_generation when the pointer is null', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(
      sourceRow({ activeGenerationId: null, activeGeneration: null }),
    );
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result).toEqual({ ok: true, value: { kind: 'no_active_generation' } });
  });

  it('returns inconsistency for missing nested generation, wrong state, provider, or source', async () => {
    const cases = [
      sourceRow({ activeGenerationId: GENERATION_ID, activeGeneration: null }),
      sourceRow({ activeGeneration: generationRow({ state: 'superseded' }) }),
      sourceRow({ activeGeneration: generationRow({ providerKey: 'osv' }) }),
      sourceRow({
        activeGeneration: generationRow({ sourceIdentifier: 'other_catalog' }),
      }),
    ];
    for (const row of cases) {
      const fake = createFakePrisma();
      fake.intelligenceSource.findUnique.mockResolvedValue(row);
      const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
      expect(result).toEqual({
        ok: true,
        value: { kind: 'inconsistent_active_generation' },
      });
    }
  });

  it('returns inconsistency for missing success timestamp and malformed catalog metadata', async () => {
    const cases = [
      sourceRow({ lastSuccessfulSyncAt: null }),
      sourceRow({ activeGeneration: generationRow({ catalogVersion: '' }) }),
      sourceRow({ activeGeneration: generationRow({ catalogReleasedAt: null }) }),
      sourceRow({ activeGeneration: generationRow({ expectedEntryCount: -1 }) }),
    ];
    for (const row of cases) {
      const fake = createFakePrisma();
      fake.intelligenceSource.findUnique.mockResolvedValue(row);
      const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
      expect(result).toEqual({
        ok: true,
        value: { kind: 'inconsistent_active_generation' },
      });
    }
  });

  it('returns absent when no matching entry exists', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(
      sourceRow({ activeGeneration: generationRow({ entries: [] }) }),
    );
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result.ok && result.value.kind).toBe('absent');
    if (result.ok && result.value.kind === 'absent') {
      expect(result.value.catalogVersion).toBe(CATALOG_VERSION);
      expect(result.value).not.toHaveProperty('vendorProject');
      expect(result.value).not.toHaveProperty('generationId');
    }
  });

  it('returns present for one matching structured entry', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(sourceRow());
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result.ok && result.value.kind).toBe('present');
    if (result.ok && result.value.kind === 'present') {
      expect(result.value.knownRansomwareCampaignUse).toBe('known');
      expect(result.value).not.toHaveProperty('rawKnownRansomwareCampaignUse');
      expect(result.value).not.toHaveProperty('requiredAction');
    }
  });

  it('returns inconsistency when two matching entries appear', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockResolvedValue(
      sourceRow({
        activeGeneration: generationRow({ entries: [entryRow(), entryRow()] }),
      }),
    );
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result).toEqual({
      ok: true,
      value: { kind: 'inconsistent_active_generation' },
    });
  });

  it('returns malformed_persisted_entry for invalid structured entry fields', async () => {
    const cases = [
      entryRow({ normalizedCve: 'cve-1900-00001' }),
      entryRow({ dateAdded: '2024-13-01' }),
      entryRow({ dueDate: '2024/02/15' }),
      entryRow({ knownRansomwareCampaignUse: 'Known' }),
    ];
    for (const entry of cases) {
      const fake = createFakePrisma();
      fake.intelligenceSource.findUnique.mockResolvedValue(
        sourceRow({ activeGeneration: generationRow({ entries: [entry] }) }),
      );
      const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
      expect(result).toEqual({ ok: true, value: { kind: 'malformed_persisted_entry' } });
    }
  });

  it('sanitizes database errors and never returns Prisma text', async () => {
    const fake = createFakePrisma();
    fake.intelligenceSource.findUnique.mockRejectedValue(
      new Error('PrismaClientKnownRequestError at postgresql://secret'),
    );
    const result = await persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('internal');
      expect(result.error.message).toBe('Active KEV membership is temporarily unavailable.');
      expect(result.error.message).not.toMatch(/Prisma|postgresql|secret/i);
    }
  });
});

describe('activation-race query pinning', () => {
  it('issues one nested query pinned to the observed generation and never re-reads the pointer', async () => {
    const fake = createFakePrisma();
    let resolveQuery: ((row: ReturnType<typeof sourceRow>) => void) | undefined;
    fake.intelligenceSource.findUnique.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveQuery = resolve;
        }),
    );
    const pending = persistenceFor(fake).loadActiveKevMembershipSnapshot(requireCve());
    expect(fake.intelligenceSource.findUnique).toHaveBeenCalledTimes(1);
    if (resolveQuery === undefined) {
      throw new Error('expected the nested source query to start');
    }
    resolveQuery(
      sourceRow({
        activeGeneration: generationRow({ entries: [entryRow()] }),
      }),
    );
    const result = await pending;
    expect(fake.intelligenceSource.findUnique).toHaveBeenCalledTimes(1);
    expect(fake.kevGeneration.findUnique).not.toHaveBeenCalled();
    expect(fake.kevEntry.findMany).not.toHaveBeenCalled();
    expect(result.ok && result.value.kind).toBe('present');
    if (result.ok && result.value.kind === 'present') {
      expect(result.value.catalogVersion).toBe(CATALOG_VERSION);
    }
  });
});
