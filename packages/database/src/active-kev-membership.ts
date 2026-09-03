import {
  ACTIVE_KEV_MEMBERSHIP_UNAVAILABLE,
  CISA_KEV_SOURCE_IDENTIFIER,
  err,
  isNonNegativeSafeInteger,
  knownRansomwareCampaignUseValues,
  ok,
  parseBoundedCatalogVersion,
  parseCalendarDate,
  parseExactCanonicalCve,
  type ActiveKevMembershipReadPort,
  type ActiveKevMembershipSnapshot,
  type CanonicalCve,
  type KnownRansomwareCampaignUse,
  type Result,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';

const CISA_KEV_PROVIDER = 'cisa_kev' as const;

type SelectedEntry = {
  normalizedCve: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
};

type SelectedGeneration = {
  providerKey: string;
  sourceIdentifier: string;
  state: string;
  catalogVersion: string | null;
  catalogReleasedAt: Date | null;
  expectedEntryCount: number;
  entries: SelectedEntry[];
};

type SelectedSource = {
  providerKey: string;
  lastSuccessfulSyncAt: Date | null;
  activeGenerationId: string | null;
  activeGeneration: SelectedGeneration | null;
};

function isNormalizedRansomware(value: string): value is KnownRansomwareCampaignUse {
  return (knownRansomwareCampaignUseValues as readonly string[]).includes(value);
}

function parseInstant(value: Date | null): Date | undefined {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return undefined;
  }
  return value;
}

function mapPresentOrMalformed(
  catalogVersion: string,
  catalogReleasedAt: Date,
  lastSuccessfulSyncAt: Date,
  entry: SelectedEntry,
  queriedCve: CanonicalCve,
): Result<ActiveKevMembershipSnapshot> {
  const normalizedCve = parseExactCanonicalCve(entry.normalizedCve);
  if (!normalizedCve.ok) {
    return ok({ kind: 'malformed_persisted_entry' });
  }
  if (normalizedCve.value !== queriedCve) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const dateAdded = parseCalendarDate(entry.dateAdded);
  if (!dateAdded.ok) {
    return ok({ kind: 'malformed_persisted_entry' });
  }
  const dueDate = parseCalendarDate(entry.dueDate);
  if (!dueDate.ok) {
    return ok({ kind: 'malformed_persisted_entry' });
  }
  if (!isNormalizedRansomware(entry.knownRansomwareCampaignUse)) {
    return ok({ kind: 'malformed_persisted_entry' });
  }
  return ok({
    kind: 'present',
    catalogVersion,
    catalogReleasedAt,
    lastSuccessfulSyncAt,
    dateAdded: dateAdded.value,
    dueDate: dueDate.value,
    knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
  });
}

function mapLoadedSource(
  source: SelectedSource,
  queriedCve: CanonicalCve,
): Result<ActiveKevMembershipSnapshot> {
  if (source.providerKey !== CISA_KEV_PROVIDER) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  if (source.activeGenerationId === null) {
    return ok({ kind: 'no_active_generation' });
  }
  const generation = source.activeGeneration;
  if (generation === null) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  if (
    generation.providerKey !== CISA_KEV_PROVIDER ||
    generation.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER ||
    generation.state !== 'active'
  ) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const catalogVersion = parseBoundedCatalogVersion(generation.catalogVersion);
  if (!catalogVersion.ok) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const catalogReleasedAt = parseInstant(generation.catalogReleasedAt);
  if (catalogReleasedAt === undefined) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  if (!isNonNegativeSafeInteger(generation.expectedEntryCount)) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const lastSuccessfulSyncAt = parseInstant(source.lastSuccessfulSyncAt);
  if (lastSuccessfulSyncAt === undefined) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const entries = generation.entries;
  if (entries.length > 1) {
    return ok({ kind: 'inconsistent_active_generation' });
  }
  const entry = entries[0];
  if (entry === undefined) {
    return ok({
      kind: 'absent',
      catalogVersion: catalogVersion.value,
      catalogReleasedAt,
      lastSuccessfulSyncAt,
    });
  }
  return mapPresentOrMalformed(
    catalogVersion.value,
    catalogReleasedAt,
    lastSuccessfulSyncAt,
    entry,
    queriedCve,
  );
}

class PrismaActiveKevMembershipPersistence implements ActiveKevMembershipReadPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async loadActiveKevMembershipSnapshot(
    cve: CanonicalCve,
  ): Promise<Result<ActiveKevMembershipSnapshot>> {
    const parsed = parseExactCanonicalCve(cve);
    if (!parsed.ok) {
      return parsed;
    }

    try {
      const source = await this.client.intelligenceSource.findUnique({
        where: { providerKey: CISA_KEV_PROVIDER },
        select: {
          providerKey: true,
          lastSuccessfulSyncAt: true,
          activeGenerationId: true,
          activeGeneration: {
            select: {
              providerKey: true,
              sourceIdentifier: true,
              state: true,
              catalogVersion: true,
              catalogReleasedAt: true,
              expectedEntryCount: true,
              entries: {
                where: { normalizedCve: parsed.value },
                take: 2,
                select: {
                  normalizedCve: true,
                  dateAdded: true,
                  dueDate: true,
                  knownRansomwareCampaignUse: true,
                },
              },
            },
          },
        },
      });
      if (source === null) {
        return ok({ kind: 'source_missing' });
      }
      return mapLoadedSource(source, parsed.value);
    } catch {
      return err(ACTIVE_KEV_MEMBERSHIP_UNAVAILABLE);
    }
  }
}

export function createActiveKevMembershipPersistence(
  client: PrismaClientLike,
): ActiveKevMembershipReadPort {
  return new PrismaActiveKevMembershipPersistence(client);
}
