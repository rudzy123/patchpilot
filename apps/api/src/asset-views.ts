import {
  assetDetailSchema,
  assetListResponseSchema,
  encodeAssetListCursor,
  environmentOptionsResponseSchema,
  membershipOptionsResponseSchema,
  teamOptionsResponseSchema,
  type AssetDetail,
  type AssetListResponse,
  type AssetSummary,
  type EnvironmentOption,
  type MembershipOption,
  type TeamOption,
} from '@patchpilot/contracts';
import type {
  AssetDetailRecord,
  AssetEnvironmentOption,
  AssetListPage,
  AssetMembershipOption,
  AssetOwnerView,
  AssetSummaryRecord,
  AssetTeamOption,
  Page,
} from '@patchpilot/domain';

export function toAssetSummary(record: AssetSummaryRecord): AssetSummary {
  return {
    id: record.id,
    name: record.name,
    assetType: record.assetType,
    lifecycleStatus: record.lifecycleStatus,
    environment:
      record.environment === null
        ? null
        : {
            id: record.environment.id,
            name: record.environment.name,
            sensitivityClass: record.environment.sensitivityClass,
          },
    owningTeam:
      record.owningTeam === null
        ? null
        : {
            id: record.owningTeam.id,
            name: record.owningTeam.name,
          },
    businessCriticality: record.businessCriticality,
    internetExposure: record.internetExposure,
    dataClassification: record.dataClassification,
    tags: [...record.tags],
    lastObservedAt: utcIso(record.lastObservedAt),
    version: record.version,
    updatedAt: record.updatedAt.toISOString(),
  };
}

export function toAssetDetail(record: AssetDetailRecord): AssetDetail {
  return assetDetailSchema.parse({
    ...toAssetSummary(record),
    description: record.description,
    repositoryUrl: record.repositoryUrl,
    deploymentContext: record.deploymentContext,
    lastSuccessfulSbomIngestionId: record.lastSuccessfulSbomIngestionId,
    lastSuccessfulSbomIngestionAt: utcIso(record.lastSuccessfulSbomIngestionAt),
    archivedAt: utcIso(record.archivedAt),
    owners: record.owners.map(toPublicOwner),
    externalIdentifiers: record.identifiers.map((identifier) => ({
      namespace: identifier.namespace,
      identifier: identifier.identifier,
    })),
    createdAt: record.createdAt.toISOString(),
  });
}

export function toAssetListResponse(page: AssetListPage): AssetListResponse {
  return assetListResponseSchema.parse({
    items: page.items.map(toAssetSummary),
    nextCursor: page.nextCursor === undefined ? null : encodeAssetListCursor(page.nextCursor),
  });
}

export function toEnvironmentOptionsResponse(page: Page<AssetEnvironmentOption>): {
  items: EnvironmentOption[];
  nextCursor: string | null;
} {
  return environmentOptionsResponseSchema.parse({
    items: page.items.map((item) => ({
      id: item.id,
      name: item.name,
      slug: item.slug,
      sensitivityClass: item.sensitivityClass,
    })),
    nextCursor: page.nextCursor === undefined ? null : page.nextCursor.id,
  });
}

export function toTeamOptionsResponse(page: Page<AssetTeamOption>): {
  items: TeamOption[];
  nextCursor: string | null;
} {
  return teamOptionsResponseSchema.parse({
    items: page.items.map((item) => ({
      id: item.id,
      name: item.name,
      slug: item.slug,
    })),
    nextCursor: page.nextCursor === undefined ? null : page.nextCursor.id,
  });
}

export function toMembershipOptionsResponse(page: Page<AssetMembershipOption>): {
  items: MembershipOption[];
  nextCursor: string | null;
} {
  return membershipOptionsResponseSchema.parse({
    items: page.items.map((item) => ({
      membershipId: item.membershipId,
      displayName: item.displayName,
      role: item.role,
    })),
    nextCursor: page.nextCursor === undefined ? null : page.nextCursor.id,
  });
}

function toPublicOwner(owner: AssetOwnerView) {
  if (owner.kind === 'membership') {
    return {
      kind: 'membership' as const,
      id: owner.id,
      membershipId: owner.membershipId,
      displayName: owner.displayName,
      role: owner.role,
    };
  }

  return {
    kind: 'team' as const,
    id: owner.id,
    teamId: owner.teamId,
    name: owner.name,
    role: owner.role,
  };
}

function utcIso(value: Date | null): string | null {
  return value === null ? null : value.toISOString();
}
