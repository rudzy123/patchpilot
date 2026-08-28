import type {
  AssetDetailRecord,
  AssetEnvironmentSummary,
  AssetExternalIdentifierRecord,
  AssetOwnerView,
  AssetSummaryRecord,
  AssetTagRecord,
  AssetTeamSummary,
  EnvironmentSensitivityClass,
} from '@patchpilot/domain';

import { mapAsset } from './mappers.js';

export type AssetListRow = {
  id: string;
  organizationId: string;
  name: string;
  assetType: AssetSummaryRecord['assetType'];
  lifecycleStatus: AssetSummaryRecord['lifecycleStatus'];
  businessCriticality: AssetSummaryRecord['businessCriticality'];
  internetExposure: AssetSummaryRecord['internetExposure'];
  dataClassification: AssetSummaryRecord['dataClassification'];
  lastObservedAt: Date | null;
  version: number;
  updatedAt: Date;
  environmentId: string | null;
  environmentName: string | null;
  environmentSensitivityClass: EnvironmentSensitivityClass | null;
  owningTeamId: string | null;
  owningTeamName: string | null;
  tags: unknown;
};

export type AssetOwnerRelationRow = {
  id: string;
  userId: string | null;
  teamId: string | null;
  role: AssetOwnerView['role'];
  team: { id: string; name: string } | null;
  user: { id: string; displayName: string } | null;
  membership: { id: string; userId: string } | null;
};

export type AssetDetailRelationRow = {
  id: string;
  organizationId: string;
  name: string;
  description: string | null;
  assetType: AssetSummaryRecord['assetType'];
  lifecycleStatus: AssetSummaryRecord['lifecycleStatus'];
  environmentId: string | null;
  owningTeamId: string | null;
  businessCriticality: AssetSummaryRecord['businessCriticality'];
  internetExposure: AssetSummaryRecord['internetExposure'];
  dataClassification: AssetSummaryRecord['dataClassification'];
  repositoryUrl: string | null;
  deploymentContext: string | null;
  lastObservedAt: Date | null;
  lastSuccessfulSbomIngestionId: string | null;
  lastSuccessfulSbomIngestionAt: Date | null;
  archivedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
  environment: {
    id: string;
    name: string;
    sensitivityClass: EnvironmentSensitivityClass;
  } | null;
  owningTeam: { id: string; name: string } | null;
  tags: readonly {
    id: string;
    organizationId: string;
    assetId: string;
    tag: string;
    createdAt: Date;
  }[];
  externalIdentifiers: readonly {
    id: string;
    organizationId: string;
    assetId: string;
    namespace: string;
    identifier: string;
    createdAt: Date;
  }[];
  owners: readonly AssetOwnerRelationRow[];
};

export function mapAssetSummary(row: AssetListRow): AssetSummaryRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    name: row.name,
    assetType: row.assetType,
    lifecycleStatus: row.lifecycleStatus,
    environment: mapEnvironmentSummary(row),
    owningTeam: mapOwningTeamSummary(row),
    businessCriticality: row.businessCriticality,
    internetExposure: row.internetExposure,
    dataClassification: row.dataClassification,
    tags: mapTagValues(row.tags),
    lastObservedAt: row.lastObservedAt,
    version: row.version,
    updatedAt: row.updatedAt,
  };
}

export function mapAssetDetail(row: AssetDetailRelationRow): AssetDetailRecord {
  const asset = mapAsset(row);
  return {
    id: asset.id,
    organizationId: asset.organizationId,
    name: asset.name,
    assetType: asset.assetType,
    lifecycleStatus: asset.lifecycleStatus,
    environment: mapRelatedEnvironment(row.environment),
    owningTeam: mapRelatedTeam(row.owningTeam),
    businessCriticality: asset.businessCriticality,
    internetExposure: asset.internetExposure,
    dataClassification: asset.dataClassification,
    tags: row.tags.map((tag) => tag.tag),
    lastObservedAt: asset.lastObservedAt,
    version: asset.version,
    updatedAt: asset.updatedAt,
    description: asset.description,
    repositoryUrl: asset.repositoryUrl,
    deploymentContext: asset.deploymentContext,
    lastSuccessfulSbomIngestionId: asset.lastSuccessfulSbomIngestionId,
    lastSuccessfulSbomIngestionAt: asset.lastSuccessfulSbomIngestionAt,
    archivedAt: asset.archivedAt,
    owners: sortOwners(row.owners.map(mapAssetOwnerView).filter(isOwnerView)),
    identifiers: [...row.externalIdentifiers]
      .sort((left, right) => left.namespace.localeCompare(right.namespace))
      .map(mapAssetExternalIdentifier),
    createdAt: asset.createdAt,
  };
}

export function mapAssetTag(row: {
  id: string;
  organizationId: string;
  assetId: string;
  tag: string;
  createdAt: Date;
}): AssetTagRecord {
  return { ...row };
}

export function mapAssetExternalIdentifier(row: {
  id: string;
  organizationId: string;
  assetId: string;
  namespace: string;
  identifier: string;
  createdAt: Date;
}): AssetExternalIdentifierRecord {
  return { ...row };
}

function mapEnvironmentSummary(row: AssetListRow): AssetEnvironmentSummary | null {
  if (
    row.environmentId === null ||
    row.environmentName === null ||
    row.environmentSensitivityClass === null
  ) {
    return null;
  }

  return {
    id: row.environmentId,
    name: row.environmentName,
    sensitivityClass: row.environmentSensitivityClass,
  };
}

function mapOwningTeamSummary(row: AssetListRow): AssetTeamSummary | null {
  if (row.owningTeamId === null || row.owningTeamName === null) {
    return null;
  }

  return { id: row.owningTeamId, name: row.owningTeamName };
}

function mapRelatedEnvironment(
  environment: AssetDetailRelationRow['environment'],
): AssetEnvironmentSummary | null {
  if (environment === null) {
    return null;
  }

  return {
    id: environment.id,
    name: environment.name,
    sensitivityClass: environment.sensitivityClass,
  };
}

function mapRelatedTeam(team: AssetDetailRelationRow['owningTeam']): AssetTeamSummary | null {
  if (team === null) {
    return null;
  }

  return { id: team.id, name: team.name };
}

function mapAssetOwnerView(row: AssetOwnerRelationRow): AssetOwnerView | undefined {
  if (row.teamId !== null) {
    if (row.team === null) {
      return undefined;
    }

    return {
      kind: 'team',
      id: row.id,
      teamId: row.team.id,
      name: row.team.name,
      role: row.role,
    };
  }

  if (row.userId === null || row.membership === null || row.user === null) {
    return undefined;
  }

  return {
    kind: 'membership',
    id: row.id,
    membershipId: row.membership.id,
    userId: row.membership.userId,
    displayName: row.user.displayName,
    role: row.role,
  };
}

function isOwnerView(value: AssetOwnerView | undefined): value is AssetOwnerView {
  return value !== undefined;
}

function sortOwners(owners: readonly AssetOwnerView[]): AssetOwnerView[] {
  return [...owners].sort((left, right) => {
    if (left.kind !== right.kind) {
      return left.kind === 'membership' ? -1 : 1;
    }

    const leftName = left.kind === 'membership' ? left.displayName : left.name;
    const rightName = right.kind === 'membership' ? right.displayName : right.name;
    const byName = leftName.localeCompare(rightName);
    if (byName !== 0) {
      return byName;
    }

    return left.role.localeCompare(right.role);
  });
}

function mapTagValues(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((tag): tag is string => typeof tag === 'string');
}
