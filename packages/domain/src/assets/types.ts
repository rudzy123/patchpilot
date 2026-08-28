import type {
  AssetDataClassification,
  AssetLifecycleStatus,
  AssetOwnerRole,
  AssetType,
  BusinessCriticality,
  EnvironmentSensitivityClass,
  InternetExposure,
  MembershipRole,
} from '../lifecycle.js';
import type { AssetExternalIdentifierRecord, AssetRecord, AssetTagRecord } from '../records.js';

export type AssetLifecycleListFilter = AssetLifecycleStatus | 'all';

export type AssetEnvironmentSummary = {
  id: string;
  name: string;
  sensitivityClass: EnvironmentSensitivityClass;
};

export type AssetTeamSummary = {
  id: string;
  name: string;
};

export type MembershipAssetOwnerAssignment = {
  kind: 'membership';
  membershipId: string;
  role: AssetOwnerRole;
};

export type TeamAssetOwnerAssignment = {
  kind: 'team';
  teamId: string;
  role: AssetOwnerRole;
};

export type AssetOwnerAssignment = MembershipAssetOwnerAssignment | TeamAssetOwnerAssignment;

export type NormalizedExternalIdentifier = {
  namespace: string;
  identifier: string;
};

export type MembershipAssetOwnerView = {
  kind: 'membership';
  id: string;
  membershipId: string;
  userId: string;
  displayName: string;
  role: AssetOwnerRole;
};

export type TeamAssetOwnerView = {
  kind: 'team';
  id: string;
  teamId: string;
  name: string;
  role: AssetOwnerRole;
};

export type AssetOwnerView = MembershipAssetOwnerView | TeamAssetOwnerView;

export type AssetSummaryRecord = {
  id: string;
  organizationId: string;
  name: string;
  assetType: AssetType;
  lifecycleStatus: AssetLifecycleStatus;
  environment: AssetEnvironmentSummary | null;
  owningTeam: AssetTeamSummary | null;
  businessCriticality: BusinessCriticality;
  internetExposure: InternetExposure;
  dataClassification: AssetDataClassification;
  tags: readonly string[];
  lastObservedAt: Date | null;
  version: number;
  updatedAt: Date;
};

export type AssetDetailRecord = AssetSummaryRecord & {
  description: string | null;
  repositoryUrl: string | null;
  deploymentContext: string | null;
  lastSuccessfulSbomIngestionId: string | null;
  lastSuccessfulSbomIngestionAt: Date | null;
  archivedAt: Date | null;
  owners: readonly AssetOwnerView[];
  identifiers: readonly AssetExternalIdentifierRecord[];
  createdAt: Date;
};

export type AssetListCursor = {
  v: 1;
  n: string;
  i: string;
};

export type AssetListQuery = {
  limit: number;
  lifecycleStatus: AssetLifecycleListFilter;
  cursor?: AssetListCursor;
  environmentId?: string;
  assetType?: AssetType;
  businessCriticality?: BusinessCriticality;
  internetExposure?: InternetExposure;
  owningTeamId?: string;
  tag?: string;
  namePrefix?: string;
};

export type AssetEnvironmentOption = {
  id: string;
  name: string;
  slug: string;
  sensitivityClass: EnvironmentSensitivityClass;
};

export type AssetTeamOption = {
  id: string;
  name: string;
  slug: string;
};

export type AssetMembershipOption = {
  membershipId: string;
  displayName: string;
  role: MembershipRole;
};

export type AssetListPage = {
  items: AssetSummaryRecord[];
  nextCursor: AssetListCursor | undefined;
};

export type AssetCompareAndSetOutcome<T = AssetDetailRecord> =
  | { kind: 'updated'; asset: T }
  | { kind: 'not_found' }
  | { kind: 'version_conflict'; asset: T }
  | { kind: 'archived'; asset: T };

export type NormalizedCreateAssetCommand = {
  name: string;
  assetType: AssetType;
  businessCriticality: BusinessCriticality;
  internetExposure: InternetExposure;
  dataClassification: AssetDataClassification;
  environmentId?: string;
  owningTeamId?: string;
  description?: string;
  repositoryUrl?: string;
  deploymentContext?: string;
  owners: readonly AssetOwnerAssignment[];
  tags: readonly string[];
  externalIdentifiers: readonly NormalizedExternalIdentifier[];
};

export type NormalizedUpdateAssetCommand = {
  expectedVersion: number;
  name?: string;
  assetType?: AssetType;
  businessCriticality?: BusinessCriticality;
  internetExposure?: InternetExposure;
  dataClassification?: AssetDataClassification;
  environmentId?: string | null;
  owningTeamId?: string | null;
  description?: string | null;
  repositoryUrl?: string | null;
  deploymentContext?: string | null;
  owners?: readonly AssetOwnerAssignment[];
  tags?: readonly string[];
  externalIdentifiers?: readonly NormalizedExternalIdentifier[];
};

export const assetUpdateMutationKeys = [
  'name',
  'assetType',
  'environmentId',
  'owningTeamId',
  'description',
  'businessCriticality',
  'internetExposure',
  'dataClassification',
  'repositoryUrl',
  'deploymentContext',
  'owners',
  'tags',
  'externalIdentifiers',
] as const;

export type AssetUpdateMutationKey = (typeof assetUpdateMutationKeys)[number];

/** Persistence root plus related rows; not a Prisma type. */
export type AssetAggregateRecord = {
  asset: AssetRecord;
  tags: readonly AssetTagRecord[];
  identifiers: readonly AssetExternalIdentifierRecord[];
  owners: readonly AssetOwnerView[];
  environment: AssetEnvironmentSummary | null;
  owningTeam: AssetTeamSummary | null;
};
