import type { AssetDetail } from '@patchpilot/contracts';

export const ASSET_TYPE_OPTIONS = [
  { value: 'application', label: 'Application' },
  { value: 'service', label: 'Service' },
  { value: 'library', label: 'Library' },
  { value: 'container_image', label: 'Container image' },
  { value: 'other', label: 'Other' },
] as const;

export const BUSINESS_CRITICALITY_OPTIONS = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
] as const;

export const INTERNET_EXPOSURE_OPTIONS = [
  { value: 'unknown', label: 'Unknown' },
  { value: 'internal', label: 'Internal' },
  { value: 'internet_facing', label: 'Internet facing' },
] as const;

export const DATA_CLASSIFICATION_OPTIONS = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'public', label: 'Public' },
  { value: 'internal', label: 'Internal' },
  { value: 'confidential', label: 'Confidential' },
  { value: 'restricted', label: 'Restricted' },
] as const;

export const OWNER_ROLE_OPTIONS = [
  { value: 'technical', label: 'Technical' },
  { value: 'business', label: 'Business' },
  { value: 'security', label: 'Security' },
] as const;

export const ASSET_TAG_MAX_COUNT = 20;
export const ASSET_IDENTIFIER_MAX_COUNT = 20;
export const ASSET_OWNER_MAX_COUNT = 20;

export type AssetFormOwner =
  | { kind: 'membership'; membershipId: string; role: 'technical' | 'business' | 'security' }
  | { kind: 'team'; teamId: string; role: 'technical' | 'business' | 'security' };

export type AssetFormValues = {
  name: string;
  assetType: string;
  environmentId: string;
  owningTeamId: string;
  description: string;
  businessCriticality: string;
  internetExposure: string;
  dataClassification: string;
  repositoryUrl: string;
  deploymentContext: string;
  owners: AssetFormOwner[];
  tags: string[];
  identifiers: Array<{ namespace: string; identifier: string }>;
};

export type FieldError = {
  id: string;
  message: string;
};

export const emptyAssetFormValues: AssetFormValues = {
  name: '',
  assetType: '',
  environmentId: '',
  owningTeamId: '',
  description: '',
  businessCriticality: 'unspecified',
  internetExposure: 'unknown',
  dataClassification: 'unspecified',
  repositoryUrl: '',
  deploymentContext: '',
  owners: [],
  tags: [],
  identifiers: [],
};

export function valuesFromAsset(asset: AssetDetail): AssetFormValues {
  return {
    name: asset.name,
    assetType: asset.assetType,
    environmentId: asset.environment?.id ?? '',
    owningTeamId: asset.owningTeam?.id ?? '',
    description: asset.description ?? '',
    businessCriticality: asset.businessCriticality,
    internetExposure: asset.internetExposure,
    dataClassification: asset.dataClassification,
    repositoryUrl: asset.repositoryUrl ?? '',
    deploymentContext: asset.deploymentContext ?? '',
    owners: asset.owners.map((owner) =>
      owner.kind === 'membership'
        ? { kind: 'membership', membershipId: owner.membershipId, role: owner.role }
        : { kind: 'team', teamId: owner.teamId, role: owner.role },
    ),
    tags: [...asset.tags],
    identifiers: asset.externalIdentifiers.map((item) => ({
      namespace: item.namespace,
      identifier: item.identifier,
    })),
  };
}

export function validateAssetForm(values: AssetFormValues): FieldError[] {
  const errors: FieldError[] = [];
  if (values.name.trim().length === 0) {
    errors.push({ id: 'asset-name', message: 'Enter a name' });
  }
  if (!ASSET_TYPE_OPTIONS.some((option) => option.value === values.assetType)) {
    errors.push({ id: 'asset-type', message: 'Select an asset type' });
  }
  return errors;
}

export function toCreateBody(values: AssetFormValues): Record<string, unknown> {
  const body: Record<string, unknown> = {
    name: values.name.trim(),
    assetType: values.assetType,
  };
  if (values.environmentId.length > 0) {
    body['environmentId'] = values.environmentId;
  }
  if (values.owningTeamId.length > 0) {
    body['owningTeamId'] = values.owningTeamId;
  }
  if (values.description.trim().length > 0) {
    body['description'] = values.description;
  }
  if (values.businessCriticality.length > 0) {
    body['businessCriticality'] = values.businessCriticality;
  }
  if (values.internetExposure.length > 0) {
    body['internetExposure'] = values.internetExposure;
  }
  if (values.dataClassification.length > 0) {
    body['dataClassification'] = values.dataClassification;
  }
  if (values.repositoryUrl.trim().length > 0) {
    body['repositoryUrl'] = values.repositoryUrl;
  }
  if (values.deploymentContext.trim().length > 0) {
    body['deploymentContext'] = values.deploymentContext;
  }
  if (values.owners.length > 0) {
    body['owners'] = values.owners;
  }
  if (values.tags.length > 0) {
    body['tags'] = values.tags;
  }
  if (values.identifiers.length > 0) {
    body['externalIdentifiers'] = values.identifiers;
  }
  return body;
}

export function toUpdateBody(values: AssetFormValues, expectedVersion: number): Record<string, unknown> {
  return {
    expectedVersion,
    name: values.name.trim(),
    assetType: values.assetType,
    environmentId: values.environmentId.length > 0 ? values.environmentId : null,
    owningTeamId: values.owningTeamId.length > 0 ? values.owningTeamId : null,
    description: values.description.trim().length > 0 ? values.description : null,
    businessCriticality: values.businessCriticality,
    internetExposure: values.internetExposure,
    dataClassification: values.dataClassification,
    repositoryUrl: values.repositoryUrl.trim().length > 0 ? values.repositoryUrl : null,
    deploymentContext: values.deploymentContext.trim().length > 0 ? values.deploymentContext : null,
    owners: values.owners,
    tags: values.tags,
    externalIdentifiers: values.identifiers,
  };
}

export function catalogLabel(
  options: ReadonlyArray<{ value: string; label: string }>,
  value: string,
): string {
  return options.find((option) => option.value === value)?.label ?? value;
}

