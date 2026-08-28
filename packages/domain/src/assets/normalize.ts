import { err, ok, type Result } from '../result.js';
import {
  ASSET_DEPLOYMENT_CONTEXT_MAX_LENGTH,
  ASSET_DESCRIPTION_MAX_LENGTH,
  ASSET_IDENTIFIER_MAX_COUNT,
  ASSET_IDENTIFIER_NAMESPACE_MAX_LENGTH,
  ASSET_IDENTIFIER_NAMESPACE_MIN_LENGTH,
  ASSET_IDENTIFIER_VALUE_MAX_LENGTH,
  ASSET_IDENTIFIER_VALUE_MIN_LENGTH,
  ASSET_NAME_MAX_LENGTH,
  ASSET_NAME_MIN_LENGTH,
  ASSET_NAME_PREFIX_MIN_LENGTH,
  ASSET_OWNER_MAX_COUNT,
  ASSET_REPOSITORY_URL_MAX_LENGTH,
  ASSET_SLUG_SHAPE,
  ASSET_TAG_MAX_COUNT,
  ASSET_TAG_MAX_LENGTH,
  ASSET_TAG_MIN_LENGTH,
  DEFAULT_BUSINESS_CRITICALITY,
  DEFAULT_DATA_CLASSIFICATION,
  DEFAULT_INTERNET_EXPOSURE,
} from './constants.js';
import { ASSET_UPDATE_EMPTY, assetValidationError } from './errors.js';
import {
  assetUpdateMutationKeys,
  type AssetOwnerAssignment,
  type AssetUpdateMutationKey,
  type NormalizedCreateAssetCommand,
  type NormalizedExternalIdentifier,
  type NormalizedUpdateAssetCommand,
} from './types.js';

const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type CreateAssetFields = {
  name: string;
  assetType: NormalizedCreateAssetCommand['assetType'];
  businessCriticality?: NormalizedCreateAssetCommand['businessCriticality'] | undefined;
  internetExposure?: NormalizedCreateAssetCommand['internetExposure'] | undefined;
  dataClassification?: NormalizedCreateAssetCommand['dataClassification'] | undefined;
  environmentId?: string | undefined;
  owningTeamId?: string | undefined;
  description?: string | undefined;
  repositoryUrl?: string | undefined;
  deploymentContext?: string | undefined;
  owners?: readonly unknown[] | undefined;
  tags?: readonly unknown[] | undefined;
  externalIdentifiers?: readonly unknown[] | undefined;
};

export type UpdateAssetFields = {
  expectedVersion: number;
  name?: string | undefined;
  assetType?: NormalizedUpdateAssetCommand['assetType'] | undefined;
  businessCriticality?: NormalizedUpdateAssetCommand['businessCriticality'] | undefined;
  internetExposure?: NormalizedUpdateAssetCommand['internetExposure'] | undefined;
  dataClassification?: NormalizedUpdateAssetCommand['dataClassification'] | undefined;
  environmentId?: string | null | undefined;
  owningTeamId?: string | null | undefined;
  description?: string | null | undefined;
  repositoryUrl?: string | null | undefined;
  deploymentContext?: string | null | undefined;
  owners?: readonly unknown[] | undefined;
  tags?: readonly unknown[] | undefined;
  externalIdentifiers?: readonly unknown[] | undefined;
};

export function hasAssetUpdateMutation(input: object): boolean {
  return assetUpdateMutationKeys.some((key) => {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      return false;
    }

    return (input as Record<AssetUpdateMutationKey, unknown>)[key] !== undefined;
  });
}

export function normalizeAssetName(value: string): Result<string> {
  return normalizeRequiredText(value, {
    fieldName: 'Asset name',
    minLength: ASSET_NAME_MIN_LENGTH,
    maxLength: ASSET_NAME_MAX_LENGTH,
    lowerCase: false,
  });
}

export function normalizeAssetNamePrefix(value: string): Result<string> {
  const normalized = normalizeRequiredText(value, {
    fieldName: 'Asset name prefix',
    minLength: ASSET_NAME_PREFIX_MIN_LENGTH,
    maxLength: ASSET_NAME_MAX_LENGTH,
    lowerCase: false,
  });
  if (!normalized.ok) {
    return normalized;
  }

  if (normalized.value.startsWith('%') || normalized.value.startsWith('_')) {
    return err(assetValidationError('Asset name prefix must not start with a wildcard.'));
  }

  return normalized;
}

export function normalizeAssetDescription(value: string): Result<string> {
  return normalizeRequiredText(value, {
    fieldName: 'Asset description',
    minLength: 1,
    maxLength: ASSET_DESCRIPTION_MAX_LENGTH,
    lowerCase: false,
  });
}

export function normalizeAssetDeploymentContext(value: string): Result<string> {
  return normalizeRequiredText(value, {
    fieldName: 'Deployment context',
    minLength: 1,
    maxLength: ASSET_DEPLOYMENT_CONTEXT_MAX_LENGTH,
    lowerCase: false,
  });
}

export function normalizeAssetRepositoryUrl(value: string): Result<string> {
  return normalizeRequiredText(value, {
    fieldName: 'Repository URL',
    minLength: 1,
    maxLength: ASSET_REPOSITORY_URL_MAX_LENGTH,
    lowerCase: false,
  });
}

export function normalizeAssetTag(value: string): Result<string> {
  const normalized = normalizeRequiredText(value, {
    fieldName: 'Asset tag',
    minLength: ASSET_TAG_MIN_LENGTH,
    maxLength: ASSET_TAG_MAX_LENGTH,
    lowerCase: true,
  });
  if (!normalized.ok) {
    return normalized;
  }

  if (!ASSET_SLUG_SHAPE.test(normalized.value)) {
    return err(
      assetValidationError(
        'Asset tag must be lowercase alphanumeric words separated by single hyphens.',
      ),
    );
  }

  return normalized;
}

export function normalizeIdentifierNamespace(value: string): Result<string> {
  const normalized = normalizeRequiredText(value, {
    fieldName: 'External identifier namespace',
    minLength: ASSET_IDENTIFIER_NAMESPACE_MIN_LENGTH,
    maxLength: ASSET_IDENTIFIER_NAMESPACE_MAX_LENGTH,
    lowerCase: true,
  });
  if (!normalized.ok) {
    return normalized;
  }

  if (!ASSET_SLUG_SHAPE.test(normalized.value)) {
    return err(
      assetValidationError(
        'External identifier namespace must be lowercase alphanumeric words separated by single hyphens.',
      ),
    );
  }

  return normalized;
}

export function normalizeIdentifierValue(value: string): Result<string> {
  return normalizeRequiredText(value, {
    fieldName: 'External identifier',
    minLength: ASSET_IDENTIFIER_VALUE_MIN_LENGTH,
    maxLength: ASSET_IDENTIFIER_VALUE_MAX_LENGTH,
    lowerCase: false,
  });
}

export function normalizeAssetTags(values: readonly unknown[]): Result<readonly string[]> {
  if (values.length > ASSET_TAG_MAX_COUNT) {
    return err(assetValidationError(`Asset cannot have more than ${ASSET_TAG_MAX_COUNT} tags.`));
  }

  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== 'string') {
      return err(assetValidationError('Asset tag must be a string.'));
    }

    const tag = normalizeAssetTag(value);
    if (!tag.ok) {
      return tag;
    }

    if (seen.has(tag.value)) {
      continue;
    }

    seen.add(tag.value);
    normalized.push(tag.value);
  }

  if (normalized.length > ASSET_TAG_MAX_COUNT) {
    return err(assetValidationError(`Asset cannot have more than ${ASSET_TAG_MAX_COUNT} tags.`));
  }

  return ok(Object.freeze([...normalized].sort((left, right) => left.localeCompare(right))));
}

export function normalizeAssetOwners(
  values: readonly unknown[],
): Result<readonly AssetOwnerAssignment[]> {
  if (values.length > ASSET_OWNER_MAX_COUNT) {
    return err(
      assetValidationError(`Asset cannot have more than ${ASSET_OWNER_MAX_COUNT} owners.`),
    );
  }

  const owners: AssetOwnerAssignment[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const owner = normalizeAssetOwner(value);
    if (!owner.ok) {
      return owner;
    }

    const duplicateKey = ownerDuplicateKey(owner.value);
    if (seen.has(duplicateKey)) {
      return err(assetValidationError('Asset owner assignments must be unique.'));
    }

    seen.add(duplicateKey);
    owners.push(owner.value);
  }

  return ok(Object.freeze(owners));
}

export function normalizeAssetExternalIdentifiers(
  values: readonly unknown[],
): Result<readonly NormalizedExternalIdentifier[]> {
  if (values.length > ASSET_IDENTIFIER_MAX_COUNT) {
    return err(
      assetValidationError(
        `Asset cannot have more than ${ASSET_IDENTIFIER_MAX_COUNT} external identifiers.`,
      ),
    );
  }

  const identifiers: NormalizedExternalIdentifier[] = [];
  const namespaces = new Set<string>();
  for (const value of values) {
    const identifier = normalizeAssetExternalIdentifier(value);
    if (!identifier.ok) {
      return identifier;
    }

    if (namespaces.has(identifier.value.namespace)) {
      return err(assetValidationError('External identifier namespaces must be unique per asset.'));
    }

    namespaces.add(identifier.value.namespace);
    identifiers.push(identifier.value);
  }

  return ok(Object.freeze(identifiers));
}

export function normalizeCreateAssetCommand(
  input: CreateAssetFields,
): Result<NormalizedCreateAssetCommand> {
  const name = normalizeAssetName(input.name);
  if (!name.ok) {
    return name;
  }

  const environmentId = normalizeOptionalUuid(input.environmentId, 'Environment');
  if (!environmentId.ok) {
    return environmentId;
  }

  const owningTeamId = normalizeOptionalUuid(input.owningTeamId, 'Owning team');
  if (!owningTeamId.ok) {
    return owningTeamId;
  }

  const description = normalizeOptionalTextField(input.description, normalizeAssetDescription);
  if (!description.ok) {
    return description;
  }

  const repositoryUrl = normalizeOptionalTextField(
    input.repositoryUrl,
    normalizeAssetRepositoryUrl,
  );
  if (!repositoryUrl.ok) {
    return repositoryUrl;
  }

  const deploymentContext = normalizeOptionalTextField(
    input.deploymentContext,
    normalizeAssetDeploymentContext,
  );
  if (!deploymentContext.ok) {
    return deploymentContext;
  }

  const owners = normalizeAssetOwners(input.owners ?? []);
  if (!owners.ok) {
    return owners;
  }

  const tags = normalizeAssetTags(input.tags ?? []);
  if (!tags.ok) {
    return tags;
  }

  const externalIdentifiers = normalizeAssetExternalIdentifiers(input.externalIdentifiers ?? []);
  if (!externalIdentifiers.ok) {
    return externalIdentifiers;
  }

  return ok({
    name: name.value,
    assetType: input.assetType,
    businessCriticality: input.businessCriticality ?? DEFAULT_BUSINESS_CRITICALITY,
    internetExposure: input.internetExposure ?? DEFAULT_INTERNET_EXPOSURE,
    dataClassification: input.dataClassification ?? DEFAULT_DATA_CLASSIFICATION,
    owners: owners.value,
    tags: tags.value,
    externalIdentifiers: externalIdentifiers.value,
    ...optionalValue('environmentId', environmentId.value),
    ...optionalValue('owningTeamId', owningTeamId.value),
    ...optionalValue('description', description.value),
    ...optionalValue('repositoryUrl', repositoryUrl.value),
    ...optionalValue('deploymentContext', deploymentContext.value),
  });
}

export function normalizeUpdateAssetCommand(
  input: UpdateAssetFields,
): Result<NormalizedUpdateAssetCommand> {
  if (!hasAssetUpdateMutation(input)) {
    return err(ASSET_UPDATE_EMPTY);
  }

  if (!Number.isInteger(input.expectedVersion) || input.expectedVersion < 1) {
    return err(assetValidationError('expectedVersion must be an integer of at least 1.'));
  }

  const name = normalizeOptionalTextField(input.name, normalizeAssetName);
  if (!name.ok) {
    return name;
  }

  const environmentId = normalizeClearableUuid(input.environmentId, 'Environment');
  if (!environmentId.ok) {
    return environmentId;
  }

  const owningTeamId = normalizeClearableUuid(input.owningTeamId, 'Owning team');
  if (!owningTeamId.ok) {
    return owningTeamId;
  }

  const description = normalizeClearableTextField(input.description, normalizeAssetDescription);
  if (!description.ok) {
    return description;
  }

  const repositoryUrl = normalizeClearableTextField(
    input.repositoryUrl,
    normalizeAssetRepositoryUrl,
  );
  if (!repositoryUrl.ok) {
    return repositoryUrl;
  }

  const deploymentContext = normalizeClearableTextField(
    input.deploymentContext,
    normalizeAssetDeploymentContext,
  );
  if (!deploymentContext.ok) {
    return deploymentContext;
  }

  const owners = input.owners === undefined ? ok(undefined) : normalizeAssetOwners(input.owners);
  if (!owners.ok) {
    return owners;
  }

  const tags = input.tags === undefined ? ok(undefined) : normalizeAssetTags(input.tags);
  if (!tags.ok) {
    return tags;
  }

  const externalIdentifiers =
    input.externalIdentifiers === undefined
      ? ok(undefined)
      : normalizeAssetExternalIdentifiers(input.externalIdentifiers);
  if (!externalIdentifiers.ok) {
    return externalIdentifiers;
  }

  return ok({
    expectedVersion: input.expectedVersion,
    ...optionalValue('name', name.value),
    ...optionalValue('assetType', input.assetType),
    ...optionalValue('businessCriticality', input.businessCriticality),
    ...optionalValue('internetExposure', input.internetExposure),
    ...optionalValue('dataClassification', input.dataClassification),
    ...optionalValue('environmentId', environmentId.value),
    ...optionalValue('owningTeamId', owningTeamId.value),
    ...optionalValue('description', description.value),
    ...optionalValue('repositoryUrl', repositoryUrl.value),
    ...optionalValue('deploymentContext', deploymentContext.value),
    ...optionalValue('owners', owners.value),
    ...optionalValue('tags', tags.value),
    ...optionalValue('externalIdentifiers', externalIdentifiers.value),
  });
}

function normalizeRequiredText(
  value: string,
  options: {
    fieldName: string;
    minLength: number;
    maxLength: number;
    lowerCase: boolean;
  },
): Result<string> {
  const trimmed = value.normalize('NFC').trim();
  if (CONTROL_CHARACTER_PATTERN.test(trimmed)) {
    return err(assetValidationError(`${options.fieldName} must not contain control characters.`));
  }

  const normalized = options.lowerCase ? trimmed.toLowerCase() : trimmed;
  if (normalized.length < options.minLength || normalized.length > options.maxLength) {
    return err(
      assetValidationError(
        `${options.fieldName} must be between ${options.minLength} and ${options.maxLength} characters.`,
      ),
    );
  }

  return ok(normalized);
}

function normalizeOptionalTextField(
  value: string | undefined,
  normalize: (value: string) => Result<string>,
): Result<string | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  return normalize(value);
}

function normalizeClearableTextField(
  value: string | null | undefined,
  normalize: (value: string) => Result<string>,
): Result<string | null | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (value === null) {
    return ok(null);
  }

  return normalize(value);
}

function normalizeOptionalUuid(
  value: string | undefined,
  fieldName: string,
): Result<string | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  return normalizeUuid(value, fieldName);
}

function normalizeClearableUuid(
  value: string | null | undefined,
  fieldName: string,
): Result<string | null | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (value === null) {
    return ok(null);
  }

  return normalizeUuid(value, fieldName);
}

function normalizeUuid(value: string, fieldName: string): Result<string> {
  const trimmed = value.normalize('NFC').trim().toLowerCase();
  if (!UUID_PATTERN.test(trimmed)) {
    return err(assetValidationError(`${fieldName} must be a UUID.`));
  }

  return ok(trimmed);
}

function normalizeAssetOwner(value: unknown): Result<AssetOwnerAssignment> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return err(assetValidationError('Asset owner must be an object.'));
  }

  const record = value as Record<string, unknown>;
  const extraKeys = Object.keys(record).filter(
    (key) => key !== 'kind' && key !== 'membershipId' && key !== 'teamId' && key !== 'role',
  );
  if (extraKeys.length > 0) {
    return err(assetValidationError('Asset owner contains unknown properties.'));
  }

  const role = record['role'];
  if (role !== 'technical' && role !== 'business' && role !== 'security') {
    return err(assetValidationError('Asset owner role is invalid.'));
  }

  if (record['kind'] === 'membership') {
    if (record['teamId'] !== undefined) {
      return err(assetValidationError('Membership owner must not include a teamId.'));
    }

    const membershipId = record['membershipId'];
    if (typeof membershipId !== 'string') {
      return err(assetValidationError('Membership owner requires membershipId.'));
    }

    const id = normalizeUuid(membershipId, 'Membership');
    if (!id.ok) {
      return id;
    }

    return ok({ kind: 'membership', membershipId: id.value, role });
  }

  if (record['kind'] === 'team') {
    if (record['membershipId'] !== undefined) {
      return err(assetValidationError('Team owner must not include a membershipId.'));
    }

    const teamId = record['teamId'];
    if (typeof teamId !== 'string') {
      return err(assetValidationError('Team owner requires teamId.'));
    }

    const id = normalizeUuid(teamId, 'Team');
    if (!id.ok) {
      return id;
    }

    return ok({ kind: 'team', teamId: id.value, role });
  }

  return err(assetValidationError('Asset owner must target a membership or a team.'));
}

function normalizeAssetExternalIdentifier(value: unknown): Result<NormalizedExternalIdentifier> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return err(assetValidationError('External identifier must be an object.'));
  }

  const record = value as Record<string, unknown>;
  const extraKeys = Object.keys(record).filter(
    (key) => key !== 'namespace' && key !== 'identifier',
  );
  if (extraKeys.length > 0) {
    return err(assetValidationError('External identifier contains unknown properties.'));
  }

  const namespaceValue = record['namespace'];
  const identifierValue = record['identifier'];
  if (typeof namespaceValue !== 'string' || typeof identifierValue !== 'string') {
    return err(assetValidationError('External identifier requires namespace and identifier.'));
  }

  const namespace = normalizeIdentifierNamespace(namespaceValue);
  if (!namespace.ok) {
    return namespace;
  }

  const identifier = normalizeIdentifierValue(identifierValue);
  if (!identifier.ok) {
    return identifier;
  }

  return ok({ namespace: namespace.value, identifier: identifier.value });
}

function ownerDuplicateKey(owner: AssetOwnerAssignment): string {
  if (owner.kind === 'membership') {
    return `membership:${owner.membershipId}:${owner.role}`;
  }

  return `team:${owner.teamId}:${owner.role}`;
}

function optionalValue<K extends string, V>(
  key: K,
  value: V | undefined,
): { [P in K]: V } | Record<string, never> {
  if (value === undefined) {
    return {};
  }

  return { [key]: value } as { [P in K]: V };
}
