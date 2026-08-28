import type {
  AssetOwnerAssignment,
  AssetDetailRecord,
  AssetOwnerView,
  NormalizedUpdateAssetCommand,
} from './types.js';

export const assetScalarUpdateFields = [
  'name',
  'assetType',
  'businessCriticality',
  'internetExposure',
  'dataClassification',
  'environmentId',
  'owningTeamId',
  'description',
  'repositoryUrl',
  'deploymentContext',
] as const;

export type AssetScalarUpdateField = (typeof assetScalarUpdateFields)[number];

export type AssetUpdateDiff = {
  changedScalarFields: readonly AssetScalarUpdateField[];
  scalarChanges: Pick<NormalizedUpdateAssetCommand, AssetScalarUpdateField>;
  ownersChanged: boolean;
  tagsChanged: boolean;
  identifiersChanged: boolean;
};

export function diffAssetUpdate(
  current: AssetDetailRecord,
  command: NormalizedUpdateAssetCommand,
): AssetUpdateDiff {
  const scalarChanges: Pick<NormalizedUpdateAssetCommand, AssetScalarUpdateField> = {};
  const changedScalarFields: AssetScalarUpdateField[] = [];

  addScalarChange(changedScalarFields, scalarChanges, 'name', command.name, current.name);
  addScalarChange(
    changedScalarFields,
    scalarChanges,
    'assetType',
    command.assetType,
    current.assetType,
  );
  addScalarChange(
    changedScalarFields,
    scalarChanges,
    'businessCriticality',
    command.businessCriticality,
    current.businessCriticality,
  );
  addScalarChange(
    changedScalarFields,
    scalarChanges,
    'internetExposure',
    command.internetExposure,
    current.internetExposure,
  );
  addScalarChange(
    changedScalarFields,
    scalarChanges,
    'dataClassification',
    command.dataClassification,
    current.dataClassification,
  );
  addClearableChange(
    changedScalarFields,
    scalarChanges,
    'environmentId',
    command.environmentId,
    current.environment?.id ?? null,
  );
  addClearableChange(
    changedScalarFields,
    scalarChanges,
    'owningTeamId',
    command.owningTeamId,
    current.owningTeam?.id ?? null,
  );
  addClearableChange(
    changedScalarFields,
    scalarChanges,
    'description',
    command.description,
    current.description,
  );
  addClearableChange(
    changedScalarFields,
    scalarChanges,
    'repositoryUrl',
    command.repositoryUrl,
    current.repositoryUrl,
  );
  addClearableChange(
    changedScalarFields,
    scalarChanges,
    'deploymentContext',
    command.deploymentContext,
    current.deploymentContext,
  );

  return {
    changedScalarFields,
    scalarChanges,
    ownersChanged:
      command.owners !== undefined && !sameOwnerAssignments(current.owners, command.owners),
    tagsChanged: command.tags !== undefined && !sameStringSets(current.tags, command.tags),
    identifiersChanged:
      command.externalIdentifiers !== undefined &&
      !sameIdentifiers(current.identifiers, command.externalIdentifiers),
  };
}

export function isNoOpAssetUpdate(diff: AssetUpdateDiff): boolean {
  return (
    diff.changedScalarFields.length === 0 &&
    !diff.ownersChanged &&
    !diff.tagsChanged &&
    !diff.identifiersChanged
  );
}

export function toCompareAndSetCommand(
  expectedVersion: number,
  command: NormalizedUpdateAssetCommand,
  diff: AssetUpdateDiff,
): NormalizedUpdateAssetCommand {
  const next: NormalizedUpdateAssetCommand = {
    expectedVersion,
    ...diff.scalarChanges,
  };

  if (diff.ownersChanged && command.owners !== undefined) {
    next.owners = command.owners;
  }
  if (diff.tagsChanged && command.tags !== undefined) {
    next.tags = command.tags;
  }
  if (diff.identifiersChanged && command.externalIdentifiers !== undefined) {
    next.externalIdentifiers = command.externalIdentifiers;
  }

  return next;
}

function addScalarChange<K extends AssetScalarUpdateField>(
  fields: AssetScalarUpdateField[],
  changes: Pick<NormalizedUpdateAssetCommand, AssetScalarUpdateField>,
  key: K,
  next: NormalizedUpdateAssetCommand[K] | undefined,
  current: NonNullable<NormalizedUpdateAssetCommand[K]>,
): void {
  if (next === undefined || next === current) {
    return;
  }

  fields.push(key);
  (changes as Record<K, NonNullable<NormalizedUpdateAssetCommand[K]>>)[key] = next as NonNullable<
    NormalizedUpdateAssetCommand[K]
  >;
}

function addClearableChange<K extends AssetScalarUpdateField>(
  fields: AssetScalarUpdateField[],
  changes: Pick<NormalizedUpdateAssetCommand, AssetScalarUpdateField>,
  key: K,
  next: NormalizedUpdateAssetCommand[K] | undefined,
  current: string | null,
): void {
  if (next === undefined || next === current) {
    return;
  }

  fields.push(key);
  (changes as Record<K, NormalizedUpdateAssetCommand[K]>)[key] = next;
}

function sameOwnerAssignments(
  current: readonly AssetOwnerView[],
  next: readonly AssetOwnerAssignment[],
): boolean {
  if (current.length !== next.length) {
    return false;
  }

  const currentKeys = new Set(current.map(ownerViewKey));
  return next.every((owner) => currentKeys.has(ownerAssignmentKey(owner)));
}

function sameStringSets(current: readonly string[], next: readonly string[]): boolean {
  if (current.length !== next.length) {
    return false;
  }

  const currentSet = new Set(current);
  return next.every((value) => currentSet.has(value));
}

function sameIdentifiers(
  current: readonly { namespace: string; identifier: string }[],
  next: readonly { namespace: string; identifier: string }[],
): boolean {
  if (current.length !== next.length) {
    return false;
  }

  const currentKeys = new Set(current.map((item) => `${item.namespace}\0${item.identifier}`));
  return next.every((item) => currentKeys.has(`${item.namespace}\0${item.identifier}`));
}

function ownerViewKey(owner: AssetOwnerView): string {
  if (owner.kind === 'membership') {
    return `membership:${owner.membershipId}:${owner.role}`;
  }

  return `team:${owner.teamId}:${owner.role}`;
}

function ownerAssignmentKey(owner: AssetOwnerAssignment): string {
  if (owner.kind === 'membership') {
    return `membership:${owner.membershipId}:${owner.role}`;
  }

  return `team:${owner.teamId}:${owner.role}`;
}
