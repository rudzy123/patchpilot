import { JSON_SCHEMA_VERSION_V1, type AuditPayloadJson } from '../json-documents.js';
import type { AppendAuditEventInput } from '../ports.js';
import type { AuthorizedAssetActor } from './authorization.js';
import type { AssetUpdateDiff } from './diff.js';
import type { AssetDetailRecord } from './types.js';

export const assetAuditActions = {
  created: 'asset.created',
  updated: 'asset.updated',
  archived: 'asset.archived',
  ownersUpdated: 'asset.owners.updated',
  tagsUpdated: 'asset.tags.updated',
  identifiersUpdated: 'asset.identifiers.updated',
} as const;

export const ASSET_AUDIT_SUBJECT_TYPE = 'asset';

export type AssetAuditRequest = {
  correlationId: string;
  requestId?: string;
};

export function assetCreatedAudit(
  actor: AuthorizedAssetActor,
  asset: AssetDetailRecord,
  request: AssetAuditRequest,
  occurredAt: Date,
): AppendAuditEventInput {
  return tenantAssetAudit({
    actor,
    assetId: asset.id,
    action: assetAuditActions.created,
    occurredAt,
    request,
    metadata: {
      assetType: asset.assetType,
      hasEnvironment: asset.environment !== null,
      hasOwningTeam: asset.owningTeam !== null,
      hasDescription: asset.description !== null,
      hasRepositoryUrl: asset.repositoryUrl !== null,
      hasDeploymentContext: asset.deploymentContext !== null,
      ownerCount: asset.owners.length,
      tagCount: asset.tags.length,
      identifierCount: asset.identifiers.length,
    },
  });
}

export function assetUpdatedAudits(
  actor: AuthorizedAssetActor,
  asset: AssetDetailRecord,
  diff: AssetUpdateDiff,
  request: AssetAuditRequest,
  occurredAt: Date,
): AppendAuditEventInput[] {
  const events: AppendAuditEventInput[] = [];
  if (diff.changedScalarFields.length > 0) {
    events.push(
      tenantAssetAudit({
        actor,
        assetId: asset.id,
        action: assetAuditActions.updated,
        occurredAt,
        request,
        metadata: {
          changedFieldCount: diff.changedScalarFields.length,
          changedFields: diff.changedScalarFields.join(','),
        },
      }),
    );
  }

  if (diff.ownersChanged) {
    events.push(
      tenantAssetAudit({
        actor,
        assetId: asset.id,
        action: assetAuditActions.ownersUpdated,
        occurredAt,
        request,
        metadata: { ownerCount: asset.owners.length },
      }),
    );
  }

  if (diff.tagsChanged) {
    events.push(
      tenantAssetAudit({
        actor,
        assetId: asset.id,
        action: assetAuditActions.tagsUpdated,
        occurredAt,
        request,
        metadata: { tagCount: asset.tags.length },
      }),
    );
  }

  if (diff.identifiersChanged) {
    events.push(
      tenantAssetAudit({
        actor,
        assetId: asset.id,
        action: assetAuditActions.identifiersUpdated,
        occurredAt,
        request,
        metadata: { identifierCount: asset.identifiers.length },
      }),
    );
  }

  return events;
}

export function assetArchivedAudit(
  actor: AuthorizedAssetActor,
  asset: AssetDetailRecord,
  request: AssetAuditRequest,
  occurredAt: Date,
): AppendAuditEventInput {
  return tenantAssetAudit({
    actor,
    assetId: asset.id,
    action: assetAuditActions.archived,
    occurredAt,
    request,
    metadata: {
      fromStatus: 'active',
      toStatus: 'archived',
      version: asset.version,
    },
  });
}

function tenantAssetAudit(input: {
  actor: AuthorizedAssetActor;
  assetId: string;
  action: string;
  occurredAt: Date;
  request: AssetAuditRequest;
  metadata: Readonly<Record<string, string | number | boolean | null>>;
}): AppendAuditEventInput {
  const payload: AuditPayloadJson = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    metadata: input.metadata,
  };

  return {
    actorType: 'user',
    actorUserId: input.actor.userId,
    organizationId: input.actor.organizationId,
    actorMembershipId: input.actor.membershipId,
    action: input.action,
    subjectType: ASSET_AUDIT_SUBJECT_TYPE,
    subjectId: input.assetId,
    occurredAt: input.occurredAt,
    correlationId: input.request.correlationId,
    payload,
    ...(input.request.requestId === undefined ? {} : { requestId: input.request.requestId }),
  };
}
