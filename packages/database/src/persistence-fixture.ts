import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';
import type { RepositoryBundle } from '@patchpilot/domain';

export async function persistTenantChangeWithAuditAndOutbox(
  repos: RepositoryBundle,
  input: {
    organizationId: string;
    assetName: string;
    assetType: 'application';
    actorMembershipId: string;
    correlationId: string;
  },
): Promise<{ assetId: string; auditEventId: string; outboxEventId: string }> {
  const asset = await repos.assets.create({
    organizationId: input.organizationId,
    name: input.assetName,
    assetType: input.assetType,
  });

  const audit = await repos.auditEvents.append({
    organizationId: input.organizationId,
    actorMembershipId: input.actorMembershipId,
    actorType: 'user',
    action: 'asset.created',
    subjectType: 'asset',
    subjectId: asset.id,
    correlationId: input.correlationId,
    payload: {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      metadata: {
        name: asset.name,
      },
    },
  });

  const outbox = await repos.outboxEvents.create({
    organizationId: input.organizationId,
    aggregateType: 'asset',
    aggregateId: asset.id,
    eventType: 'asset.created',
    dedupeKey: `asset.created:${asset.id}:${input.correlationId}`,
    payload: {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      ids: {
        assetId: asset.id,
      },
      metadata: {
        reason: 'asset_created',
      },
    },
  });

  return {
    assetId: asset.id,
    auditEventId: audit.id,
    outboxEventId: outbox.id,
  };
}
