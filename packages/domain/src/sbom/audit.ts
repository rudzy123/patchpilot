import { JSON_SCHEMA_VERSION_V1, type AuditPayloadJson } from '../json-documents.js';
import type { AppendAuditEventInput } from '../ports.js';
import type { AuthorizedSbomUploadActor } from './authorization.js';
import { SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION } from './constants.js';

export const sbomAuditActions = {
  uploaded: 'sbom.uploaded',
  duplicate: 'sbom.duplicate',
} as const;

export const SBOM_AUDIT_SUBJECT_TYPE = 'sbom';

export type SbomUploadAuditRequest = {
  correlationId: string;
  requestId?: string;
};

export type SbomUploadAuditMetadata = {
  assetId: string;
  sbomId: string;
  ingestionId: string;
  byteLength: number;
  sha256: string;
  declaredContentType: string;
  parserVersion: string;
};

export function sbomUploadedAudit(
  actor: AuthorizedSbomUploadActor,
  metadata: SbomUploadAuditMetadata,
  request: SbomUploadAuditRequest,
  occurredAt: Date,
): AppendAuditEventInput {
  return tenantSbomAudit({
    actor,
    action: sbomAuditActions.uploaded,
    subjectId: metadata.sbomId,
    metadata,
    request,
    occurredAt,
  });
}

export function sbomDuplicateAudit(
  actor: AuthorizedSbomUploadActor,
  metadata: SbomUploadAuditMetadata,
  request: SbomUploadAuditRequest,
  occurredAt: Date,
): AppendAuditEventInput {
  return tenantSbomAudit({
    actor,
    action: sbomAuditActions.duplicate,
    subjectId: metadata.sbomId,
    metadata,
    request,
    occurredAt,
  });
}

function tenantSbomAudit(input: {
  actor: AuthorizedSbomUploadActor;
  action: string;
  subjectId: string;
  metadata: SbomUploadAuditMetadata;
  request: SbomUploadAuditRequest;
  occurredAt: Date;
}): AppendAuditEventInput {
  const payload: AuditPayloadJson = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    metadata: {
      schemaVersion: SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
      assetId: input.metadata.assetId,
      sbomId: input.metadata.sbomId,
      ingestionId: input.metadata.ingestionId,
      byteLength: input.metadata.byteLength,
      sha256: input.metadata.sha256,
      declaredContentType: input.metadata.declaredContentType,
      parserVersion: input.metadata.parserVersion,
    },
  };

  return {
    actorType: 'user',
    actorUserId: input.actor.userId,
    organizationId: input.actor.organizationId,
    actorMembershipId: input.actor.membershipId,
    action: input.action,
    subjectType: SBOM_AUDIT_SUBJECT_TYPE,
    subjectId: input.subjectId,
    occurredAt: input.occurredAt,
    correlationId: input.request.correlationId,
    payload,
    ...(input.request.requestId === undefined ? {} : { requestId: input.request.requestId }),
  };
}
