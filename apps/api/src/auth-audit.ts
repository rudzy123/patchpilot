import { anonymousAuditActorFields, auditActorFields, type TrustedActor } from '@patchpilot/auth';
import type { Logger } from '@patchpilot/logger';
import {
  JSON_SCHEMA_VERSION_V1,
  type AppendAuditEventInput,
  type AuditAppendRepository,
  type AuditPayloadJson,
} from '@patchpilot/domain';

export type AuthAuditOutcome =
  'succeeded' | 'invalid_credentials' | 'rate_limited' | 'unavailable' | 'validation';

function redactedAuthPayload(outcome: AuthAuditOutcome): AuditPayloadJson {
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    metadata: { outcome },
  };
}

export async function appendAuthAudit(
  audit: Pick<AuditAppendRepository, 'append'>,
  logger: Logger,
  input: AppendAuditEventInput,
): Promise<void> {
  try {
    await audit.append(input);
  } catch {
    logger.error(
      {
        event: 'auth.audit_append_failed',
        requestId: input.requestId,
        correlationId: input.correlationId,
        action: input.action,
      },
      'auth audit append failed',
    );
  }
}

export function loginSucceededAuditInput(input: {
  actor: TrustedActor;
  sessionId: string;
  requestId: string;
  correlationId: string;
}): AppendAuditEventInput {
  return {
    actorType: 'user',
    actorUserId: input.actor.userId,
    action: 'auth.login_succeeded',
    subjectType: 'session',
    subjectId: input.sessionId,
    requestId: input.requestId,
    correlationId: input.correlationId,
    payload: redactedAuthPayload('succeeded'),
  };
}

export function loginFailedAuditInput(input: {
  requestId: string;
  correlationId: string;
  outcome: Exclude<AuthAuditOutcome, 'succeeded'>;
}): AppendAuditEventInput {
  return {
    ...anonymousAuditActorFields,
    action: 'auth.login_failed',
    subjectType: 'auth',
    subjectId: input.requestId,
    requestId: input.requestId,
    correlationId: input.correlationId,
    payload: redactedAuthPayload(input.outcome),
  };
}

export function logoutAuditInput(input: {
  sessionId: string;
  userId: string;
  requestId: string;
  correlationId: string;
}): AppendAuditEventInput {
  return {
    actorType: 'user',
    actorUserId: input.userId,
    action: 'auth.logout',
    subjectType: 'session',
    subjectId: input.sessionId,
    requestId: input.requestId,
    correlationId: input.correlationId,
    payload: redactedAuthPayload('succeeded'),
  };
}

export function organizationSelectedAuditInput(input: {
  actor: TrustedActor;
  sessionId: string;
  requestId: string;
  correlationId: string;
}): AppendAuditEventInput {
  return {
    ...auditActorFields(input.actor),
    action: 'auth.organization_selected',
    subjectType: 'session',
    subjectId: input.sessionId,
    requestId: input.requestId,
    correlationId: input.correlationId,
    payload: redactedAuthPayload('succeeded'),
  };
}
