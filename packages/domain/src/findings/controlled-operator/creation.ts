/**
 * Controlled Finding creation application.
 * Construction performs no I/O. This module is the only production caller
 * of the creation-authorization issuer. The caller does not receive the handle.
 */

import { randomUUID } from 'node:crypto';

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
  type SealedFindingCreationCommand,
} from '../controlled-creation/authorization.js';
import {
  FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
  type FindingCreationTransactionResult,
} from '../controlled-creation/eligibility.js';
import { parseFindingCreationEvidenceSet } from '../controlled-creation/evidence-set.js';
import {
  FINDING_CREATION_AMBIENT_CLAIMS,
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from '../controlled-creation/policy.js';
import {
  closedRecord,
  isPlainObject,
  readOwnData,
  recordHasAmbientKey,
} from '../controlled-creation/plain.js';
import type { ParsedFindingCreationTrustedContext } from '../controlled-creation/trusted-context.js';
import {
  parseControlledFindingOperatorActor,
  type ControlledFindingOperatorActor,
  type ParsedControlledFindingOperatorActor,
} from './actor.js';
import {
  FINDING_CREATE_CONTROLLED_PERMISSION,
  roleGrantsControlledFindingOperatorPermission,
} from './permissions.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const CONTROLLED_FINDING_CREATION_REQUEST_FIELDS = [
  'assetId',
  'componentId',
  'vulnerabilityId',
  'expectedSbomIngestionId',
  'expectedProductMatchEvidenceIds',
] as const;

const APPLICATION_FAILURES = [
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'not_found',
  'evidence_unavailable',
  'evidence_not_affected',
  'evidence_not_current',
  'evidence_not_eligible',
  'target_mismatch',
  'evidence_set_mismatch',
  'finding_already_exists',
  'immutable_conflict',
  'malformed_persisted_state',
  'transaction_aborted',
  'database_unavailable',
  'internal_failure',
] as const;

type ApplicationFailure = (typeof APPLICATION_FAILURES)[number];

export type ControlledFindingCreationApplicationResult =
  | {
      readonly status: 'created' | 'already_applied';
      readonly findingId: string;
    }
  | {
      readonly status: ApplicationFailure;
    };

export type ControlledFindingCreationPersistencePort = {
  apply(input: {
    readonly trustedContext: ParsedFindingCreationTrustedContext;
    readonly command: SealedFindingCreationCommand;
  }): Promise<FindingCreationTransactionResult>;
};

export type ControlledFindingCreationCorrelationSource = () => string;

export type ControlledFindingCreationApplicationDependencies = {
  readonly persistence: ControlledFindingCreationPersistencePort;
  readonly createCorrelationId?: ControlledFindingCreationCorrelationSource;
};

export type ControlledFindingCreationApplicationInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly request: unknown;
};

type ParsedCreationRequest = {
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly evidenceIds: readonly string[];
};

export function createControlledFindingCreationApplication(
  dependencies: ControlledFindingCreationApplicationDependencies,
) {
  const createCorrelationId = dependencies.createCorrelationId ?? randomUUID;
  const persistence = dependencies.persistence;
  return {
    async execute(
      input: ControlledFindingCreationApplicationInput,
    ): Promise<ControlledFindingCreationApplicationResult> {
      try {
        return await executeCreation(persistence, createCorrelationId, input);
      } catch {
        return failure('internal_failure');
      }
    },
  };
}

async function executeCreation(
  persistence: ControlledFindingCreationPersistencePort,
  createCorrelationId: ControlledFindingCreationCorrelationSource,
  input: ControlledFindingCreationApplicationInput,
): Promise<ControlledFindingCreationApplicationResult> {
  const actor = parseControlledFindingOperatorActor(input.actor);
  if (
    actor === null ||
    !roleGrantsControlledFindingOperatorPermission(actor.role, FINDING_CREATE_CONTROLLED_PERMISSION)
  ) {
    return failure('authority_required');
  }
  const parsed = parseCreationRequest(input.request);
  if (!parsed.ok) {
    return failure(parsed.status);
  }
  const correlationId = readCorrelationId(createCorrelationId);
  if (correlationId === null) {
    return failure('internal_failure');
  }
  const trustedContext = creationTrustedContext(actor);
  const issued = issueFindingCreationAuthorization({
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    assetId: parsed.request.assetId,
    componentId: parsed.request.componentId,
    vulnerabilityId: parsed.request.vulnerabilityId,
    sbomIngestionId: parsed.request.expectedSbomIngestionId,
    productMatchEvidenceIds: [...parsed.request.evidenceIds],
    correlationId,
  });
  if (issued.status !== 'authorized') {
    return authorizationFailure(issued.status);
  }
  const opened = openFindingCreationCommand({
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: parsed.request.assetId,
    expectedComponentId: parsed.request.componentId,
    expectedVulnerabilityId: parsed.request.vulnerabilityId,
    expectedSbomIngestionId: parsed.request.expectedSbomIngestionId,
    expectedProductMatchEvidenceIds: [...parsed.request.evidenceIds],
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    return authorizationFailure(opened.status);
  }
  if (typeof persistence.apply !== 'function') {
    return failure('internal_failure');
  }
  let persisted: unknown;
  try {
    persisted = await persistence.apply({
      trustedContext,
      command: opened.command,
    });
  } catch {
    return failure('internal_failure');
  }
  return boundPersistence(persisted);
}

function parseCreationRequest(
  input: unknown,
):
  | { readonly ok: true; readonly request: ParsedCreationRequest }
  | { readonly ok: false; readonly status: 'invalid_command' | 'authority_rejected' } {
  if (recordHasAmbientKey(input, FINDING_CREATION_AMBIENT_CLAIMS)) {
    return { ok: false, status: 'authority_rejected' };
  }
  if (hasProhibitedField(input)) {
    return { ok: false, status: 'invalid_command' };
  }
  const values = closedRecord(input, CONTROLLED_FINDING_CREATION_REQUEST_FIELDS);
  if (values === null) {
    return { ok: false, status: 'invalid_command' };
  }
  const assetId = values.get('assetId');
  const componentId = values.get('componentId');
  const vulnerabilityId = values.get('vulnerabilityId');
  const expectedSbomIngestionId = values.get('expectedSbomIngestionId');
  if (
    !isUuid(assetId) ||
    !isUuid(componentId) ||
    !isUuid(vulnerabilityId) ||
    !isUuid(expectedSbomIngestionId)
  ) {
    return { ok: false, status: 'invalid_command' };
  }
  const evidence = parseFindingCreationEvidenceSet(values.get('expectedProductMatchEvidenceIds'));
  if (!evidence.ok) {
    return { ok: false, status: 'invalid_command' };
  }
  return {
    ok: true,
    request: {
      assetId,
      componentId,
      vulnerabilityId,
      expectedSbomIngestionId,
      evidenceIds: evidence.evidenceSet.ids,
    },
  };
}

function creationTrustedContext(
  actor: ParsedControlledFindingOperatorActor,
): ParsedFindingCreationTrustedContext {
  return {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: actor.organizationId,
    actorId: actor.userId,
    membershipId: actor.membershipId,
    // Absent membershipStatus is the session-actor contract: active membership
    // resolution already produced the role. The creation transaction reloads
    // that membership. An explicit non-active status never reaches this object.
    membershipStatus: 'active',
  };
}

function readCorrelationId(
  createCorrelationId: ControlledFindingCreationCorrelationSource,
): string | null {
  try {
    const correlationId = createCorrelationId();
    return isUuid(correlationId) ? correlationId : null;
  } catch {
    return null;
  }
}

const SUCCESS_RESULT_FIELDS = [
  'schemaVersion',
  'status',
  'findingId',
  'foreignResourceRevealed',
  'tenantDisclosure',
  'authorityCreated',
  'writesPerformed',
  'observationAdded',
  'auditEventAdded',
  'timestampChanged',
] as const;

function boundPersistence(value: unknown): ControlledFindingCreationApplicationResult {
  if (!isPlainObject(value)) {
    return failure('internal_failure');
  }
  const status = readOwnData(value, 'status');
  if (status === 'created' || status === 'already_applied') {
    const findingId = closedSuccessFindingId(value, status);
    if (findingId === null) {
      return failure('internal_failure');
    }
    return Object.freeze({ status, findingId });
  }
  if (isApplicationFailure(status)) {
    return failure(status);
  }
  return failure('internal_failure');
}

function closedSuccessFindingId(
  value: Record<string, unknown>,
  status: 'created' | 'already_applied',
): string | null {
  const fields = closedRecord(value, SUCCESS_RESULT_FIELDS);
  if (fields === null || fields.get('status') !== status) {
    return null;
  }
  if (fields.get('schemaVersion') !== FINDING_CREATION_TRANSACTION_SCHEMA_VERSION) {
    return null;
  }
  const findingId = fields.get('findingId');
  if (!isUuid(findingId)) {
    return null;
  }
  if (
    fields.get('foreignResourceRevealed') !== false ||
    fields.get('tenantDisclosure') !== 'indistinguishable' ||
    fields.get('authorityCreated') !== false ||
    fields.get('timestampChanged') !== false
  ) {
    return null;
  }
  const created =
    fields.get('writesPerformed') === true &&
    fields.get('observationAdded') === true &&
    fields.get('auditEventAdded') === true;
  const replayed =
    fields.get('writesPerformed') === false &&
    fields.get('observationAdded') === false &&
    fields.get('auditEventAdded') === false;
  if (status === 'created' ? !created : !replayed) {
    return null;
  }
  return findingId;
}

function authorizationFailure(status: string): ControlledFindingCreationApplicationResult {
  if (isApplicationFailure(status)) {
    return failure(status);
  }
  return failure('internal_failure');
}

function failure(status: ApplicationFailure): ControlledFindingCreationApplicationResult {
  return Object.freeze({ status });
}

function isApplicationFailure(value: unknown): value is ApplicationFailure {
  return typeof value === 'string' && (APPLICATION_FAILURES as readonly string[]).includes(value);
}

function hasProhibitedField(input: unknown): boolean {
  if (!isPlainObject(input)) {
    return false;
  }
  const prohibited = new Set<string>(FINDING_CREATION_PROHIBITED_COMMAND_FIELDS);
  return Object.getOwnPropertyNames(input).some((name) => prohibited.has(name));
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
