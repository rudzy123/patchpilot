/**
 * Process-local Finding creation authorization.
 * Supported package surface is the `@patchpilot/domain` root export only.
 * This module is not that export. A plain object, JSON value, clone, spread,
 * prototype copy, Proxy, or type assertion is not authority.
 * `issueFindingCreationAuthorization` is the internal issuer. The only
 * production caller is the controlled creation application module. Same-package
 * relative imports can reach it. That is an internal trust boundary, not a
 * supported authority-minting API. This module does not persist a Finding.
 */

import { inspect } from 'node:util';

import { parseFindingCreationCommandFields } from './command.js';
import { evidenceSetsMatch, parseFindingCreationEvidenceSet } from './evidence-set.js';
import {
  FINDING_CREATION_AMBIENT_CLAIMS,
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PRODUCTION_REGISTRATION,
  FINDING_CREATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_ZERO_EFFECTS,
  findingCreationOutcomeExplanation,
  findingCreationOutcomeForReason,
  type FindingCreationAuthorizationOutcome,
  type FindingCreationReason,
} from './policy.js';
import { closedRecord, isHostileProxy, recordHasAmbientKey } from './plain.js';
import {
  parseTrustedFindingCreationContext,
  trustedContextsMatch,
  type ParsedFindingCreationTrustedContext,
} from './trusted-context.js';

const ISSUE_KEYS = [
  'schemaVersion',
  'trustedContext',
  'purpose',
  'policyId',
  'policyVersion',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'sbomIngestionId',
  'productMatchEvidenceIds',
  'correlationId',
] as const;

const PRESENT_KEYS = ['trustedContext', 'command'] as const;

const REUSE_KEYS = ['left', 'right'] as const;

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type AuthorizationSeal = {
  readonly schemaVersion: typeof FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION;
  readonly purpose: typeof FINDING_CREATION_PURPOSE;
  readonly policyId: typeof FINDING_CREATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_CREATION_POLICY_VERSION;
  readonly context: ParsedFindingCreationTrustedContext;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly evidenceSet: {
    readonly ids: readonly string[];
    readonly fingerprint: string;
  };
  readonly correlationId: string;
};

type CommandSeal = {
  readonly authorization: object;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly evidenceSet: AuthorizationSeal['evidenceSet'];
  readonly correlationId: string;
};

const authorizationSeals = new WeakMap<object, AuthorizationSeal>();
const commandSeals = new WeakMap<object, CommandSeal>();

export type FindingCreationAuthorizationHandle = object;

export type SealedFindingCreationCommand = {
  readonly schemaVersion: 'finding_creation_command_v1';
  readonly purpose: typeof FINDING_CREATION_PURPOSE;
  readonly policyId: typeof FINDING_CREATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_CREATION_POLICY_VERSION;
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly expectedProductMatchEvidenceIds: readonly string[];
  readonly correlationId: string;
};

type Operation = 'issue' | 'open' | 'present' | 'reuse';

type Envelope = {
  readonly effects: typeof FINDING_CREATION_ZERO_EFFECTS;
  readonly findingCreation: 'not_performed';
  readonly persistence: 'not_performed';
  readonly productionRegistration: typeof FINDING_CREATION_PRODUCTION_REGISTRATION;
  readonly tenantDisclosure: 'indistinguishable';
  readonly explanation: string;
  readonly authorityRenewed: false;
};

export type FindingCreationDenied = Envelope & {
  readonly status: Exclude<FindingCreationAuthorizationOutcome, 'authorized'>;
  readonly reason: FindingCreationReason;
  readonly operation: Operation;
  readonly continuation: 'stopped';
  readonly processLocalAuthorization: 'not_issued';
  readonly authorityCreated: false;
};

export type FindingCreationIssueResult =
  | FindingCreationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'issue';
      readonly continuation: 'command';
      readonly processLocalAuthorization: 'issued';
      readonly authorityCreated: true;
      readonly authorization: FindingCreationAuthorizationHandle;
    });

export type FindingCreationOpenResult =
  | FindingCreationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'open';
      readonly continuation: 'presentation';
      readonly processLocalAuthorization: 'bound';
      readonly authorityCreated: false;
      readonly command: SealedFindingCreationCommand;
    });

export type FindingCreationPresentationResult =
  | FindingCreationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'present';
      readonly continuation: 'evidence_validation';
      readonly processLocalAuthorization: 'presented';
      readonly authorityCreated: false;
      readonly authorizationReuse: 'repeatable';
    });

export type FindingCreationReuseResult =
  | FindingCreationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'reuse';
      readonly continuation: 'stopped';
      readonly processLocalAuthorization: 'reused' | 'distinct';
      readonly authorityCreated: false;
      readonly classification: 'exact_reuse' | 'distinct_authorization';
    });

/**
 * Same-package issuer. Package entry points do not re-export this function.
 * Calling it mints one process-local authorization. It does not write a Finding.
 */
export function issueFindingCreationAuthorization(input: unknown): FindingCreationIssueResult {
  return guard(denied('internal', 'issue'), () => issueAuthorization(input));
}

export function openFindingCreationCommand(input: unknown): FindingCreationOpenResult {
  return guard(denied('internal', 'open'), () => openCommand(input));
}

export function presentFindingCreationAuthorization(
  input: unknown,
): FindingCreationPresentationResult {
  return guard(denied('internal', 'present'), () => presentAuthorization(input));
}

export function classifyFindingCreationAuthorizationReuse(
  input: unknown,
): FindingCreationReuseResult {
  return guard(denied('internal', 'reuse'), () => classifyReuse(input));
}

function issueAuthorization(input: unknown): FindingCreationIssueResult {
  if (recordHasAmbientKey(input, FINDING_CREATION_AMBIENT_CLAIMS)) {
    return denied('ambient_authority_rejected', 'issue');
  }
  if (hasProhibitedField(input)) {
    return denied('command_rejected', 'issue');
  }
  const values = closedRecord(input, ISSUE_KEYS);
  if (values === null) {
    return denied('command_rejected', 'issue');
  }
  if (values.get('schemaVersion') !== FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION) {
    return denied('schema_mismatch', 'issue');
  }
  if (values.get('purpose') !== FINDING_CREATION_PURPOSE) {
    return denied('purpose_mismatch', 'issue');
  }
  if (
    values.get('policyId') !== FINDING_CREATION_POLICY_ID ||
    !Object.is(values.get('policyVersion'), FINDING_CREATION_POLICY_VERSION)
  ) {
    return denied('policy_mismatch', 'issue');
  }
  const context = parseTrustedFindingCreationContext(values.get('trustedContext'));
  if (!context.ok) {
    return denied(context.reason, 'issue');
  }
  const assetId = values.get('assetId');
  const componentId = values.get('componentId');
  const vulnerabilityId = values.get('vulnerabilityId');
  const sbomIngestionId = values.get('sbomIngestionId');
  const correlationId = values.get('correlationId');
  if (
    !isUuid(assetId) ||
    !isUuid(componentId) ||
    !isUuid(vulnerabilityId) ||
    !isUuid(sbomIngestionId) ||
    !isUuid(correlationId)
  ) {
    return denied('command_rejected', 'issue');
  }
  const evidence = parseFindingCreationEvidenceSet(values.get('productMatchEvidenceIds'));
  if (!evidence.ok) {
    return denied(evidence.reason, 'issue');
  }
  const handle = redactedHandle();
  authorizationSeals.set(handle, {
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    context: context.context,
    assetId,
    componentId,
    vulnerabilityId,
    sbomIngestionId,
    evidenceSet: evidence.evidenceSet,
    correlationId,
  });
  return {
    ...envelope('authorized'),
    explanation: 'process-local creation authorization issued',
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'issue',
    continuation: 'command',
    processLocalAuthorization: 'issued',
    authorityCreated: true,
    authorization: handle,
  };
}

function openCommand(input: unknown): FindingCreationOpenResult {
  const parsed = parseFindingCreationCommandFields(input);
  if (!parsed.ok) {
    return denied(parsed.reason, 'open');
  }
  const seal = authorizationSeals.get(parsed.fields.authorization);
  if (seal === undefined) {
    return denied('authorization_unrecognized', 'open');
  }
  const reason = bindingMismatch(seal, {
    assetId: parsed.fields.expectedAssetId,
    componentId: parsed.fields.expectedComponentId,
    vulnerabilityId: parsed.fields.expectedVulnerabilityId,
    sbomIngestionId: parsed.fields.expectedSbomIngestionId,
    evidenceSet: parsed.fields.evidenceSet,
    correlationId: parsed.fields.correlationId,
  });
  if (reason !== null) {
    return denied(reason, 'open');
  }
  const command = sealedCommand(parsed.fields);
  commandSeals.set(command, {
    authorization: parsed.fields.authorization,
    assetId: parsed.fields.expectedAssetId,
    componentId: parsed.fields.expectedComponentId,
    vulnerabilityId: parsed.fields.expectedVulnerabilityId,
    sbomIngestionId: parsed.fields.expectedSbomIngestionId,
    evidenceSet: parsed.fields.evidenceSet,
    correlationId: parsed.fields.correlationId,
  });
  return {
    ...envelope('authorized'),
    explanation: 'creation command is bound to the authorization',
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'open',
    continuation: 'presentation',
    processLocalAuthorization: 'bound',
    authorityCreated: false,
    command,
  };
}

function presentAuthorization(input: unknown): FindingCreationPresentationResult {
  if (recordHasAmbientKey(input, FINDING_CREATION_AMBIENT_CLAIMS)) {
    return denied('ambient_authority_rejected', 'present');
  }
  const values = closedRecord(input, PRESENT_KEYS);
  if (values === null) {
    return denied('command_rejected', 'present');
  }
  const command = values.get('command');
  if (typeof command !== 'object' || command === null) {
    return denied('authorization_missing', 'present');
  }
  const commandSeal = commandSeals.get(command);
  if (commandSeal === undefined) {
    return denied('authorization_unrecognized', 'present');
  }
  const seal = authorizationSeals.get(commandSeal.authorization);
  if (seal === undefined) {
    return denied('authorization_unrecognized', 'present');
  }
  const context = parseTrustedFindingCreationContext(values.get('trustedContext'));
  if (!context.ok) {
    return denied(context.reason, 'present');
  }
  if (!trustedContextsMatch(context.context, seal.context)) {
    return denied(contextMismatch(context.context, seal.context), 'present');
  }
  const reason = bindingMismatch(seal, commandSeal);
  if (reason !== null) {
    return denied(reason, 'present');
  }
  return {
    ...envelope('authorized'),
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'present',
    continuation: 'evidence_validation',
    processLocalAuthorization: 'presented',
    authorityCreated: false,
    authorizationReuse: 'repeatable',
  };
}

function classifyReuse(input: unknown): FindingCreationReuseResult {
  const values = closedRecord(input, REUSE_KEYS);
  if (values === null) {
    return denied('command_rejected', 'reuse');
  }
  const left = values.get('left');
  const right = values.get('right');
  if (typeof left !== 'object' || left === null || typeof right !== 'object' || right === null) {
    return denied('authorization_missing', 'reuse');
  }
  const leftSeal = authorizationSeals.get(left);
  const rightSeal = authorizationSeals.get(right);
  if (leftSeal === undefined || rightSeal === undefined) {
    return denied('authorization_unrecognized', 'reuse');
  }
  if (left === right) {
    return {
      ...envelope('authorized'),
      explanation: 'exact authorization reuse does not create authority',
      status: 'authorized',
      reason: 'exact_binding',
      operation: 'reuse',
      continuation: 'stopped',
      processLocalAuthorization: 'reused',
      authorityCreated: false,
      classification: 'exact_reuse',
    };
  }
  return {
    ...envelope('authorized'),
    explanation: 'distinct process-local authorizations are not reuse',
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'reuse',
    continuation: 'stopped',
    processLocalAuthorization: 'distinct',
    authorityCreated: false,
    classification: 'distinct_authorization',
  };
}

function bindingMismatch(
  seal: AuthorizationSeal,
  binding: {
    readonly assetId: string;
    readonly componentId: string;
    readonly vulnerabilityId: string;
    readonly sbomIngestionId: string;
    readonly evidenceSet: AuthorizationSeal['evidenceSet'];
    readonly correlationId: string;
  },
): FindingCreationReason | null {
  if (binding.assetId !== seal.assetId) {
    return 'asset_mismatch';
  }
  if (binding.componentId !== seal.componentId) {
    return 'component_mismatch';
  }
  if (binding.vulnerabilityId !== seal.vulnerabilityId) {
    return 'vulnerability_mismatch';
  }
  if (binding.sbomIngestionId !== seal.sbomIngestionId) {
    return 'ingestion_mismatch';
  }
  if (!evidenceSetsMatch(binding.evidenceSet, seal.evidenceSet)) {
    return 'evidence_set_mismatch';
  }
  if (binding.correlationId !== seal.correlationId) {
    return 'correlation_mismatch';
  }
  return null;
}

function contextMismatch(
  presented: ParsedFindingCreationTrustedContext,
  sealed: ParsedFindingCreationTrustedContext,
): FindingCreationReason {
  if (presented.organizationId !== sealed.organizationId) {
    return 'organization_mismatch';
  }
  if (presented.actorId !== sealed.actorId) {
    return 'actor_mismatch';
  }
  return 'membership_mismatch';
}

function defineRedacted(target: object, label: string): void {
  const text = (): string => label;
  Object.defineProperty(target, 'toString', {
    value: text,
    enumerable: false,
  });
  Object.defineProperty(target, 'valueOf', {
    value: text,
    enumerable: false,
  });
  Object.defineProperty(target, Symbol.toPrimitive, {
    value: () => label,
    enumerable: false,
  });
  Object.defineProperty(target, 'toJSON', {
    value: () => ({ classification: 'redacted', reusableAuthority: false as const }),
    enumerable: false,
  });
  Object.defineProperty(target, inspect.custom, {
    value: () => label,
    enumerable: false,
  });
}

function sealedCommand(fields: {
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly evidenceSet: { readonly ids: readonly string[] };
  readonly correlationId: string;
  readonly authorization: object;
}): SealedFindingCreationCommand {
  const command = Object.create(null) as Record<string, unknown>;
  const ids = Object.freeze([...fields.evidenceSet.ids]);
  defineData(command, 'schemaVersion', 'finding_creation_command_v1');
  defineData(command, 'purpose', FINDING_CREATION_PURPOSE);
  defineData(command, 'policyId', FINDING_CREATION_POLICY_ID);
  defineData(command, 'policyVersion', FINDING_CREATION_POLICY_VERSION);
  defineData(command, 'expectedAssetId', fields.expectedAssetId);
  defineData(command, 'expectedComponentId', fields.expectedComponentId);
  defineData(command, 'expectedVulnerabilityId', fields.expectedVulnerabilityId);
  defineData(command, 'expectedSbomIngestionId', fields.expectedSbomIngestionId);
  defineData(command, 'expectedProductMatchEvidenceIds', ids);
  defineData(command, 'correlationId', fields.correlationId);
  Object.defineProperty(command, 'authorization', {
    value: fields.authorization,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  defineRedacted(command, 'FindingCreationCommand { reusableAuthority: false }');
  return Object.freeze(command) as SealedFindingCreationCommand;
}

function defineData(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: false,
    configurable: false,
  });
}

function redactedHandle(): object {
  const handle = Object.create(null) as object;
  defineRedacted(handle, 'FindingCreationAuthorization { reusableAuthority: false }');
  return Object.freeze(handle);
}

function hasProhibitedField(input: unknown): boolean {
  if (typeof input !== 'object' || input === null || isHostileProxy(input)) {
    return false;
  }
  const prohibited = new Set<string>(FINDING_CREATION_PROHIBITED_COMMAND_FIELDS);
  return Object.getOwnPropertyNames(input).some((name) => prohibited.has(name));
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}

function envelope(status: 'authorized'): Envelope {
  return {
    effects: FINDING_CREATION_ZERO_EFFECTS,
    findingCreation: 'not_performed',
    persistence: 'not_performed',
    productionRegistration: FINDING_CREATION_PRODUCTION_REGISTRATION,
    tenantDisclosure: 'indistinguishable',
    explanation: findingCreationOutcomeExplanation(status),
    authorityRenewed: false,
  };
}

function denied(reason: FindingCreationReason, operation: Operation): FindingCreationDenied {
  const status = findingCreationOutcomeForReason(reason);
  if (status === 'authorized') {
    return denied('internal', operation);
  }
  return {
    effects: FINDING_CREATION_ZERO_EFFECTS,
    findingCreation: 'not_performed',
    persistence: 'not_performed',
    productionRegistration: FINDING_CREATION_PRODUCTION_REGISTRATION,
    tenantDisclosure: 'indistinguishable',
    explanation: findingCreationOutcomeExplanation(status),
    authorityRenewed: false,
    status,
    reason,
    operation,
    continuation: 'stopped',
    processLocalAuthorization: 'not_issued',
    authorityCreated: false,
  };
}

function guard<T>(fallback: T, body: () => T): T {
  try {
    return body();
  } catch {
    return fallback;
  }
}
