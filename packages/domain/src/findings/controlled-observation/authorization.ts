/**
 * Process-local repeated-observation authorization.
 * Supported package surface is the `@patchpilot/domain` root export only.
 * This module is not that export. A plain object, JSON value, clone, spread,
 * prototype copy, Proxy, or type assertion is not authority.
 *
 * Package-internal trust assumption: source files inside `packages/domain`
 * can import this module by relative path. That import is not a supported
 * minting API. The issuer is absent from package-root and subpath exports.
 * Architecture tests reject every other production source that names the
 * issuer. API, web, worker, CLI, transport, repository, and generic service
 * code cannot mint authority through supported imports. No test issuer or
 * reset helper is exported. The seal lives in a module-private WeakMap and
 * is not serializable.
 *
 * The issuer has no production caller. This module does not persist an
 * observation or update a Finding.
 */

import { inspect } from 'node:util';

import { parseFindingRepeatedObservationCommandFields } from './command.js';
import {
  FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION,
  FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
  findingRepeatedObservationOutcomeExplanation,
  findingRepeatedObservationOutcomeForReason,
  type FindingRepeatedObservationAuthorizationOutcome,
  type FindingRepeatedObservationReason,
} from './policy.js';
import { closedRecord, isHostileProxy, recordHasAmbientKey } from './plain.js';
import {
  parseFindingRepeatedObservationSupport,
  repeatedObservationSupportsMatch,
  type FindingRepeatedObservationSupport,
} from './support.js';
import {
  parseTrustedFindingRepeatedObservationContext,
  trustedRepeatedObservationContextsMatch,
  type ParsedFindingRepeatedObservationTrustedContext,
} from './trusted-context.js';

const ISSUE_KEYS = [
  'schemaVersion',
  'trustedContext',
  'purpose',
  'policyId',
  'policyVersion',
  'findingId',
  'assetId',
  'componentId',
  'vulnerabilityId',
  'sbomIngestionId',
  'support',
  'correlationId',
] as const;

const PRESENT_KEYS = ['trustedContext', 'command'] as const;

const REUSE_KEYS = ['left', 'right'] as const;

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type AuthorizationSeal = {
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION;
  readonly purpose: typeof FINDING_REPEATED_OBSERVATION_PURPOSE;
  readonly policyId: typeof FINDING_REPEATED_OBSERVATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_REPEATED_OBSERVATION_POLICY_VERSION;
  readonly context: ParsedFindingRepeatedObservationTrustedContext;
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly support: FindingRepeatedObservationSupport;
  readonly correlationId: string;
};

type CommandSeal = {
  readonly authorization: object;
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly support: FindingRepeatedObservationSupport;
  readonly correlationId: string;
};

const authorizationSeals = new WeakMap<object, AuthorizationSeal>();
const commandSeals = new WeakMap<object, CommandSeal>();

export type FindingRepeatedObservationAuthorizationHandle = object;

type SealedCommandBase = {
  readonly schemaVersion: 'finding_repeated_observation_command_v1';
  readonly purpose: typeof FINDING_REPEATED_OBSERVATION_PURPOSE;
  readonly policyId: typeof FINDING_REPEATED_OBSERVATION_POLICY_ID;
  readonly policyVersion: typeof FINDING_REPEATED_OBSERVATION_POLICY_VERSION;
  readonly expectedFindingId: string;
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly correlationId: string;
};

export type SealedFindingRepeatedObservationEvidenceCommand = SealedCommandBase & {
  readonly supportKind: 'evidence_set';
  readonly expectedProductMatchEvidenceIds: readonly string[];
  readonly expectedUnknownVersionOccurrenceIds: readonly string[];
  readonly expectedSupportCount: number;
};

export type SealedFindingRepeatedObservationAbsenceCommand = SealedCommandBase & {
  readonly supportKind: 'component_absence';
  readonly expectedGraphCompleteness: 'complete' | 'no_dependencies';
  readonly expectedComponentCount: number;
  readonly expectedOccurrenceCardinality: number;
  readonly expectedDependencyEdgeCount: number;
  readonly expectedFindingComponentOccurrenceCount: 0;
  readonly expectedNormalizationVersion: 2;
};

export type SealedFindingRepeatedObservationCommand =
  SealedFindingRepeatedObservationEvidenceCommand | SealedFindingRepeatedObservationAbsenceCommand;

type Operation = 'issue' | 'open' | 'present' | 'reuse';

type Envelope = {
  readonly effects: typeof FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS;
  readonly observationWrite: 'not_performed';
  readonly findingMutation: 'not_performed';
  readonly persistence: 'not_performed';
  readonly productionRegistration: typeof FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION;
  readonly tenantDisclosure: 'indistinguishable';
  readonly explanation: string;
  readonly authorityRenewed: false;
  readonly durableAuthority: false;
};

export type FindingRepeatedObservationDenied = Envelope & {
  readonly status: Exclude<FindingRepeatedObservationAuthorizationOutcome, 'authorized'>;
  readonly reason: FindingRepeatedObservationReason;
  readonly operation: Operation;
  readonly continuation: 'stopped';
  readonly processLocalAuthorization: 'not_issued';
  readonly authorityCreated: false;
};

export type FindingRepeatedObservationIssueResult =
  | FindingRepeatedObservationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'issue';
      readonly continuation: 'command';
      readonly processLocalAuthorization: 'issued';
      readonly authorityCreated: true;
      readonly authorization: FindingRepeatedObservationAuthorizationHandle;
    });

export type FindingRepeatedObservationOpenResult =
  | FindingRepeatedObservationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'open';
      readonly continuation: 'presentation';
      readonly processLocalAuthorization: 'bound';
      readonly authorityCreated: false;
      readonly command: SealedFindingRepeatedObservationCommand;
    });

export type FindingRepeatedObservationPresentationResult =
  | FindingRepeatedObservationDenied
  | (Envelope & {
      readonly status: 'authorized';
      readonly reason: 'exact_binding';
      readonly operation: 'present';
      readonly continuation: 'persisted_fact_validation';
      readonly processLocalAuthorization: 'presented';
      readonly authorityCreated: false;
      readonly authorizationReuse: 'repeatable';
      readonly authorizationConsumed: false;
      readonly authorizationExpires: false;
    });

export type FindingRepeatedObservationReuseResult =
  | FindingRepeatedObservationDenied
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
 * Calling it mints one process-local authorization. It does not write an
 * observation, update a Finding, or renew durable authority.
 */
export function issueFindingRepeatedObservationAuthorization(
  input: unknown,
): FindingRepeatedObservationIssueResult {
  return guard(denied('internal', 'issue'), () => issueAuthorization(input));
}

export function openFindingRepeatedObservationCommand(
  input: unknown,
): FindingRepeatedObservationOpenResult {
  return guard(denied('internal', 'open'), () => openCommand(input));
}

export function presentFindingRepeatedObservationAuthorization(
  input: unknown,
): FindingRepeatedObservationPresentationResult {
  return guard(denied('internal', 'present'), () => presentAuthorization(input));
}

export function classifyFindingRepeatedObservationAuthorizationReuse(
  input: unknown,
): FindingRepeatedObservationReuseResult {
  return guard(denied('internal', 'reuse'), () => classifyReuse(input));
}

function issueAuthorization(input: unknown): FindingRepeatedObservationIssueResult {
  if (recordHasAmbientKey(input, FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS)) {
    return denied('ambient_authority_rejected', 'issue');
  }
  const prohibited = prohibitedReason(input);
  if (prohibited !== null) {
    return denied(prohibited, 'issue');
  }
  const values = closedRecord(input, ISSUE_KEYS);
  if (values === null) {
    return denied('command_rejected', 'issue');
  }
  if (values.get('schemaVersion') !== FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION) {
    return denied('schema_mismatch', 'issue');
  }
  if (values.get('purpose') !== FINDING_REPEATED_OBSERVATION_PURPOSE) {
    return denied('purpose_mismatch', 'issue');
  }
  if (
    values.get('policyId') !== FINDING_REPEATED_OBSERVATION_POLICY_ID ||
    !Object.is(values.get('policyVersion'), FINDING_REPEATED_OBSERVATION_POLICY_VERSION)
  ) {
    return denied('policy_mismatch', 'issue');
  }
  const context = parseTrustedFindingRepeatedObservationContext(values.get('trustedContext'));
  if (!context.ok) {
    return denied(context.reason, 'issue');
  }
  const findingId = values.get('findingId');
  const assetId = values.get('assetId');
  const componentId = values.get('componentId');
  const vulnerabilityId = values.get('vulnerabilityId');
  const sbomIngestionId = values.get('sbomIngestionId');
  const correlationId = values.get('correlationId');
  if (
    !isUuid(findingId) ||
    !isUuid(assetId) ||
    !isUuid(componentId) ||
    !isUuid(vulnerabilityId) ||
    !isUuid(sbomIngestionId) ||
    !isUuid(correlationId)
  ) {
    return denied('command_rejected', 'issue');
  }
  const support = parseFindingRepeatedObservationSupport(values.get('support'), sbomIngestionId);
  if (!support.ok) {
    return denied(support.reason, 'issue');
  }
  const handle = redactedHandle();
  authorizationSeals.set(handle, {
    schemaVersion: FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    context: context.context,
    findingId,
    assetId,
    componentId,
    vulnerabilityId,
    sbomIngestionId,
    support: support.support,
    correlationId,
  });
  return {
    ...envelope('authorized'),
    explanation: 'process-local repeated-observation authorization issued',
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'issue',
    continuation: 'command',
    processLocalAuthorization: 'issued',
    authorityCreated: true,
    authorization: handle,
  };
}

function openCommand(input: unknown): FindingRepeatedObservationOpenResult {
  const parsed = parseFindingRepeatedObservationCommandFields(input);
  if (!parsed.ok) {
    return denied(parsed.reason, 'open');
  }
  const seal = authorizationSeals.get(parsed.fields.authorization);
  if (seal === undefined) {
    return denied('authorization_unrecognized', 'open');
  }
  const reason = bindingMismatch(seal, {
    findingId: parsed.fields.expectedFindingId,
    assetId: parsed.fields.expectedAssetId,
    componentId: parsed.fields.expectedComponentId,
    vulnerabilityId: parsed.fields.expectedVulnerabilityId,
    sbomIngestionId: parsed.fields.expectedSbomIngestionId,
    support: parsed.fields.support,
    correlationId: parsed.fields.correlationId,
  });
  if (reason !== null) {
    return denied(reason, 'open');
  }
  const command = sealedCommand(parsed.fields);
  commandSeals.set(command, {
    authorization: parsed.fields.authorization,
    findingId: parsed.fields.expectedFindingId,
    assetId: parsed.fields.expectedAssetId,
    componentId: parsed.fields.expectedComponentId,
    vulnerabilityId: parsed.fields.expectedVulnerabilityId,
    sbomIngestionId: parsed.fields.expectedSbomIngestionId,
    support: parsed.fields.support,
    correlationId: parsed.fields.correlationId,
  });
  return {
    ...envelope('authorized'),
    explanation: 'repeated-observation command is bound to the authorization',
    status: 'authorized',
    reason: 'exact_binding',
    operation: 'open',
    continuation: 'presentation',
    processLocalAuthorization: 'bound',
    authorityCreated: false,
    command,
  };
}

function presentAuthorization(input: unknown): FindingRepeatedObservationPresentationResult {
  if (recordHasAmbientKey(input, FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS)) {
    return denied('ambient_authority_rejected', 'present');
  }
  const values = closedRecord(input, PRESENT_KEYS);
  if (values === null) {
    return denied('command_rejected', 'present');
  }
  const command = values.get('command');
  if (command === null || command === undefined) {
    return denied('authorization_missing', 'present');
  }
  if (typeof command !== 'object' || isHostileProxy(command)) {
    return denied('authorization_unrecognized', 'present');
  }
  const commandSeal = commandSeals.get(command);
  if (commandSeal === undefined) {
    return denied('authorization_unrecognized', 'present');
  }
  const seal = authorizationSeals.get(commandSeal.authorization);
  if (seal === undefined) {
    return denied('authorization_unrecognized', 'present');
  }
  const context = parseTrustedFindingRepeatedObservationContext(values.get('trustedContext'));
  if (!context.ok) {
    return denied(context.reason, 'present');
  }
  if (!trustedRepeatedObservationContextsMatch(context.context, seal.context)) {
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
    continuation: 'persisted_fact_validation',
    processLocalAuthorization: 'presented',
    authorityCreated: false,
    authorizationReuse: 'repeatable',
    authorizationConsumed: false,
    authorizationExpires: false,
  };
}

function classifyReuse(input: unknown): FindingRepeatedObservationReuseResult {
  const values = closedRecord(input, REUSE_KEYS);
  if (values === null) {
    return denied('command_rejected', 'reuse');
  }
  const left = values.get('left');
  const right = values.get('right');
  if (
    typeof left !== 'object' ||
    left === null ||
    isHostileProxy(left) ||
    typeof right !== 'object' ||
    right === null ||
    isHostileProxy(right)
  ) {
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
    readonly findingId: string;
    readonly assetId: string;
    readonly componentId: string;
    readonly vulnerabilityId: string;
    readonly sbomIngestionId: string;
    readonly support: FindingRepeatedObservationSupport;
    readonly correlationId: string;
  },
): FindingRepeatedObservationReason | null {
  if (binding.findingId !== seal.findingId) {
    return 'finding_mismatch';
  }
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
  const supportReason = repeatedObservationSupportsMatch(binding.support, seal.support);
  if (supportReason !== null) {
    return supportReason;
  }
  if (binding.correlationId !== seal.correlationId) {
    return 'correlation_mismatch';
  }
  return null;
}

function contextMismatch(
  presented: ParsedFindingRepeatedObservationTrustedContext,
  sealed: ParsedFindingRepeatedObservationTrustedContext,
): FindingRepeatedObservationReason {
  if (presented.organizationId !== sealed.organizationId) {
    return 'organization_mismatch';
  }
  if (presented.actorId !== sealed.actorId) {
    return 'actor_mismatch';
  }
  return 'membership_mismatch';
}

function sealedCommand(fields: {
  readonly expectedFindingId: string;
  readonly expectedAssetId: string;
  readonly expectedComponentId: string;
  readonly expectedVulnerabilityId: string;
  readonly expectedSbomIngestionId: string;
  readonly support: FindingRepeatedObservationSupport;
  readonly correlationId: string;
  readonly authorization: object;
}): SealedFindingRepeatedObservationCommand {
  const command = Object.create(null) as Record<string, unknown>;
  defineData(command, 'schemaVersion', 'finding_repeated_observation_command_v1');
  defineData(command, 'purpose', FINDING_REPEATED_OBSERVATION_PURPOSE);
  defineData(command, 'policyId', FINDING_REPEATED_OBSERVATION_POLICY_ID);
  defineData(command, 'policyVersion', FINDING_REPEATED_OBSERVATION_POLICY_VERSION);
  defineData(command, 'expectedFindingId', fields.expectedFindingId);
  defineData(command, 'expectedAssetId', fields.expectedAssetId);
  defineData(command, 'expectedComponentId', fields.expectedComponentId);
  defineData(command, 'expectedVulnerabilityId', fields.expectedVulnerabilityId);
  defineData(command, 'expectedSbomIngestionId', fields.expectedSbomIngestionId);
  defineData(command, 'correlationId', fields.correlationId);
  if (fields.support.kind === 'evidence_set') {
    defineData(command, 'supportKind', 'evidence_set');
    defineData(
      command,
      'expectedProductMatchEvidenceIds',
      Object.freeze([...fields.support.productMatchEvidenceIds]),
    );
    defineData(
      command,
      'expectedUnknownVersionOccurrenceIds',
      Object.freeze([...fields.support.unknownVersionOccurrenceIds]),
    );
    defineData(command, 'expectedSupportCount', fields.support.supportCount);
  } else {
    defineData(command, 'supportKind', 'component_absence');
    defineData(command, 'expectedGraphCompleteness', fields.support.graphCompleteness);
    defineData(command, 'expectedComponentCount', fields.support.componentCount);
    defineData(command, 'expectedOccurrenceCardinality', fields.support.occurrenceCardinality);
    defineData(command, 'expectedDependencyEdgeCount', fields.support.dependencyEdgeCount);
    defineData(command, 'expectedFindingComponentOccurrenceCount', 0);
    defineData(command, 'expectedNormalizationVersion', fields.support.normalizationVersion);
  }
  Object.defineProperty(command, 'authorization', {
    value: fields.authorization,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  defineRedacted(command, 'FindingRepeatedObservationCommand { reusableAuthority: false }');
  return Object.freeze(command) as SealedFindingRepeatedObservationCommand;
}

function defineData(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: false,
    configurable: false,
  });
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

function redactedHandle(): object {
  const handle = Object.create(null) as object;
  defineRedacted(handle, 'FindingRepeatedObservationAuthorization { reusableAuthority: false }');
  return Object.freeze(handle);
}

function prohibitedReason(input: unknown): FindingRepeatedObservationReason | null {
  if (typeof input !== 'object' || input === null || isHostileProxy(input)) {
    return null;
  }
  const names = new Set(Object.getOwnPropertyNames(input));
  if (names.has('aggregate') || names.has('observationAggregate')) {
    return 'caller_selected_aggregate';
  }
  if (names.has('observationResult') || names.has('mappedResult') || names.has('result')) {
    return 'caller_selected_result';
  }
  const prohibited = new Set<string>(FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS);
  for (const name of names) {
    if (prohibited.has(name)) {
      return 'command_rejected';
    }
  }
  return null;
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}

function envelope(status: 'authorized'): Envelope {
  return {
    effects: FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
    observationWrite: 'not_performed',
    findingMutation: 'not_performed',
    persistence: 'not_performed',
    productionRegistration: FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION,
    tenantDisclosure: 'indistinguishable',
    explanation: findingRepeatedObservationOutcomeExplanation(status),
    authorityRenewed: false,
    durableAuthority: false,
  };
}

function denied(
  reason: FindingRepeatedObservationReason,
  operation: Operation,
): FindingRepeatedObservationDenied {
  const status = findingRepeatedObservationOutcomeForReason(reason);
  if (status === 'authorized') {
    return denied('internal', operation);
  }
  return {
    effects: FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
    observationWrite: 'not_performed',
    findingMutation: 'not_performed',
    persistence: 'not_performed',
    productionRegistration: FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION,
    tenantDisclosure: 'indistinguishable',
    explanation: findingRepeatedObservationOutcomeExplanation(status),
    authorityRenewed: false,
    durableAuthority: false,
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
