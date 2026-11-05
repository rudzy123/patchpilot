/**
 * Remediation queue read for the actor's organization.
 * The organization comes from the trusted actor. This module does not call
 * the priority engine, assemble facts, or write an audit row.
 * Section order is the adapter's stored-field order.
 * humanReview is a marker. It does not change section order or stored priority.
 */

import {
  closedRecord,
  isPlainObject,
  recordHasAmbientKey,
} from '../findings/controlled-creation/plain.js';
import { parseControlledFindingOperatorActor } from '../findings/controlled-operator/actor.js';
import { assertNever } from '../result.js';
import {
  isAdmittedPriorityPolicyPair,
  type AdmittedPriorityPolicyPair,
} from './admitted-priority-policy.js';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
} from './persistence-port.js';
import { PRIORITY_INSPECT_PERMISSION, roleGrantsPriorityPermission } from './permissions.js';
import { classifyPriorityInputChanges } from './priority-read.js';
import type { FindingPriorityReviewMarker } from './priority-review.js';
import { roleGrantsRemediationQueueRead } from './remediation-queue-permissions.js';
import {
  decodeRemediationQueueCursor,
  encodeRemediationQueueCursor,
  type RemediationQueueCursor,
} from './remediation-queue-cursor.js';
import {
  REMEDIATION_QUEUE_MAX_LIMIT,
  REMEDIATION_QUEUE_SECTIONS,
  type RemediationQueueCalculationFields,
  type RemediationQueueCounts,
  type RemediationQueuePersistencePort,
  type RemediationQueueRawRow,
  type RemediationQueueSection,
} from './remediation-queue-port.js';

export const REMEDIATION_QUEUE_COMPARISON_MESSAGE =
  'recalculation required for comparison' as const;

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DECIMAL_TEXT = /^(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const ENVELOPE_KEYS = ['actor', 'command'] as const;

const COMMAND_KEYS = ['section', 'limit', 'cursor'] as const;

const ENVELOPE_AUTHORITY_KEYS = [
  'organizationId',
  'organization',
  'membershipId',
  'membershipRole',
  'membershipStatus',
  'role',
  'roles',
  'permission',
  'permissions',
  'userId',
  'sessionId',
  'admin',
  'owner',
] as const;

const COMMAND_AUTHORITY_KEYS = [
  'organizationId',
  'organization',
  'actorUserId',
  'membershipId',
  'role',
  'permission',
  'permissions',
] as const;

export type RemediationQueueReference = {
  readonly policyKey: typeof BUILTIN_PRIORITY_POLICY_KEY;
  readonly policyVersion: typeof BUILTIN_PRIORITY_POLICY_VERSION;
  readonly policyDefinitionSha256: string;
  readonly engineVersion: string;
};

export type RemediationQueueRankedRow = {
  readonly findingId: string;
  readonly assetId: string;
  readonly assetName: string;
  readonly componentName: string;
  readonly componentVersion: string;
  readonly vulnerabilityPublicId: string;
  readonly priorityBand: RemediationQueueCalculationFields['priorityBand'];
  readonly priority: number;
  readonly policy: {
    readonly riskPolicyId: string;
    readonly policyKey: string;
    readonly policyVersion: number;
    readonly policyDefinitionSha256: string;
  };
  readonly calculatedAt: string;
  readonly inputsChanged: NonNullable<ReturnType<typeof classifyPriorityInputChanges>>;
  readonly humanReview: FindingPriorityReviewMarker;
};

export type RemediationQueueIncomparableRow = RemediationQueueRankedRow & {
  readonly comparisonMessage: typeof REMEDIATION_QUEUE_COMPARISON_MESSAGE;
};

export type RemediationQueueNotCalculatedRow = {
  readonly findingId: string;
  readonly assetId: string;
  readonly assetName: string;
  readonly componentName: string;
  readonly componentVersion: string;
  readonly vulnerabilityPublicId: string;
  readonly humanReview: FindingPriorityReviewMarker;
};

export type RemediationQueuePage = {
  readonly asOf: string;
  readonly reference: RemediationQueueReference;
  readonly counts: RemediationQueueCounts;
  readonly section: RemediationQueueSection;
  readonly limit: number;
  readonly nextCursor: string | null;
  readonly rows: readonly (
    RemediationQueueRankedRow | RemediationQueueIncomparableRow | RemediationQueueNotCalculatedRow
  )[];
};

export type ReadRemediationQueueDependencies = {
  readonly persistence: Pick<
    RemediationQueuePersistencePort,
    'findPublishedBuiltinPriorityPolicy' | 'readRemediationQueue'
  >;
  readonly admittedPairs: readonly AdmittedPriorityPolicyPair[];
  readonly referenceEngineVersion: string;
  readonly hashPolicyDefinition: (definition: unknown) => string | null;
};

export type ReadRemediationQueueResult =
  | { readonly kind: 'page'; readonly page: RemediationQueuePage }
  | { readonly kind: 'priority_policy_unavailable' }
  | { readonly kind: 'stale_cursor' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'internal_failure' };

export function createReadRemediationQueueUseCase(dependencies: ReadRemediationQueueDependencies) {
  return {
    async execute(input: unknown): Promise<ReadRemediationQueueResult> {
      try {
        return await executeRead(dependencies, input);
      } catch {
        return { kind: 'internal_failure' };
      }
    },
  };
}

async function executeRead(
  dependencies: ReadRemediationQueueDependencies,
  input: unknown,
): Promise<ReadRemediationQueueResult> {
  const command = authorize(input);
  if (!command.ok) {
    return { kind: command.kind };
  }
  if (
    typeof dependencies.persistence.findPublishedBuiltinPriorityPolicy !== 'function' ||
    typeof dependencies.persistence.readRemediationQueue !== 'function' ||
    typeof dependencies.hashPolicyDefinition !== 'function' ||
    dependencies.referenceEngineVersion.length === 0
  ) {
    return { kind: 'internal_failure' };
  }
  const published = await dependencies.persistence.findPublishedBuiltinPriorityPolicy();
  if (published.kind === 'unavailable') {
    return { kind: 'unavailable' };
  }
  if (published.kind === 'not_found') {
    return { kind: 'priority_policy_unavailable' };
  }
  if (published.kind !== 'found') {
    return assertNever(published);
  }
  const admitted = admit(dependencies, published.policy.definition);
  if (
    !admitted.ok ||
    published.policy.policyKey !== BUILTIN_PRIORITY_POLICY_KEY ||
    published.policy.version !== BUILTIN_PRIORITY_POLICY_VERSION
  ) {
    return { kind: 'priority_policy_unavailable' };
  }
  const cursor = readCursor(command.cursor, command.section, admitted.hash, dependencies);
  if (cursor === 'invalid') {
    return { kind: 'invalid_command' };
  }
  if (cursor === 'stale') {
    return { kind: 'stale_cursor' };
  }
  const read = await dependencies.persistence.readRemediationQueue({
    organizationId: command.organizationId,
    section: command.section,
    referencePolicyDefinitionSha256: admitted.hash,
    referenceEngineVersion: dependencies.referenceEngineVersion,
    limit: command.limit,
    cursor,
  });
  if (read.kind === 'policy_absent') {
    return { kind: 'priority_policy_unavailable' };
  }
  if (read.kind === 'malformed' || read.kind === 'unavailable') {
    return { kind: 'unavailable' };
  }
  if (read.kind !== 'page') {
    return assertNever(read);
  }
  const confirmed = admit(dependencies, read.publishedDefinition);
  if (
    !confirmed.ok ||
    confirmed.hash !== admitted.hash ||
    read.publishedPolicyKey !== BUILTIN_PRIORITY_POLICY_KEY ||
    read.publishedPolicyVersion !== BUILTIN_PRIORITY_POLICY_VERSION ||
    !TIMESTAMP.test(read.asOf) ||
    !countsPartition(read.counts, read.findingCount)
  ) {
    return { kind: 'unavailable' };
  }
  const mapped = mapRows(
    read.rows,
    command.section,
    admitted.hash,
    dependencies,
    read.activeKevGenerationId,
  );
  if (mapped === null) {
    return { kind: 'unavailable' };
  }
  if (
    mapped.rows.length > command.limit ||
    (read.hasMore && mapped.rows.length !== command.limit)
  ) {
    return { kind: 'unavailable' };
  }
  let nextCursor: string | null = null;
  if (read.hasMore) {
    if (mapped.last === null) {
      return { kind: 'unavailable' };
    }
    const cursorValue = cursorFor(command.section, admitted.hash, dependencies, mapped.last);
    if (cursorValue === null) {
      return { kind: 'unavailable' };
    }
    nextCursor = encodeRemediationQueueCursor(cursorValue);
  }
  return {
    kind: 'page',
    page: {
      asOf: read.asOf,
      reference: {
        policyKey: BUILTIN_PRIORITY_POLICY_KEY,
        policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
        policyDefinitionSha256: admitted.hash,
        engineVersion: dependencies.referenceEngineVersion,
      },
      counts: read.counts,
      section: command.section,
      limit: command.limit,
      nextCursor,
      rows: mapped.rows,
    },
  };
}

function authorize(input: unknown):
  | {
      readonly ok: true;
      readonly organizationId: string;
      readonly section: RemediationQueueSection;
      readonly limit: number;
      readonly cursor: string | null;
    }
  | { readonly ok: false; readonly kind: 'unauthorized' | 'invalid_command' } {
  if (recordHasAmbientKey(input, ENVELOPE_AUTHORITY_KEYS)) {
    return { ok: false, kind: 'unauthorized' };
  }
  const envelope = closedRecord(input, ENVELOPE_KEYS);
  if (envelope === null) {
    return { ok: false, kind: 'invalid_command' };
  }
  const actor = parseControlledFindingOperatorActor(envelope.get('actor'));
  if (
    actor === null ||
    !roleGrantsRemediationQueueRead(actor.role) ||
    !roleGrantsPriorityPermission(actor.role, PRIORITY_INSPECT_PERMISSION)
  ) {
    return { ok: false, kind: 'unauthorized' };
  }
  const commandRecord = envelope.get('command');
  if (!isPlainObject(commandRecord)) {
    return { ok: false, kind: 'invalid_command' };
  }
  if (recordHasAmbientKey(commandRecord, COMMAND_AUTHORITY_KEYS)) {
    return { ok: false, kind: 'unauthorized' };
  }
  const command = closedRecord(commandRecord, COMMAND_KEYS);
  if (command === null) {
    return { ok: false, kind: 'invalid_command' };
  }
  const section = command.get('section');
  const limit = command.get('limit');
  const cursor = command.get('cursor');
  if (!isSection(section) || !isLimit(limit)) {
    return { ok: false, kind: 'invalid_command' };
  }
  if (cursor !== null && typeof cursor !== 'string') {
    return { ok: false, kind: 'invalid_command' };
  }
  return { ok: true, organizationId: actor.organizationId, section, limit, cursor };
}

function admit(
  dependencies: ReadRemediationQueueDependencies,
  definition: unknown,
): { readonly ok: true; readonly hash: string } | { readonly ok: false } {
  let hash: string | null;
  try {
    hash = dependencies.hashPolicyDefinition(definition);
  } catch {
    return { ok: false };
  }
  if (
    hash === null ||
    !isAdmittedPriorityPolicyPair(
      dependencies.admittedPairs,
      dependencies.referenceEngineVersion,
      hash,
    )
  ) {
    return { ok: false };
  }
  return { ok: true, hash };
}

function readCursor(
  value: string | null,
  section: RemediationQueueSection,
  hash: string,
  dependencies: ReadRemediationQueueDependencies,
): RemediationQueueCursor | null | 'invalid' | 'stale' {
  if (value === null) {
    return null;
  }
  const decoded = decodeRemediationQueueCursor(value);
  if (!decoded.ok) {
    return 'invalid';
  }
  if (
    decoded.cursor.section !== section ||
    decoded.cursor.policyDefinitionSha256 !== hash ||
    decoded.cursor.engineVersion !== dependencies.referenceEngineVersion
  ) {
    return 'stale';
  }
  return decoded.cursor;
}

function mapRows(
  rows: readonly RemediationQueueRawRow[],
  section: RemediationQueueSection,
  hash: string,
  dependencies: ReadRemediationQueueDependencies,
  activeKevGenerationId: string | null,
): {
  readonly rows: readonly RemediationQueuePage['rows'][number][];
  readonly last: RemediationQueueRawRow | null;
} | null {
  const mapped: RemediationQueuePage['rows'][number][] = [];
  let last: RemediationQueueRawRow | null = null;
  for (const row of rows) {
    if (row.section !== section || !identityOk(row)) {
      return null;
    }
    if (section === 'not_calculated') {
      if (
        row.calculation !== null ||
        row.humanReview.status !== 'none' ||
        row.humanReview.priorReviewExists
      ) {
        return null;
      }
      mapped.push({
        findingId: row.findingId,
        assetId: row.assetId,
        assetName: row.assetName,
        componentName: row.componentName,
        componentVersion: row.componentVersion,
        vulnerabilityPublicId: row.vulnerabilityPublicId,
        humanReview: row.humanReview,
      });
      last = row;
      continue;
    }
    if (
      row.calculation === null ||
      !calculationMatches(row.calculation, section, hash, dependencies)
    ) {
      return null;
    }
    const inputsChanged = classifyPriorityInputChanges({
      storedPolicyDefinitionSha256: row.calculation.policyDefinitionSha256,
      publishedPolicyDefinitionSha256: hash,
      storedEngineVersion: row.calculation.calculationEngineVersion,
      referenceEngineVersion: dependencies.referenceEngineVersion,
      storedKevGenerationId: row.calculation.storedKevGenerationId,
      activeKevGenerationId,
      lastObservedAt: new Date(row.calculation.lastObservedAt),
      assetUpdatedAt: new Date(row.calculation.assetUpdatedAt),
      calculatedAt: new Date(row.calculation.calculatedAt),
    });
    if (inputsChanged === null) {
      return null;
    }
    const calculated = {
      findingId: row.findingId,
      assetId: row.assetId,
      assetName: row.assetName,
      componentName: row.componentName,
      componentVersion: row.componentVersion,
      vulnerabilityPublicId: row.vulnerabilityPublicId,
      priorityBand: row.calculation.priorityBand,
      priority: row.calculation.priority,
      policy: {
        riskPolicyId: row.calculation.riskPolicyId,
        policyKey: row.calculation.policyKey,
        policyVersion: row.calculation.policyVersion,
        policyDefinitionSha256: row.calculation.policyDefinitionSha256,
      },
      calculatedAt: row.calculation.calculatedAt,
      inputsChanged,
      humanReview: row.humanReview,
    };
    if (section === 'incomparable') {
      mapped.push({
        ...calculated,
        comparisonMessage: REMEDIATION_QUEUE_COMPARISON_MESSAGE,
      });
    } else {
      mapped.push(calculated);
    }
    last = row;
  }
  return { rows: mapped, last };
}

function cursorFor(
  section: RemediationQueueSection,
  hash: string,
  dependencies: ReadRemediationQueueDependencies,
  row: RemediationQueueRawRow,
): RemediationQueueCursor | null {
  if (section === 'not_calculated') {
    return {
      section,
      policyDefinitionSha256: hash,
      engineVersion: dependencies.referenceEngineVersion,
      firstObservedAt: row.firstObservedAt,
      findingId: row.findingId,
    };
  }
  if (section === 'incomparable' && row.calculation !== null) {
    return {
      section,
      policyDefinitionSha256: hash,
      engineVersion: dependencies.referenceEngineVersion,
      calculatedAt: row.calculation.calculatedAt,
      findingId: row.findingId,
    };
  }
  if (section === 'ranked' && row.calculation !== null) {
    return {
      section,
      policyDefinitionSha256: hash,
      engineVersion: dependencies.referenceEngineVersion,
      priorityText: row.calculation.priorityText,
      escalationRecommended: row.calculation.escalationRecommended,
      kevListed: row.calculation.kevListed,
      severityText: row.calculation.severityText,
      firstObservedAt: row.firstObservedAt,
      findingId: row.findingId,
    };
  }
  return null;
}

function identityOk(row: RemediationQueueRawRow): boolean {
  return (
    UUID_LOWER.test(row.findingId) &&
    UUID_LOWER.test(row.assetId) &&
    TIMESTAMP.test(row.firstObservedAt) &&
    row.assetName.length > 0 &&
    row.assetName.length <= 200 &&
    row.componentName.length > 0 &&
    row.componentName.length <= 512 &&
    row.componentVersion.length > 0 &&
    row.componentVersion.length <= 256 &&
    row.vulnerabilityPublicId.length > 0 &&
    row.vulnerabilityPublicId.length <= 128
  );
}

function calculationMatches(
  calculation: RemediationQueueCalculationFields,
  section: RemediationQueueSection,
  hash: string,
  dependencies: ReadRemediationQueueDependencies,
): boolean {
  const comparable =
    calculation.policyKey === BUILTIN_PRIORITY_POLICY_KEY &&
    calculation.policyDefinitionSha256 === hash &&
    calculation.calculationEngineVersion === dependencies.referenceEngineVersion;
  if (section === 'ranked' && !comparable) {
    return false;
  }
  if (section === 'incomparable' && comparable) {
    return false;
  }
  if (
    calculation.priorityBand !== 'P1' &&
    calculation.priorityBand !== 'P2' &&
    calculation.priorityBand !== 'P3' &&
    calculation.priorityBand !== 'P4'
  ) {
    return false;
  }
  return (
    UUID_LOWER.test(calculation.riskPolicyId) &&
    SHA256_HEX.test(calculation.policyDefinitionSha256) &&
    TIMESTAMP.test(calculation.calculatedAt) &&
    TIMESTAMP.test(calculation.lastObservedAt) &&
    TIMESTAMP.test(calculation.assetUpdatedAt) &&
    DECIMAL_TEXT.test(calculation.priorityText) &&
    Number(calculation.priorityText) === calculation.priority &&
    DECIMAL_TEXT.test(calculation.severityText) &&
    Number(calculation.severityText) === calculation.severityPercent &&
    Number.isInteger(calculation.policyVersion) &&
    calculation.policyVersion > 0 &&
    calculation.calculationEngineVersion.length > 0 &&
    calculation.calculationEngineVersion.length <= 64 &&
    calculation.policyKey.length > 0 &&
    calculation.policyKey.length <= 128
  );
}

function countsPartition(counts: RemediationQueueCounts, findingCount: number): boolean {
  return (
    Number.isSafeInteger(counts.ranked) &&
    Number.isSafeInteger(counts.incomparable) &&
    Number.isSafeInteger(counts.not_calculated) &&
    Number.isSafeInteger(findingCount) &&
    counts.ranked >= 0 &&
    counts.incomparable >= 0 &&
    counts.not_calculated >= 0 &&
    counts.ranked + counts.incomparable + counts.not_calculated === findingCount
  );
}

function isSection(value: unknown): value is RemediationQueueSection {
  return (
    typeof value === 'string' && (REMEDIATION_QUEUE_SECTIONS as readonly string[]).includes(value)
  );
}

function isLimit(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= REMEDIATION_QUEUE_MAX_LIMIT
  );
}
