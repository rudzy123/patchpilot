/**
 * Append-only human review of one immutable RiskCalculation.
 * The organization comes from the trusted actor. A review does not change
 * the calculated priority, the Finding, or queue order.
 * This module does not import Prisma, Fastify, or the policy engine.
 */

import { JSON_SCHEMA_VERSION_V1 } from '../json-documents.js';
import {
  closedRecord,
  isPlainObject,
  recordHasAmbientKey,
} from '../findings/controlled-creation/plain.js';
import { parseControlledFindingOperatorActor } from '../findings/controlled-operator/actor.js';
import { assertNever } from '../result.js';
import { PRIORITY_BANDS, type PriorityBand } from './catalog.js';
import {
  PRIORITY_REVIEW_CONTROLLED_PERMISSION,
  roleGrantsPriorityPermission,
} from './permissions.js';

const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ENVELOPE_KEYS = ['actor', 'command'] as const;

const COMMAND_KEYS = [
  'findingId',
  'riskCalculationId',
  'supersedesReviewId',
  'decision',
  'correctedBand',
  'expiresAt',
  'reason',
  'correlationId',
] as const;

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

export const PRIORITY_REVIEW_DECISIONS = ['accepted', 'corrected', 'withdrawn'] as const;

export type PriorityReviewDecision = (typeof PRIORITY_REVIEW_DECISIONS)[number];

export const PRIORITY_REVIEW_SUBJECT_TYPE = 'risk_calculation_review' as const;

export const PRIORITY_REVIEW_AUDIT_ACTIONS = Object.freeze({
  accepted: 'priority.review_accepted',
  corrected: 'priority.review_corrected',
  withdrawn: 'priority.review_withdrawn',
} as const);

export const FINDING_PRIORITY_REVIEW_NONE = Object.freeze({
  status: 'none' as const,
  priorReviewExists: false as const,
});

export type FindingPriorityReviewNone = typeof FINDING_PRIORITY_REVIEW_NONE;

export type FindingPriorityReviewMarker =
  | FindingPriorityReviewNone
  | {
      readonly status: 'none_for_current_calculation';
      readonly priorReviewExists: true;
    }
  | {
      readonly status: 'accepted';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
    }
  | {
      readonly status: 'withdrawn';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
    }
  | {
      readonly status: 'corrected';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly correctedBand: PriorityBand;
      readonly expiresAt: string;
    }
  | {
      readonly status: 'expired';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly correctedBand: PriorityBand;
      readonly expiresAt: string;
    };

export type FindingPriorityReview =
  | FindingPriorityReviewNone
  | {
      readonly status: 'none_for_current_calculation';
      readonly priorReviewExists: true;
    }
  | {
      readonly status: 'accepted';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly reason: string | null;
    }
  | {
      readonly status: 'withdrawn';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly reason: string;
    }
  | {
      readonly status: 'corrected';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly correctedBand: PriorityBand;
      readonly expiresAt: string;
      readonly reason: string;
    }
  | {
      readonly status: 'expired';
      readonly priorReviewExists: boolean;
      readonly reviewId: string;
      readonly correctedBand: PriorityBand;
      readonly expiresAt: string;
      readonly reason: string;
    };

export type StoredPriorityReviewHead = {
  readonly reviewId: string;
  readonly decision: PriorityReviewDecision;
  readonly correctedBand: PriorityBand | null;
  readonly expiresAt: Date | null;
};

export type PriorityReviewProjectionInput = {
  readonly asOf: Date;
  readonly priorReviewExists: boolean;
  readonly head: StoredPriorityReviewHead | null;
  readonly reason?: string | null;
};

export type RecordPriorityReviewCommand = {
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly findingId: string;
  readonly riskCalculationId: string;
  readonly supersedesReviewId: string | null;
  readonly decision: PriorityReviewDecision;
  readonly correctedBand: PriorityBand | null;
  readonly expiresAt: Date | null;
  readonly reason: string | null;
  readonly correlationId: string;
};

export type RecordPriorityReviewPersistenceResult =
  | {
      readonly kind: 'recorded' | 'already_applied';
      readonly reviewId: string;
      readonly findingId: string;
      readonly riskCalculationId: string;
    }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'calculation_not_current' }
  | { readonly kind: 'review_not_current' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'unavailable' };

export type PriorityReviewPersistencePort = {
  readonly recordPriorityReview: (
    command: RecordPriorityReviewCommand,
  ) => Promise<RecordPriorityReviewPersistenceResult>;
};

export type RecordPriorityReviewResult =
  | {
      readonly kind: 'recorded' | 'already_applied';
      readonly reviewId: string;
      readonly findingId: string;
      readonly riskCalculationId: string;
    }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'calculation_not_current' }
  | { readonly kind: 'review_not_current' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'invalid_command' }
  | { readonly kind: 'unavailable' };

export type PriorityReviewAuditPayload = {
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  readonly reviewId: string;
  readonly findingId: string;
  readonly riskCalculationId: string;
  readonly decision: PriorityReviewDecision;
  readonly correctedBand: PriorityBand | null;
  readonly expiresAt: string | null;
  readonly supersedesReviewId: string | null;
  readonly reasonLength: number;
};

const AUDIT_KEYS = [
  'schemaVersion',
  'reviewId',
  'findingId',
  'riskCalculationId',
  'decision',
  'correctedBand',
  'expiresAt',
  'supersedesReviewId',
  'reasonLength',
] as const;

export function normalizePriorityReviewReason(value: string): string | null {
  if (value.includes('\u0000')) {
    return null;
  }
  const normalized = value.normalize('NFC');
  if (normalized.length < 1 || normalized.length > 2000 || normalized.includes('\u0000')) {
    return null;
  }
  return normalized;
}

export function projectPriorityReviewMarker(
  input: PriorityReviewProjectionInput,
): FindingPriorityReviewMarker | null {
  if (!Number.isFinite(input.asOf.getTime())) {
    return null;
  }
  if (input.head === null) {
    if (input.priorReviewExists) {
      return { status: 'none_for_current_calculation', priorReviewExists: true };
    }
    return FINDING_PRIORITY_REVIEW_NONE;
  }
  if (!UUID_LOWER.test(input.head.reviewId)) {
    return null;
  }
  const head = input.head;
  if (head.decision === 'accepted' || head.decision === 'withdrawn') {
    if (head.correctedBand !== null || head.expiresAt !== null) {
      return null;
    }
    return {
      status: head.decision,
      priorReviewExists: input.priorReviewExists,
      reviewId: head.reviewId,
    };
  }
  if (head.decision !== 'corrected') {
    return assertNever(head.decision);
  }
  if (head.correctedBand === null || head.expiresAt === null) {
    return null;
  }
  if (!PRIORITY_BANDS.includes(head.correctedBand)) {
    return null;
  }
  const expiresAt = isoInstant(head.expiresAt);
  if (expiresAt === null) {
    return null;
  }
  const projected = {
    priorReviewExists: input.priorReviewExists,
    reviewId: head.reviewId,
    correctedBand: head.correctedBand,
    expiresAt,
  };
  if (head.expiresAt.getTime() <= input.asOf.getTime()) {
    return { status: 'expired', ...projected };
  }
  return { status: 'corrected', ...projected };
}

export function projectFindingPriorityReview(
  input: PriorityReviewProjectionInput,
): FindingPriorityReview | null {
  const marker = projectPriorityReviewMarker(input);
  if (marker === null) {
    return null;
  }
  if (marker.status === 'none' || marker.status === 'none_for_current_calculation') {
    if (input.reason !== undefined && input.reason !== null) {
      return null;
    }
    return marker;
  }
  const reason = input.reason === undefined ? null : input.reason;
  if (reason !== null && normalizePriorityReviewReason(reason) !== reason) {
    return null;
  }
  if (marker.status === 'accepted') {
    return {
      status: 'accepted',
      priorReviewExists: marker.priorReviewExists,
      reviewId: marker.reviewId,
      reason,
    };
  }
  if (reason === null) {
    return null;
  }
  if (marker.status === 'withdrawn') {
    return {
      status: 'withdrawn',
      priorReviewExists: marker.priorReviewExists,
      reviewId: marker.reviewId,
      reason,
    };
  }
  if (marker.status === 'corrected' || marker.status === 'expired') {
    return {
      status: marker.status,
      priorReviewExists: marker.priorReviewExists,
      reviewId: marker.reviewId,
      correctedBand: marker.correctedBand,
      expiresAt: marker.expiresAt,
      reason,
    };
  }
  return assertNever(marker);
}

export function priorityReviewAuditPayload(input: {
  readonly reviewId: string;
  readonly findingId: string;
  readonly riskCalculationId: string;
  readonly decision: PriorityReviewDecision;
  readonly correctedBand: PriorityBand | null;
  readonly expiresAt: string | null;
  readonly supersedesReviewId: string | null;
  readonly reasonLength: number;
}): PriorityReviewAuditPayload | null {
  if (
    !UUID_LOWER.test(input.reviewId) ||
    !UUID_LOWER.test(input.findingId) ||
    !UUID_LOWER.test(input.riskCalculationId)
  ) {
    return null;
  }
  if (input.supersedesReviewId !== null && !UUID_LOWER.test(input.supersedesReviewId)) {
    return null;
  }
  if (input.correctedBand !== null && !PRIORITY_BANDS.includes(input.correctedBand)) {
    return null;
  }
  if (input.expiresAt !== null && !TIMESTAMP.test(input.expiresAt)) {
    return null;
  }
  if (
    !Number.isInteger(input.reasonLength) ||
    input.reasonLength < 0 ||
    input.reasonLength > 2000
  ) {
    return null;
  }
  const payload: PriorityReviewAuditPayload = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    reviewId: input.reviewId,
    findingId: input.findingId,
    riskCalculationId: input.riskCalculationId,
    decision: input.decision,
    correctedBand: input.correctedBand,
    expiresAt: input.expiresAt,
    supersedesReviewId: input.supersedesReviewId,
    reasonLength: input.reasonLength,
  };
  const keys = Object.keys(payload);
  if (keys.length !== AUDIT_KEYS.length || AUDIT_KEYS.some((key) => !keys.includes(key))) {
    return null;
  }
  if ('reason' in payload) {
    return null;
  }
  return Object.freeze(payload);
}

export function priorityReviewAuditAction(
  decision: PriorityReviewDecision,
): (typeof PRIORITY_REVIEW_AUDIT_ACTIONS)[PriorityReviewDecision] {
  return PRIORITY_REVIEW_AUDIT_ACTIONS[decision];
}

export function createRecordPriorityReviewUseCase(dependencies: {
  readonly persistence: PriorityReviewPersistencePort;
}) {
  return {
    async execute(input: unknown): Promise<RecordPriorityReviewResult> {
      try {
        return await executeRecord(dependencies, input);
      } catch {
        return { kind: 'unavailable' };
      }
    },
  };
}

async function executeRecord(
  dependencies: { readonly persistence: PriorityReviewPersistencePort },
  input: unknown,
): Promise<RecordPriorityReviewResult> {
  if (recordHasAmbientKey(input, ENVELOPE_AUTHORITY_KEYS)) {
    return { kind: 'unauthorized' };
  }
  const envelope = closedRecord(input, ENVELOPE_KEYS);
  if (envelope === null) {
    return { kind: 'invalid_command' };
  }
  const actor = parseControlledFindingOperatorActor(envelope.get('actor'));
  if (
    actor === null ||
    !roleGrantsPriorityPermission(actor.role, PRIORITY_REVIEW_CONTROLLED_PERMISSION)
  ) {
    return { kind: 'unauthorized' };
  }
  const command = readCommand(envelope.get('command'));
  if (command === null) {
    return { kind: 'invalid_command' };
  }
  if (typeof dependencies.persistence.recordPriorityReview !== 'function') {
    return { kind: 'unavailable' };
  }
  const recorded = await dependencies.persistence.recordPriorityReview({
    organizationId: actor.organizationId,
    actorUserId: actor.userId,
    membershipId: actor.membershipId,
    ...command,
  });
  return mapRecorded(recorded, command.findingId, command.riskCalculationId);
}

function mapRecorded(
  recorded: RecordPriorityReviewPersistenceResult,
  findingId: string,
  riskCalculationId: string,
): RecordPriorityReviewResult {
  switch (recorded.kind) {
    case 'recorded':
    case 'already_applied':
      if (recorded.findingId !== findingId || recorded.riskCalculationId !== riskCalculationId) {
        return { kind: 'not_found' };
      }
      return recorded;
    case 'not_found':
    case 'calculation_not_current':
    case 'review_not_current':
    case 'unauthorized':
    case 'unavailable':
      return { kind: recorded.kind };
    case 'rejected':
      return { kind: 'invalid_command' };
    default:
      return assertNever(recorded);
  }
}

function readCommand(
  input: unknown,
): Omit<RecordPriorityReviewCommand, 'organizationId' | 'actorUserId' | 'membershipId'> | null {
  if (!isPlainObject(input) || recordHasAmbientKey(input, COMMAND_AUTHORITY_KEYS)) {
    return null;
  }
  const command = closedRecord(input, COMMAND_KEYS);
  if (command === null) {
    return null;
  }
  const findingId = command.get('findingId');
  const riskCalculationId = command.get('riskCalculationId');
  const correlationId = command.get('correlationId');
  const supersedesReviewId = command.get('supersedesReviewId');
  const decision = command.get('decision');
  if (
    typeof findingId !== 'string' ||
    !UUID_LOWER.test(findingId) ||
    typeof riskCalculationId !== 'string' ||
    !UUID_LOWER.test(riskCalculationId) ||
    typeof correlationId !== 'string' ||
    !UUID_LOWER.test(correlationId) ||
    !isDecision(decision)
  ) {
    return null;
  }
  if (
    supersedesReviewId !== null &&
    (typeof supersedesReviewId !== 'string' || !UUID_LOWER.test(supersedesReviewId))
  ) {
    return null;
  }
  const correctedBand = readBand(command.get('correctedBand'));
  const expiresAt = readExpires(command.get('expiresAt'));
  const reason = readReason(command.get('reason'));
  if (correctedBand === 'invalid' || expiresAt === 'invalid' || reason === 'invalid') {
    return null;
  }
  if (!decisionShape(decision, supersedesReviewId, correctedBand, expiresAt, reason)) {
    return null;
  }
  return {
    findingId,
    riskCalculationId,
    supersedesReviewId,
    decision,
    correctedBand,
    expiresAt,
    reason,
    correlationId,
  };
}

function decisionShape(
  decision: PriorityReviewDecision,
  supersedesReviewId: string | null,
  correctedBand: PriorityBand | null,
  expiresAt: Date | null,
  reason: string | null,
): boolean {
  if (decision === 'accepted') {
    return correctedBand === null && expiresAt === null;
  }
  if (decision === 'withdrawn') {
    return (
      supersedesReviewId !== null && correctedBand === null && expiresAt === null && reason !== null
    );
  }
  return correctedBand !== null && expiresAt !== null && reason !== null;
}

function readBand(value: unknown): PriorityBand | null | 'invalid' {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'string' || !PRIORITY_BANDS.includes(value as PriorityBand)) {
    return 'invalid';
  }
  return value as PriorityBand;
}

function readExpires(value: unknown): Date | null | 'invalid' {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'string' || !TIMESTAMP.test(value)) {
    return 'invalid';
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    return 'invalid';
  }
  return parsed;
}

function readReason(value: unknown): string | null | 'invalid' {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    return 'invalid';
  }
  const normalized = normalizePriorityReviewReason(value);
  return normalized === null ? 'invalid' : normalized;
}

function isDecision(value: unknown): value is PriorityReviewDecision {
  return value === 'accepted' || value === 'corrected' || value === 'withdrawn';
}

function isoInstant(value: Date): string | null {
  if (!Number.isFinite(value.getTime())) {
    return null;
  }
  const text = value.toISOString();
  return TIMESTAMP.test(text) ? text : null;
}
