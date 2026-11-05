/**
 * HTTP translation for the remediation queue.
 * Query organization identity is rejected. The cursor stays out of logs.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import {
  remediationQueueResponseSchema,
  type RemediationQueueResponse,
} from '@patchpilot/contracts';
import {
  REMEDIATION_QUEUE_DEFAULT_LIMIT,
  REMEDIATION_QUEUE_MAX_CURSOR_LENGTH,
  assertNever,
  type AppError,
  type ReadRemediationQueueResult,
  type RemediationQueuePage,
  type RemediationQueueSection,
} from '@patchpilot/domain';

import {
  INVALID_REQUEST,
  PRIORITY_POLICY_UNAVAILABLE,
  REMEDIATION_QUEUE_UNAVAILABLE,
} from './http-errors.js';

export const REMEDIATION_QUEUE_ROUTE = '/remediation-queue';

export const REMEDIATION_QUEUE_STALE_CURSOR: AppError = Object.freeze({
  code: 'conflict',
  message: 'The page cursor is no longer current.',
});

const SECTIONS = new Set<RemediationQueueSection>(['ranked', 'incomparable', 'not_calculated']);

export type RemediationQueuePublicOutcome =
  | 'page'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'conflict'
  | 'rate_limited'
  | 'policy_unavailable'
  | 'unavailable'
  | 'internal';

export function translateRemediationQueue(
  result: ReadRemediationQueueResult,
):
  | { readonly ok: true; readonly statusCode: 200; readonly body: RemediationQueueResponse }
  | { readonly ok: false; readonly error: AppError } {
  switch (result.kind) {
    case 'page': {
      const body = remediationQueueResponseSchema.safeParse(toResponse(result.page));
      if (!body.success) {
        return { ok: false, error: REMEDIATION_QUEUE_UNAVAILABLE };
      }
      return { ok: true, statusCode: 200, body: body.data };
    }
    case 'priority_policy_unavailable':
      return { ok: false, error: PRIORITY_POLICY_UNAVAILABLE };
    case 'stale_cursor':
      return { ok: false, error: REMEDIATION_QUEUE_STALE_CURSOR };
    case 'unauthorized':
      return { ok: false, error: PERMISSION_DENIED };
    case 'invalid_command':
      return { ok: false, error: INVALID_REQUEST };
    case 'unavailable':
    case 'internal_failure':
      return { ok: false, error: REMEDIATION_QUEUE_UNAVAILABLE };
    default:
      return assertNever(result);
  }
}

export function remediationQueueOutcomeForError(error: AppError): RemediationQueuePublicOutcome {
  if (
    error === PRIORITY_POLICY_UNAVAILABLE ||
    error.message === PRIORITY_POLICY_UNAVAILABLE.message
  ) {
    return 'policy_unavailable';
  }
  switch (error.code) {
    case 'validation':
      return 'validation';
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    case 'conflict':
      return 'conflict';
    case 'rate_limited':
      return 'rate_limited';
    case 'internal':
      return error.message === REMEDIATION_QUEUE_UNAVAILABLE.message ? 'unavailable' : 'internal';
    default:
      return 'internal';
  }
}

export function parseRemediationQueueQuery(url: string):
  | {
      readonly ok: true;
      readonly section: RemediationQueueSection;
      readonly limit: number;
      readonly cursor: string | null;
    }
  | { readonly ok: false } {
  const question = url.indexOf('?');
  const query = question < 0 ? '' : (url.slice(question + 1).split('#')[0] ?? '');
  if (query.length === 0) {
    return { ok: false };
  }
  const seen = new Set<string>();
  let section: RemediationQueueSection | null = null;
  let limit = REMEDIATION_QUEUE_DEFAULT_LIMIT;
  let cursor: string | null = null;
  for (const part of query.split('&')) {
    if (part.length === 0) {
      return { ok: false };
    }
    const separator = part.indexOf('=');
    const rawKey = separator < 0 ? part : part.slice(0, separator);
    const rawValue = separator < 0 ? '' : part.slice(separator + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
      value = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    } catch {
      return { ok: false };
    }
    if (seen.has(key)) {
      return { ok: false };
    }
    seen.add(key);
    if (key === 'section') {
      if (!isSection(value)) {
        return { ok: false };
      }
      section = value;
    } else if (key === 'limit') {
      if (!/^(?:[1-9]|[1-4][0-9]|50)$/.test(value)) {
        return { ok: false };
      }
      limit = Number(value);
    } else if (key === 'cursor') {
      if (value.length === 0 || value.length > REMEDIATION_QUEUE_MAX_CURSOR_LENGTH) {
        return { ok: false };
      }
      cursor = value;
    } else {
      return { ok: false };
    }
  }
  if (section === null) {
    return { ok: false };
  }
  return { ok: true, section, limit, cursor };
}

function toResponse(page: RemediationQueuePage): unknown {
  return {
    schemaVersion: 'remediation_queue_v1',
    asOf: page.asOf,
    reference: page.reference,
    counts: page.counts,
    section: page.section,
    limit: page.limit,
    nextCursor: page.nextCursor,
    rows: page.rows.map((row) => toRow(page.section, row)),
  };
}

function toRow(
  section: RemediationQueueSection,
  row: RemediationQueuePage['rows'][number],
): unknown {
  const identity = {
    findingId: row.findingId,
    assetId: row.assetId,
    assetName: row.assetName,
    componentName: row.componentName,
    componentVersion: row.componentVersion,
    vulnerabilityPublicId: row.vulnerabilityPublicId,
    humanReview: row.humanReview,
  };
  if (section === 'not_calculated' || !('priority' in row)) {
    return identity;
  }
  const calculated = {
    ...identity,
    priorityBand: row.priorityBand,
    priority: row.priority,
    policy: row.policy,
    calculatedAt: row.calculatedAt,
    inputsChanged: {
      status: row.inputsChanged.status,
      signals: [...row.inputsChanged.signals],
    },
  };
  if (section === 'incomparable' && 'comparisonMessage' in row) {
    return { ...calculated, comparisonMessage: row.comparisonMessage };
  }
  return calculated;
}

function isSection(value: string): value is RemediationQueueSection {
  return SECTIONS.has(value as RemediationQueueSection);
}
