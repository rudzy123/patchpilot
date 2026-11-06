/**
 * HTTP translation for the remediation queue.
 * Query organization identity is rejected. The cursor stays out of logs.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import {
  remediationQueueExportRequestSchema,
  remediationQueueExportResponseSchema,
  remediationQueueResponseSchema,
  type RemediationQueueExportRequest,
  type RemediationQueueResponse,
} from '@patchpilot/contracts';
import {
  REMEDIATION_QUEUE_DEFAULT_LIMIT,
  REMEDIATION_QUEUE_EXPORT_CAP,
  REMEDIATION_QUEUE_MAX_CURSOR_LENGTH,
  assertNever,
  type AppError,
  type ExportRemediationQueueResult,
  type FindingPriorityReviewMarker,
  type ReadRemediationQueueResult,
  type RemediationQueueExportDocument,
  type RemediationQueueIncomparableRow,
  type RemediationQueueNotCalculatedRow,
  type RemediationQueuePage,
  type RemediationQueueRankedRow,
  type RemediationQueueSection,
} from '@patchpilot/domain';

import {
  INVALID_REQUEST,
  PRIORITY_POLICY_UNAVAILABLE,
  REMEDIATION_QUEUE_UNAVAILABLE,
} from './http-errors.js';

export const REMEDIATION_QUEUE_ROUTE = '/remediation-queue';
export const REMEDIATION_QUEUE_EXPORT_ROUTE = '/remediation-queue/export';

export const REMEDIATION_QUEUE_STALE_CURSOR: AppError = Object.freeze({
  code: 'conflict',
  message: 'The page cursor is no longer current.',
});

export const REMEDIATION_QUEUE_EXPORT_CAP_EXCEEDED: AppError = Object.freeze({
  code: 'conflict',
  message: `Remediation queue export exceeds ${REMEDIATION_QUEUE_EXPORT_CAP} findings.`,
});

export const REMEDIATION_QUEUE_EXPORT_NOT_RECORDED: AppError = Object.freeze({
  code: 'conflict',
  message: 'The export was not recorded.',
});

export const REMEDIATION_QUEUE_EXPORT_JSON_TYPE = 'application/json; charset=utf-8';
export const REMEDIATION_QUEUE_EXPORT_CSV_TYPE = 'text/csv; charset=utf-8';
export const REMEDIATION_QUEUE_EXPORT_JSON_DISPOSITION =
  'attachment; filename="remediation-queue.json"';
export const REMEDIATION_QUEUE_EXPORT_CSV_DISPOSITION =
  'attachment; filename="remediation-queue.csv"';

export const REMEDIATION_QUEUE_EXPORT_CSV_HEADER = [
  'section',
  'findingId',
  'assetId',
  'assetName',
  'componentName',
  'componentVersion',
  'vulnerabilityPublicId',
  'humanReviewStatus',
  'humanReviewPriorReviewExists',
  'humanReviewId',
  'humanReviewCorrectedBand',
  'humanReviewExpiresAt',
  'priorityBand',
  'priority',
  'riskPolicyId',
  'policyKey',
  'policyVersion',
  'policyDefinitionSha256',
  'calculatedAt',
  'inputsChangedStatus',
  'inputsChangedSignals',
  'comparisonMessage',
].join(',');

const SECTIONS = new Set<RemediationQueueSection>(['ranked', 'incomparable', 'not_calculated']);

export type RemediationQueuePublicOutcome =
  | 'page'
  | 'exported'
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

export function parseRemediationQueueExportBody(
  body: unknown,
):
  | { readonly ok: true; readonly format: RemediationQueueExportRequest['format'] }
  | { readonly ok: false } {
  const parsed = remediationQueueExportRequestSchema.safeParse(body);
  if (!parsed.success) {
    return { ok: false };
  }
  return { ok: true, format: parsed.data.format };
}

export function translateRemediationQueueExport(result: ExportRemediationQueueResult):
  | {
      readonly ok: true;
      readonly statusCode: 200;
      readonly contentType: string;
      readonly contentDisposition: string;
      readonly body: Uint8Array;
    }
  | { readonly ok: false; readonly error: AppError } {
  switch (result.kind) {
    case 'exported':
      return {
        ok: true,
        statusCode: 200,
        contentType:
          result.document.format === 'json'
            ? REMEDIATION_QUEUE_EXPORT_JSON_TYPE
            : REMEDIATION_QUEUE_EXPORT_CSV_TYPE,
        contentDisposition:
          result.document.format === 'json'
            ? REMEDIATION_QUEUE_EXPORT_JSON_DISPOSITION
            : REMEDIATION_QUEUE_EXPORT_CSV_DISPOSITION,
        body: result.body,
      };
    case 'priority_policy_unavailable':
      return { ok: false, error: PRIORITY_POLICY_UNAVAILABLE };
    case 'cap_exceeded':
      return { ok: false, error: REMEDIATION_QUEUE_EXPORT_CAP_EXCEEDED };
    case 'correlation_conflict':
      return { ok: false, error: REMEDIATION_QUEUE_EXPORT_NOT_RECORDED };
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

export function serializeRemediationQueueExport(
  document: RemediationQueueExportDocument,
): Uint8Array {
  if (document.format === 'json') {
    return encodeUtf8(serializeExportJson(document));
  }
  return encodeUtf8(serializeExportCsv(document));
}

function serializeExportJson(document: RemediationQueueExportDocument): string {
  const body = {
    schemaVersion: 'remediation_queue_export_v1' as const,
    format: 'json' as const,
    asOf: document.asOf,
    reference: {
      policyKey: document.reference.policyKey,
      policyVersion: document.reference.policyVersion,
      policyDefinitionSha256: document.reference.policyDefinitionSha256,
      engineVersion: document.reference.engineVersion,
    },
    counts: {
      ranked: document.counts.ranked,
      incomparable: document.counts.incomparable,
      not_calculated: document.counts.not_calculated,
    },
    rowCount: document.rowCount,
    cap: document.cap,
    sections: {
      ranked: document.sections.ranked.map((row) => toRow('ranked', row)),
      incomparable: document.sections.incomparable.map((row) => toRow('incomparable', row)),
      not_calculated: document.sections.not_calculated.map((row) => toRow('not_calculated', row)),
    },
  };
  if (document.format !== 'json' || !remediationQueueExportResponseSchema.safeParse(body).success) {
    throw new Error('remediation queue export serialization failed');
  }
  return JSON.stringify(body);
}

function serializeExportCsv(document: RemediationQueueExportDocument): string {
  if (!remediationQueueExportResponseSchema.safeParse(exportJsonCandidate(document)).success) {
    throw new Error('remediation queue export serialization failed');
  }
  const lines = [REMEDIATION_QUEUE_EXPORT_CSV_HEADER];
  for (const row of document.sections.ranked) {
    lines.push(csvLine('ranked', row));
  }
  for (const row of document.sections.incomparable) {
    lines.push(csvLine('incomparable', row));
  }
  for (const row of document.sections.not_calculated) {
    lines.push(csvLine('not_calculated', row));
  }
  return `${lines.join('\n')}\n`;
}

function exportJsonCandidate(document: RemediationQueueExportDocument): unknown {
  return {
    schemaVersion: 'remediation_queue_export_v1',
    format: document.format,
    asOf: document.asOf,
    reference: document.reference,
    counts: document.counts,
    rowCount: document.rowCount,
    cap: document.cap,
    sections: {
      ranked: document.sections.ranked.map((row) => toRow('ranked', row)),
      incomparable: document.sections.incomparable.map((row) => toRow('incomparable', row)),
      not_calculated: document.sections.not_calculated.map((row) => toRow('not_calculated', row)),
    },
  };
}

type ExportRow =
  RemediationQueueRankedRow | RemediationQueueIncomparableRow | RemediationQueueNotCalculatedRow;

function csvLine(section: RemediationQueueSection, row: ExportRow): string {
  const review = reviewCells(row.humanReview);
  const calculated = calculatedCells(row);
  const comparison = 'comparisonMessage' in row ? row.comparisonMessage : '';
  return [
    csvText(section),
    csvText(row.findingId),
    csvText(row.assetId),
    csvText(row.assetName),
    csvText(row.componentName),
    csvText(row.componentVersion),
    csvText(row.vulnerabilityPublicId),
    ...review,
    ...calculated,
    csvText(comparison),
  ].join(',');
}

function reviewCells(marker: FindingPriorityReviewMarker): readonly string[] {
  return [
    csvText(marker.status),
    csvText(marker.priorReviewExists ? 'true' : 'false'),
    csvText('reviewId' in marker ? marker.reviewId : ''),
    csvText('correctedBand' in marker ? marker.correctedBand : ''),
    csvText('expiresAt' in marker ? marker.expiresAt : ''),
  ];
}

function calculatedCells(row: ExportRow): readonly string[] {
  if (!('priority' in row)) {
    return ['', '', '', '', '', '', '', '', ''];
  }
  return [
    csvText(row.priorityBand),
    csvNumber(row.priority),
    csvText(row.policy.riskPolicyId),
    csvText(row.policy.policyKey),
    csvNumber(row.policy.policyVersion),
    csvText(row.policy.policyDefinitionSha256),
    csvText(row.calculatedAt),
    csvText(row.inputsChanged.status),
    csvText(row.inputsChanged.signals.join(',')),
  ];
}

function csvText(value: string): string {
  if (value.length === 0) {
    return '';
  }
  const neutralized = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return quoteCsv(neutralized);
}

function csvNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new Error('remediation queue export serialization failed');
  }
  return quoteCsv(JSON.stringify(value));
}

function quoteCsv(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replaceAll('"', '""')}"`;
  }
  return value;
}

function encodeUtf8(value: string): Uint8Array {
  const encoded = Buffer.from(value, 'utf8');
  if (encoded.length >= 3 && encoded[0] === 0xef && encoded[1] === 0xbb && encoded[2] === 0xbf) {
    throw new Error('remediation queue export serialization failed');
  }
  return encoded;
}
