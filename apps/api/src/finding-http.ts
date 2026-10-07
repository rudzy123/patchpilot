import { PERMISSION_DENIED } from '@patchpilot/auth';
import type { AppError } from '@patchpilot/domain';
import type { FastifyRequest } from 'fastify';

import { readSingleHeader } from './headers.js';
import {
  AUTH_HTTP_RATE_LIMITED,
  FINDING_OPERATOR_UNAVAILABLE,
  INVALID_REQUEST,
} from './http-errors.js';

const UTF8_CHARSETS = new Set(['utf-8', 'utf8']);

export const FINDING_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Not found.',
});

export const FINDING_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'The request conflicts with the current evidence.',
});

export const FINDING_UNPROCESSABLE: AppError = Object.freeze({
  code: 'unprocessable_evidence',
  message: 'The evidence cannot be used for this request.',
});

export const FINDING_INTERNAL: AppError = Object.freeze({
  code: 'internal',
  message: 'An internal error occurred.',
});

export type FindingPublicOutcome =
  | 'created'
  | 'already_applied'
  | 'found'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'unprocessable_evidence'
  | 'rate_limited'
  | 'unavailable'
  | 'internal';

export function findingOutcomeForError(error: AppError): FindingPublicOutcome {
  switch (error.code) {
    case 'validation':
      return 'validation';
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    case 'not_found':
      return 'not_found';
    case 'conflict':
      return 'conflict';
    case 'rate_limited':
      return 'rate_limited';
    case 'unprocessable_evidence':
      return 'unprocessable_evidence';
    case 'internal':
      return error.message === FINDING_OPERATOR_UNAVAILABLE.message ? 'unavailable' : 'internal';
  }
}

export function creationFailureError(status: string): AppError {
  switch (status) {
    case 'invalid_command':
    case 'authority_rejected':
      return INVALID_REQUEST;
    case 'authority_required':
      return PERMISSION_DENIED;
    case 'not_found':
    case 'target_mismatch':
      return FINDING_NOT_FOUND;
    case 'evidence_set_mismatch':
    case 'evidence_not_current':
    case 'finding_already_exists':
    case 'immutable_conflict':
      return FINDING_CONFLICT;
    case 'evidence_unavailable':
    case 'evidence_not_affected':
    case 'evidence_not_eligible':
      return FINDING_UNPROCESSABLE;
    case 'database_unavailable':
      return FINDING_OPERATOR_UNAVAILABLE;
    default:
      return FINDING_INTERNAL;
  }
}

export function inspectionFailureError(status: string): AppError {
  switch (status) {
    case 'authority_required':
      return PERMISSION_DENIED;
    case 'not_found':
      return FINDING_NOT_FOUND;
    case 'evidence_unavailable':
      return FINDING_UNPROCESSABLE;
    case 'database_unavailable':
      return FINDING_OPERATOR_UNAVAILABLE;
    default:
      return FINDING_INTERNAL;
  }
}

export function parseFindingJsonContentType(
  value: string | string[] | undefined,
): { ok: true } | { ok: false } {
  if (typeof value !== 'string') {
    return { ok: false };
  }
  const parts = value
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  const mediaType = parts[0]?.toLowerCase();
  if (mediaType !== 'application/json') {
    return { ok: false };
  }
  for (const parameter of parts.slice(1)) {
    const separator = parameter.indexOf('=');
    if (separator <= 0) {
      return { ok: false };
    }
    const name = parameter.slice(0, separator).trim().toLowerCase();
    let parameterValue = parameter.slice(separator + 1).trim();
    if (
      parameterValue.startsWith('"') &&
      parameterValue.endsWith('"') &&
      parameterValue.length >= 2
    ) {
      parameterValue = parameterValue.slice(1, -1);
    }
    if (name !== 'charset' || !UTF8_CHARSETS.has(parameterValue.toLowerCase())) {
      return { ok: false };
    }
  }
  return { ok: true };
}

export function declaredContentLength(
  value: string | string[] | undefined,
): 'absent' | 'invalid' | number {
  if (value === undefined) {
    return 'absent';
  }
  if (Array.isArray(value) || !/^\d+$/.test(value)) {
    return 'invalid';
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length)) {
    return 'invalid';
  }
  return length;
}

export function requestCarriesBody(request: FastifyRequest): boolean {
  const lengthHeader = request.headers['content-length'];
  if (lengthHeader !== undefined) {
    if (Array.isArray(lengthHeader) || !/^\d+$/.test(lengthHeader) || Number(lengthHeader) > 0) {
      return true;
    }
  }
  const transfer = readSingleHeader(request.headers['transfer-encoding']);
  if (transfer === undefined) {
    return false;
  }
  return transfer
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part.length > 0)
    .some((encoding) => encoding !== 'identity');
}

export function findingRateLimitedError(): AppError {
  return AUTH_HTTP_RATE_LIMITED;
}
