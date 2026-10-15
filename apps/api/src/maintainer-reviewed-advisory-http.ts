import { AUTHENTICATION_REQUIRED } from '@patchpilot/auth';
import {
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_TRANSPORT_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_TRANSPORT_SCHEMA_VERSION,
  maintainerReviewedAdvisoryApprovalResponseSchema,
  maintainerReviewedAdvisorySubmissionResponseSchema,
} from '@patchpilot/contracts';
import type { AppError } from '@patchpilot/domain';

import type { AdvisoryMutationResult } from './maintainer-reviewed-advisory-runtime.js';
import {
  ADVISORY_APPROVAL_NOT_RECORDED,
  ADVISORY_AUTHORITY_REJECTED,
  ADVISORY_BODY_TOO_LARGE,
  ADVISORY_CONFLICT,
  ADVISORY_MUTATION_UNAVAILABLE,
  ADVISORY_NOT_FOUND,
  ADVISORY_UNSUPPORTED_MEDIA_TYPE,
  INVALID_REQUEST,
} from './http-errors.js';

const UTF8_CHARSETS = new Set(['utf-8', 'utf8']);

export type AdvisoryPublicOutcome =
  | 'submitted'
  | 'already_applied'
  | 'approved'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'unsupported_media'
  | 'payload_too_large'
  | 'unavailable';

export type AdvisorySuccessTranslation = {
  readonly ok: true;
  readonly statusCode: 200 | 201;
  readonly body: {
    readonly schemaVersion: string;
    readonly result: 'submitted' | 'already_applied' | 'approved';
    readonly advisoryRevisionId: string;
  };
};

export type AdvisoryFailureTranslation = {
  readonly ok: false;
  readonly error: AppError;
};

/**
 * ADR 0042 status mapping. Capability outcomes share one nonactionable
 * refusal so the transport does not disclose issuer, seal, or binding state.
 * user_inactive is not a public outcome; a leaked value uses the same
 * authority refusal as authority_rejected.
 */
export function translateAdvisoryMutationResult(
  result: AdvisoryMutationResult,
  route: 'submission' | 'approval',
): AdvisorySuccessTranslation | AdvisoryFailureTranslation {
  if (
    (result.outcome === 'submitted' || result.outcome === 'already_applied') &&
    route === 'submission' &&
    typeof result.revisionId === 'string'
  ) {
    const body = maintainerReviewedAdvisorySubmissionResponseSchema.safeParse({
      schemaVersion: MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_TRANSPORT_SCHEMA_VERSION,
      result: result.outcome,
      advisoryRevisionId: result.revisionId,
    });
    if (!body.success) {
      return { ok: false, error: ADVISORY_MUTATION_UNAVAILABLE };
    }
    return {
      ok: true,
      statusCode: result.outcome === 'submitted' ? 201 : 200,
      body: body.data,
    };
  }
  if (
    (result.outcome === 'approved' || result.outcome === 'already_applied') &&
    route === 'approval' &&
    typeof result.revisionId === 'string'
  ) {
    const body = maintainerReviewedAdvisoryApprovalResponseSchema.safeParse({
      schemaVersion: MAINTAINER_REVIEWED_ADVISORY_APPROVAL_TRANSPORT_SCHEMA_VERSION,
      result: result.outcome,
      advisoryRevisionId: result.revisionId,
    });
    if (!body.success) {
      return { ok: false, error: ADVISORY_MUTATION_UNAVAILABLE };
    }
    return {
      ok: true,
      statusCode: result.outcome === 'approved' ? 201 : 200,
      body: body.data,
    };
  }
  return { ok: false, error: advisoryFailureError(result.outcome) };
}

export function advisoryFailureError(outcome: string): AppError {
  switch (outcome) {
    case 'invalid_command':
    case 'malformed_document':
    case 'unsupported_origin':
      return INVALID_REQUEST;
    case 'authority_required':
      return AUTHENTICATION_REQUIRED;
    case 'authority_rejected':
    case 'user_inactive':
      return ADVISORY_AUTHORITY_REJECTED;
    case 'not_found':
      return ADVISORY_NOT_FOUND;
    case 'separation_of_duties_required':
    case 'capability_required':
    case 'capability_rejected':
    case 'capability_expired':
      return ADVISORY_APPROVAL_NOT_RECORDED;
    case 'immutable_conflict':
      return ADVISORY_CONFLICT;
    case 'malformed_persisted_state':
    case 'transaction_aborted':
    case 'database_unavailable':
    case 'internal_failure':
      return ADVISORY_MUTATION_UNAVAILABLE;
    default:
      return ADVISORY_MUTATION_UNAVAILABLE;
  }
}

export function advisoryOutcomeForError(error: AppError): AdvisoryPublicOutcome {
  if (error.message === ADVISORY_BODY_TOO_LARGE.message) {
    return 'payload_too_large';
  }
  if (error.message === ADVISORY_UNSUPPORTED_MEDIA_TYPE.message) {
    return 'unsupported_media';
  }
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
      return 'unavailable';
    case 'internal':
      return 'unavailable';
  }
}

export function advisoryStatusClass(statusCode: number): '2xx' | '4xx' | '5xx' {
  if (statusCode >= 500) {
    return '5xx';
  }
  if (statusCode >= 400) {
    return '4xx';
  }
  return '2xx';
}

export function parseAdvisoryJsonContentType(
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

export function declaredAdvisoryContentLength(
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

export function advisoryContentEncodingRejected(value: string | string[] | undefined): boolean {
  if (value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return true;
  }
  const encodings = value
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part.length > 0);
  return encodings.length === 0 || encodings.some((encoding) => encoding !== 'identity');
}
