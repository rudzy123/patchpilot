import { LOGIN_UNAVAILABLE } from '@patchpilot/auth';
import { errorEnvelopeSchema } from '@patchpilot/contracts';
import type { AppError } from '@patchpilot/domain';
import type { FastifyReply, FastifyRequest } from 'fastify';

export const ORIGIN_NOT_ALLOWED: AppError = Object.freeze({
  code: 'forbidden',
  message: 'Origin is not allowed.',
});

export const JSON_CONTENT_TYPE_REQUIRED: AppError = Object.freeze({
  code: 'validation',
  message: 'Content-Type must be application/json.',
});

export const INVALID_REQUEST: AppError = Object.freeze({
  code: 'validation',
  message: 'Invalid request.',
});

export const SBOM_CONTENT_TYPE_REQUIRED: AppError = Object.freeze({
  code: 'validation',
  message: 'Content-Type must be application/json or application/vnd.cyclonedx+json.',
});

export const SBOM_CHARSET_REQUIRED: AppError = Object.freeze({
  code: 'validation',
  message: 'UTF-8 charset is required.',
});

export const SBOM_CONTENT_TYPE_PARAMETER_REJECTED: AppError = Object.freeze({
  code: 'validation',
  message: 'Unsupported Content-Type parameter.',
});

export const SBOM_IDEMPOTENCY_KEY_REQUIRED: AppError = Object.freeze({
  code: 'validation',
  message: 'Idempotency-Key is required.',
});

export const SBOM_UPLOAD_TOO_LARGE: AppError = Object.freeze({
  code: 'validation',
  message: 'Upload exceeds the configured size limit.',
});

/** Public response when the in-memory HTTP auth limiter is exhausted. */
export const AUTH_HTTP_RATE_LIMITED: AppError = Object.freeze({
  code: 'rate_limited',
  message: 'Too many requests. Try again later.',
});

export function httpStatusForError(error: AppError): number {
  if (error.code === 'validation' && error.message === SBOM_UPLOAD_TOO_LARGE.message) {
    return 413;
  }

  switch (error.code) {
    case 'validation':
      return 400;
    case 'unauthorized':
      return 401;
    case 'forbidden':
      return 403;
    case 'not_found':
      return 404;
    case 'conflict':
      return 409;
    case 'rate_limited':
      return 429;
    case 'unprocessable_evidence':
      return 422;
    case 'internal':
      return error.message === LOGIN_UNAVAILABLE.message ? 503 : 500;
  }
}

export function sendAppError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
): FastifyReply {
  const body = errorEnvelopeSchema.parse({
    error: {
      code: error.code,
      message: error.message,
      requestId: request.requestId,
      correlationId: request.correlationId,
    },
  });
  return reply.status(httpStatusForError(error)).send(body);
}
