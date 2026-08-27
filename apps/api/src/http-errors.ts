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

/** Public response when the in-memory HTTP auth limiter is exhausted. */
export const AUTH_HTTP_RATE_LIMITED: AppError = Object.freeze({
  code: 'rate_limited',
  message: 'Too many requests. Try again later.',
});

export function httpStatusForError(error: AppError): number {
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
