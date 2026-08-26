export const errorCodes = [
  'validation',
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'rate_limited',
  'unprocessable_evidence',
  'internal',
] as const;

export type ErrorCode = (typeof errorCodes)[number];

export type AppError = {
  code: ErrorCode;
  message: string;
};

export type Result<T, E = AppError> = { ok: true; value: T } | { ok: false; error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}
