import type { AppError } from '../result.js';

export const INTELLIGENCE_INVALID_TRANSITION: AppError = Object.freeze({
  code: 'conflict',
  message: 'Intelligence sync-run transition is not allowed.',
});

export const INTELLIGENCE_TERMINAL_STATE: AppError = Object.freeze({
  code: 'conflict',
  message: 'Intelligence sync-run is already terminal. Operator replay must create a new run.',
});

export const INTELLIGENCE_INVALID_PROVIDER: AppError = Object.freeze({
  code: 'validation',
  message: 'Intelligence provider is not in the Session 9 closed set.',
});

export const INTELLIGENCE_INVALID_SOURCE: AppError = Object.freeze({
  code: 'validation',
  message: 'Intelligence source identifier is not in the Session 9 closed set.',
});

export const INTELLIGENCE_OSV_RUNTIME_FORBIDDEN: AppError = Object.freeze({
  code: 'validation',
  message: 'OSV is deferred and fail-closed in Session 9. It cannot be synchronized.',
});

export const INTELLIGENCE_GENERATION_INCOMPLETE: AppError = Object.freeze({
  code: 'conflict',
  message: 'Incomplete KEV generations cannot activate.',
});

export const INTELLIGENCE_GENERATION_COUNT_MISMATCH: AppError = Object.freeze({
  code: 'conflict',
  message: 'KEV generation staged entry count must match the expected count before activation.',
});

export const INTELLIGENCE_GENERATION_NOT_VISIBLE: AppError = Object.freeze({
  code: 'conflict',
  message: 'Staging KEV generations are invisible to catalog readers.',
});

export const INTELLIGENCE_ABANDONED_GENERATION: AppError = Object.freeze({
  code: 'conflict',
  message: 'Abandoned KEV generations cannot activate.',
});

export const INTELLIGENCE_ACTIVATION_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'KEV generation activation lost the IntelligenceSource compare-and-set.',
});

export const INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT: AppError = Object.freeze({
  code: 'conflict',
  message:
    'KEV catalog activation is inconsistent. Refusing to manufacture completion or treat an unactivated completed SyncRun as replay.',
});

export const INTELLIGENCE_INVALID_OBJECT_KEY: AppError = Object.freeze({
  code: 'validation',
  message: 'Intelligence snapshot object key is not a valid instance-owned snapshot key.',
});

export const INTELLIGENCE_ARBITRARY_URL_FORBIDDEN: AppError = Object.freeze({
  code: 'validation',
  message: 'Provider HTTP ports do not accept caller-supplied URLs.',
});

export const INTELLIGENCE_STATUS_UNAVAILABLE: AppError = Object.freeze({
  code: 'internal',
  message: 'Intelligence status is temporarily unavailable.',
});

export const INTELLIGENCE_STATUS_INCONSISTENT: AppError = Object.freeze({
  code: 'internal',
  message: 'An internal error occurred.',
});

export const INTELLIGENCE_PROVIDER_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Not found.',
});

export function intelligenceValidationError(message: string): AppError {
  return {
    code: 'validation',
    message,
  };
}
