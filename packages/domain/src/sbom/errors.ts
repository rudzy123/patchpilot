import type { AppError } from '../result.js';

export const SBOM_INVALID_CURSOR: AppError = Object.freeze({
  code: 'validation',
  message: 'Invalid request.',
});

export const SBOM_INVALID_TRANSITION: AppError = Object.freeze({
  code: 'conflict',
  message: 'SBOM ingestion transition is not allowed.',
});

export const SBOM_TERMINAL_STATE: AppError = Object.freeze({
  code: 'conflict',
  message: 'SBOM ingestion is already terminal.',
});

export const SBOM_DUPLICATE_STATE_FORBIDDEN: AppError = Object.freeze({
  code: 'conflict',
  message: 'Duplicate-state ingestion rows are not used for evidence deduplication.',
});

export const SBOM_PROCESSING_REQUIRES_STARTED_AT: AppError = Object.freeze({
  code: 'validation',
  message: 'Processing requires startedAt. Lease timestamps are not the processor lock.',
});

export const SBOM_COMPLETED_REQUIREMENTS: AppError = Object.freeze({
  code: 'validation',
  message: 'Completed ingestions require graph completeness and graph counts.',
});

export const SBOM_UNSUPPORTED_STAGE: AppError = Object.freeze({
  code: 'validation',
  message: 'Session 8 does not run correlate, enrich, or score stages.',
});

export const SBOM_INVALID_VERSION: AppError = Object.freeze({
  code: 'validation',
  message: 'Component version is not a known observed value or an explicit unknown.',
});

export const SBOM_INVALID_GRAPH: AppError = Object.freeze({
  code: 'validation',
  message: 'Normalized graph is not valid.',
});

export const SBOM_INVALID_IDENTITY: AppError = Object.freeze({
  code: 'validation',
  message: 'Component identity is not valid.',
});

export function sbomValidationError(message: string): AppError {
  return {
    code: 'validation',
    message,
  };
}
