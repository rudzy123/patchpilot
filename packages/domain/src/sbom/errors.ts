import type { AppError } from '../result.js';
import {
  ASSET_ARCHIVED,
  ASSET_NOT_FOUND,
  ORGANIZATION_CONTEXT_REQUIRED,
  PERMISSION_DENIED,
} from '../assets/errors.js';

export { ASSET_ARCHIVED, ASSET_NOT_FOUND, ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED };

export type SbomUploadFailureOutcome =
  | 'not_found'
  | 'forbidden'
  | 'archived'
  | 'in_progress'
  | 'idempotency_conflict'
  | 'client_aborted'
  | 'storage_failed'
  | 'possible_orphan'
  | 'missing_ingestion'
  | 'internal';

export type SbomUploadFailure = AppError & {
  outcome: SbomUploadFailureOutcome;
};

export const SBOM_UPLOAD_IN_PROGRESS: SbomUploadFailure = Object.freeze({
  code: 'conflict',
  message: 'Upload is already in progress.',
  outcome: 'in_progress',
});

export const SBOM_UPLOAD_IDEMPOTENCY_CONFLICT: SbomUploadFailure = Object.freeze({
  code: 'conflict',
  message: 'Idempotency key was reused with a different request.',
  outcome: 'idempotency_conflict',
});

export const SBOM_UPLOAD_CLIENT_ABORTED: SbomUploadFailure = Object.freeze({
  code: 'validation',
  message: 'Upload was aborted.',
  outcome: 'client_aborted',
});

export const SBOM_UPLOAD_MISSING_INGESTION: SbomUploadFailure = Object.freeze({
  code: 'internal',
  message: 'Existing SBOM evidence is missing a current ingestion.',
  outcome: 'missing_ingestion',
});

export const SBOM_UPLOAD_REPLAY_UNAVAILABLE: SbomUploadFailure = Object.freeze({
  code: 'internal',
  message: 'Completed upload could not be reconstructed.',
  outcome: 'internal',
});

export const SBOM_UPLOAD_INTERNAL: SbomUploadFailure = Object.freeze({
  code: 'internal',
  message: 'SBOM upload failed.',
  outcome: 'internal',
});

export const SBOM_UPLOAD_POSSIBLE_ORPHAN: SbomUploadFailure = Object.freeze({
  code: 'internal',
  message: 'SBOM upload could not be finalized after object storage succeeded.',
  outcome: 'possible_orphan',
});

export class SbomEvidenceConflictError extends Error {
  public constructor() {
    super('SBOM evidence already exists for this organization, asset, and digest.');
    this.name = 'SbomEvidenceConflictError';
  }
}

export function isSbomEvidenceConflictError(error: unknown): error is SbomEvidenceConflictError {
  return error instanceof SbomEvidenceConflictError;
}

export function sbomUploadFailure(
  error: AppError,
  outcome: SbomUploadFailureOutcome,
): SbomUploadFailure {
  return { code: error.code, message: error.message, outcome };
}

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
