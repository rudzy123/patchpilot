import { describe, expect, it } from 'vitest';

import {
  advisoryFailureError,
  translateAdvisoryMutationResult,
} from './maintainer-reviewed-advisory-http.js';

const REVISION = '33333333-3333-4333-8333-333333333333';

describe('maintainer-reviewed advisory result translation', () => {
  it('maps submission success to the closed transport body', () => {
    const submitted = translateAdvisoryMutationResult(
      { outcome: 'submitted', revisionId: REVISION },
      'submission',
    );
    const replay = translateAdvisoryMutationResult(
      { outcome: 'already_applied', revisionId: REVISION },
      'submission',
    );
    expect(submitted).toMatchObject({ ok: true, statusCode: 201 });
    expect(replay).toMatchObject({ ok: true, statusCode: 200 });
    if (!submitted.ok || !replay.ok) {
      return;
    }
    expect(Object.keys(submitted.body).sort()).toEqual([
      'advisoryRevisionId',
      'result',
      'schemaVersion',
    ]);
    expect(submitted.body.result).toBe('submitted');
    expect(replay.body.result).toBe('already_applied');
  });

  it('maps approval success to the closed transport body', () => {
    const approved = translateAdvisoryMutationResult(
      { outcome: 'approved', revisionId: REVISION },
      'approval',
    );
    const replay = translateAdvisoryMutationResult(
      { outcome: 'already_applied', revisionId: REVISION },
      'approval',
    );
    expect(approved).toMatchObject({ ok: true, statusCode: 201 });
    expect(replay).toMatchObject({ ok: true, statusCode: 200 });
  });

  it('collapses capability outcomes into one nonactionable refusal', () => {
    const errors = ['capability_required', 'capability_rejected', 'capability_expired'].map(
      (outcome) => advisoryFailureError(outcome),
    );
    expect(new Set(errors.map((error) => error.code))).toEqual(new Set(['forbidden']));
    expect(new Set(errors.map((error) => error.message))).toEqual(
      new Set(['The approval was not recorded.']),
    );
    const serialized = JSON.stringify(errors);
    expect(serialized).not.toMatch(/capability|seal|issuer|binding|expired/i);
  });

  it('follows the ADR 0042 status families', () => {
    expect(advisoryFailureError('invalid_command').code).toBe('validation');
    expect(advisoryFailureError('malformed_document').code).toBe('validation');
    expect(advisoryFailureError('unsupported_origin').code).toBe('validation');
    expect(advisoryFailureError('authority_required').code).toBe('unauthorized');
    expect(advisoryFailureError('authority_rejected').code).toBe('forbidden');
    expect(advisoryFailureError('user_inactive')).toEqual(
      advisoryFailureError('authority_rejected'),
    );
    expect(advisoryFailureError('not_found').code).toBe('not_found');
    expect(advisoryFailureError('separation_of_duties_required').message).toBe(
      'The approval was not recorded.',
    );
    expect(advisoryFailureError('immutable_conflict').code).toBe('conflict');
    for (const outcome of [
      'malformed_persisted_state',
      'transaction_aborted',
      'database_unavailable',
      'internal_failure',
    ]) {
      expect(advisoryFailureError(outcome).message).toBe(
        'Maintainer-reviewed advisory storage is temporarily unavailable.',
      );
    }
    expect(JSON.stringify(advisoryFailureError('database_unavailable'))).not.toMatch(
      /sql|prisma|postgres|constraint/i,
    );
  });
});
