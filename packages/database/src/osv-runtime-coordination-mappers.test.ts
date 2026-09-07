import { describe, expect, it } from 'vitest';

import {
  bigintToLeaseInteger,
  coerceLeaseRow,
  OsvRuntimeCoordinationMappingError,
} from './osv-runtime-coordination-mappers.js';

const BEYOND_SAFE = 9_007_199_254_740_993n;
const BIGINT_MAX = 9_223_372_036_854_775_807n;

describe('OSV runtime coordination BIGINT mapping', () => {
  it('preserves exact decimal strings above Number.MAX_SAFE_INTEGER', () => {
    expect(bigintToLeaseInteger(BEYOND_SAFE)).toBe('9007199254740993');
    expect(bigintToLeaseInteger('9007199254740993')).toBe('9007199254740993');
    expect(bigintToLeaseInteger(BIGINT_MAX)).toBe('9223372036854775807');
    expect(bigintToLeaseInteger(1)).toBe('1');
  });

  it('fails closed on unsafe Number values and non-positive integers', () => {
    expect(() => bigintToLeaseInteger(Number.MAX_SAFE_INTEGER + 2)).toThrow(
      OsvRuntimeCoordinationMappingError,
    );
    expect(() =>
      coerceLeaseRow({
        scope: 'osv_runtime_lease_scope_osv_gcs_public_export_v1',
        run_id: '22222222-2222-4222-8222-222222222222',
        holder_token_digest: 'a'.repeat(64),
        row_revision: Number.MAX_SAFE_INTEGER + 2,
        fencing_token: 1n,
        state: 'held',
        acquired_at: new Date('2026-09-07T12:00:00.000Z'),
        heartbeat_at: new Date('2026-09-07T12:00:00.000Z'),
        expires_at: new Date('2026-09-07T12:15:00.000Z'),
        released_at: null,
        release_reason: null,
      }),
    ).toThrow(OsvRuntimeCoordinationMappingError);
    expect(() => bigintToLeaseInteger(0)).toThrow(OsvRuntimeCoordinationMappingError);
    expect(() => bigintToLeaseInteger(-1n)).toThrow(OsvRuntimeCoordinationMappingError);
    expect(() => bigintToLeaseInteger('-1')).toThrow(OsvRuntimeCoordinationMappingError);
    expect(() =>
      coerceLeaseRow({
        scope: 'osv_runtime_lease_scope_osv_gcs_public_export_v1',
        run_id: '22222222-2222-4222-8222-222222222222',
        holder_token_digest: 'a'.repeat(64),
        row_revision: '-1',
        fencing_token: 1n,
        state: 'held',
        acquired_at: new Date('2026-09-07T12:00:00.000Z'),
        heartbeat_at: new Date('2026-09-07T12:00:00.000Z'),
        expires_at: new Date('2026-09-07T12:15:00.000Z'),
        released_at: null,
        release_reason: null,
      }),
    ).toThrow(OsvRuntimeCoordinationMappingError);
  });
});
