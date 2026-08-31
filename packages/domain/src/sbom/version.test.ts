import { describe, expect, it } from 'vitest';

import { FORBIDDEN_KNOWN_VERSION_STRINGS } from './constants.js';
import {
  fromOccurrenceVersionColumns,
  knownComponentVersion,
  parseComponentVersion,
  toOccurrenceVersionColumns,
  unknownComponentVersion,
} from './version.js';

describe('component version', () => {
  it('accepts a known non-empty observed version', () => {
    const known = knownComponentVersion('1.2.3');
    expect(known).toEqual({ ok: true, value: { kind: 'known', value: '1.2.3' } });
    if (!known.ok) {
      return;
    }
    expect(toOccurrenceVersionColumns(known.value)).toEqual({
      ok: true,
      value: { versionKnown: true, version: '1.2.3' },
    });
    expect(fromOccurrenceVersionColumns({ versionKnown: true, version: '1.2.3' })).toEqual(known);
  });

  it('represents unknown version without an observed value', () => {
    const unknown = unknownComponentVersion();
    expect(unknown).toEqual({ kind: 'unknown' });
    expect(unknown).not.toHaveProperty('value');
    expect(toOccurrenceVersionColumns(unknown)).toEqual({
      ok: true,
      value: { versionKnown: false, version: '' },
    });
    expect(fromOccurrenceVersionColumns({ versionKnown: false, version: '' })).toEqual({
      ok: true,
      value: { kind: 'unknown' },
    });
  });

  it('rejects a known empty version', () => {
    expect(knownComponentVersion('').ok).toBe(false);
    expect(parseComponentVersion({ kind: 'known', value: '' }).ok).toBe(false);
    expect(fromOccurrenceVersionColumns({ versionKnown: true, version: '' }).ok).toBe(false);
  });

  it('rejects *, latest, and unknown as known ComponentVersion values', () => {
    // Session 8 rejects these as known values. They may appear only as literal
    // observed evidence if a future explicit policy permits them.
    for (const sentinel of FORBIDDEN_KNOWN_VERSION_STRINGS) {
      expect(knownComponentVersion(sentinel).ok).toBe(false);
      expect(parseComponentVersion({ kind: 'known', value: sentinel }).ok).toBe(false);
      expect(toOccurrenceVersionColumns({ kind: 'known', value: sentinel }).ok).toBe(false);
      expect(fromOccurrenceVersionColumns({ versionKnown: true, version: sentinel }).ok).toBe(
        false,
      );
    }
    expect(knownComponentVersion('LATEST').ok).toBe(false);
    expect(knownComponentVersion('Unknown').ok).toBe(false);
  });

  it('rejects unknown versions that carry a placeholder observed value', () => {
    expect(fromOccurrenceVersionColumns({ versionKnown: false, version: '*' }).ok).toBe(false);
    expect(
      parseComponentVersion({ kind: 'unknown', value: '' } as unknown as { kind: 'unknown' }).ok,
    ).toBe(false);
  });
});
