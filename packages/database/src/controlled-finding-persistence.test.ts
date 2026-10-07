import { describe, expect, it } from 'vitest';

import * as persistence from './controlled-finding-persistence.js';
import * as database from './index.js';

describe('controlled finding persistence export', () => {
  it('exposes only the two API persistence factories', () => {
    expect(Object.keys(persistence).sort()).toEqual([
      'createControlledFindingCreationPersistence',
      'createControlledFindingInspectionPersistence',
    ]);
    expect(Object.keys(database).filter((name) => /finding/i.test(name))).toEqual([]);
  });
});
