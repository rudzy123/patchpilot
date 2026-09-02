import { describe, expect, it } from 'vitest';

import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { cisaKevSynchronizationConfigFrom } from './intelligence-composition.js';

describe('intelligence composition helpers', () => {
  it('maps typed intelligence config without starting timers or contacting CISA', () => {
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const mapped = cisaKevSynchronizationConfigFrom(config.intelligence);
    expect(mapped.kevEnabled).toBe(true);
    expect(mapped.kevJobLeaseMs).toBe(config.intelligence.kevJobLeaseMs);
    expect(mapped.syncMaxAttempts).toBe(config.intelligence.syncMaxAttempts);
    expect(mapped.parserVersion).toBe(config.intelligence.parserVersion);
  });
});
