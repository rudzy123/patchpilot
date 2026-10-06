import { describe, expect, it } from 'vitest';

import {
  formatCleanupFailure,
  redactConnectionSecrets,
  withCleanupOnFailure,
} from './integration-database-cleanup.js';

describe('integration database cleanup reporting', () => {
  it('redacts connection strings from cleanup reports', () => {
    const message = formatCleanupFailure(
      new Error(
        'connect postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot_it_api_1_abcdef012345 failed',
      ),
    );
    expect(message).toContain('integration database cleanup failed');
    expect(message).toContain('postgresql://<redacted>');
    expect(message).not.toContain('patchpilot-dev-not-for-production');
    expect(redactConnectionSecrets('postgres://user:secret@localhost/patchpilot')).not.toContain(
      'secret',
    );
  });

  it('preserves the original failure when cleanup also fails', async () => {
    let cleanupRan = false;
    await expect(
      withCleanupOnFailure(
        async () => {
          throw new Error('original failure');
        },
        async () => {
          cleanupRan = true;
          throw new Error(
            'cleanup postgresql://patchpilot:secret@127.0.0.1:55432/patchpilot_it_api_1_abcdef012345',
          );
        },
      ),
    ).rejects.toThrow('original failure');
    expect(cleanupRan).toBe(true);
  });

  it('returns the operation result when cleanup is not needed', async () => {
    let cleanupRan = false;
    await expect(
      withCleanupOnFailure(
        async () => 'ready',
        async () => {
          cleanupRan = true;
        },
      ),
    ).resolves.toBe('ready');
    expect(cleanupRan).toBe(false);
  });
});
