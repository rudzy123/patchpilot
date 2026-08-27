import { Writable } from 'node:stream';

import { argon2id, hash, needsRehash, verify } from 'argon2';
import { describe, expect, it } from 'vitest';

import { createLogger } from '@patchpilot/logger';

import { packageBoundary, passwordHashingLibrary } from './index.js';

const SYNTHETIC_PASSWORD = 'compat-test-only-12';
const OWASP_MINIMUM = {
  type: argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

function collectLogs(): { stream: Writable; text: () => string } {
  const chunks: Array<Buffer | string> = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk as Buffer | string);
      callback();
    },
  });

  return {
    stream,
    text: () => chunks.join(''),
  };
}

describe('@patchpilot/auth', () => {
  it('exports the package boundary and selected hashing library', () => {
    expect(packageBoundary).toBe('@patchpilot/auth');
    expect(passwordHashingLibrary).toBe('argon2');
  });
});

describe('argon2 compatibility', () => {
  it('hashes and verifies a synthetic password with Argon2id PHC', async () => {
    const collected = collectLogs();
    const logger = createLogger({
      service: 'auth-compat',
      level: 'info',
      pretty: false,
      destination: collected.stream,
    });

    const digest = await hash(SYNTHETIC_PASSWORD, OWASP_MINIMUM);

    // node-argon2 serializes PHC params as m,p,t via @phc/format object key order.
    expect(digest).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    await expect(verify(digest, SYNTHETIC_PASSWORD)).resolves.toBe(true);
    await expect(verify(digest, 'compat-test-wrong-12')).resolves.toBe(false);
    expect(
      needsRehash(digest, {
        memoryCost: OWASP_MINIMUM.memoryCost,
        timeCost: OWASP_MINIMUM.timeCost,
        parallelism: OWASP_MINIMUM.parallelism,
      }),
    ).toBe(false);
    expect(
      needsRehash(digest, {
        memoryCost: 65_536,
        timeCost: 3,
        parallelism: 1,
      }),
    ).toBe(true);

    logger.info({ event: 'argon2-compat', ok: true }, 'argon2 compatibility');
    logger.info({ passwordHash: digest, phc: digest }, 'must not emit digest');

    const output = collected.text();
    expect(output).toContain('argon2-compat');
    expect(output).toContain('[Redacted]');
    expect(output).not.toContain(digest);
    expect(output).not.toContain('$argon2id$');
    expect(output).not.toContain(SYNTHETIC_PASSWORD);
  });
});
