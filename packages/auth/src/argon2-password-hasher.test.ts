import { describe, expect, it } from 'vitest';

import { createArgon2PasswordHasher } from './argon2-password-hasher.js';
import { DUMMY_ARGON2ID_PHC } from './dummy-phc.js';

describe('Argon2 password hasher', () => {
  it('uses Argon2id PHC strings and needsRehash after parameter changes', async () => {
    const hasher = createArgon2PasswordHasher();
    const parameters = { memoryCost: 8_192, timeCost: 1, parallelism: 1 };
    const digest = await hasher.hash('compat-test-only-12', parameters);
    expect(digest.startsWith('$argon2id$')).toBe(true);
    await expect(hasher.verify(digest, 'compat-test-only-12')).resolves.toBe(true);
    await expect(hasher.verify(digest, 'compat-test-wrong-12')).resolves.toBe(false);
    expect(hasher.needsRehash(digest, parameters)).toBe(false);
    expect(hasher.needsRehash(digest, { memoryCost: 19_456, timeCost: 2, parallelism: 1 })).toBe(
      true,
    );
  });

  it('returns false for malformed PHC strings instead of throwing', async () => {
    const hasher = createArgon2PasswordHasher();
    await expect(hasher.verify('not-a-phc', 'compat-test-only-12')).resolves.toBe(false);
  });

  it('keeps a fixed dummy Argon2id PHC that belongs to no account', () => {
    expect(DUMMY_ARGON2ID_PHC.startsWith('$argon2id$v=19$')).toBe(true);
    expect(DUMMY_ARGON2ID_PHC.length).toBeGreaterThanOrEqual(48);
    expect(DUMMY_ARGON2ID_PHC.length).toBeLessThanOrEqual(255);
  });
});
