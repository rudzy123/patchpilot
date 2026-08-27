import { argon2id, hash, needsRehash, verify } from 'argon2';

import type { Argon2Parameters, PasswordHasher } from './password-hasher.js';

export function createArgon2PasswordHasher(): PasswordHasher {
  return {
    async hash(password: string, parameters: Argon2Parameters): Promise<string> {
      return hash(password, {
        type: argon2id,
        memoryCost: parameters.memoryCost,
        timeCost: parameters.timeCost,
        parallelism: parameters.parallelism,
      });
    },

    async verify(passwordHash: string, password: string): Promise<boolean> {
      try {
        return await verify(passwordHash, password);
      } catch {
        return false;
      }
    },

    needsRehash(passwordHash: string, parameters: Argon2Parameters): boolean {
      return needsRehash(passwordHash, {
        memoryCost: parameters.memoryCost,
        timeCost: parameters.timeCost,
        parallelism: parameters.parallelism,
      });
    },
  };
}
