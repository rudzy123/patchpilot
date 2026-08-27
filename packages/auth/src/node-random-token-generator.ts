import { randomBytes } from 'node:crypto';

import type { RandomTokenGenerator } from './random-token-generator.js';

export function createNodeRandomTokenGenerator(): RandomTokenGenerator {
  return {
    generate(byteLength: number): string {
      if (!Number.isInteger(byteLength) || byteLength < 1) {
        throw new Error('Token byte length must be a positive integer.');
      }

      return randomBytes(byteLength).toString('base64url');
    },
  };
}
