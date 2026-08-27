import type { AuthConfig } from '@patchpilot/config';

export type Argon2Parameters = {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
};

export type PasswordHasher = {
  hash(password: string, parameters: Argon2Parameters): Promise<string>;
  verify(passwordHash: string, password: string): Promise<boolean>;
  needsRehash(passwordHash: string, parameters: Argon2Parameters): boolean;
};

export function argon2ParametersFromAuthConfig(
  auth: Pick<AuthConfig, 'argon2MemoryKib' | 'argon2TimeCost' | 'argon2Parallelism'>,
): Argon2Parameters {
  return {
    memoryCost: auth.argon2MemoryKib,
    timeCost: auth.argon2TimeCost,
    parallelism: auth.argon2Parallelism,
  };
}
