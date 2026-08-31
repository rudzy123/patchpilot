import { Prisma } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';

export type PrismaClientLike = PrismaClient | Prisma.TransactionClient;

export function isRootPrismaClient(client: PrismaClientLike): client is PrismaClient {
  return typeof (client as PrismaClient).$transaction === 'function';
}

export const SHA256_HEX = /^[a-f0-9]{64}$/;
export const ARGON2ID_PHC_PREFIX = '$argon2id$';
export const ARGON2ID_PHC_MIN_LENGTH = 48;
export const ARGON2ID_PHC_MAX_LENGTH = 255;
export const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** Local @ dotted-domain. Labels exclude `.` so quantifiers do not overlap (CodeQL js/polynomial-redos). */
export const EMAIL_PATTERN = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function requireSha256(value: string, fieldName: string): string {
  if (!SHA256_HEX.test(value)) {
    throw new Error(`${fieldName} must be 64 lowercase hexadecimal characters.`);
  }

  return value;
}

export function requireArgon2idPhc(value: string, fieldName: string): string {
  if (
    !value.startsWith(ARGON2ID_PHC_PREFIX) ||
    value.length < ARGON2ID_PHC_MIN_LENGTH ||
    value.length > ARGON2ID_PHC_MAX_LENGTH
  ) {
    throw new Error(`${fieldName} must be an Argon2id PHC string between 48 and 255 characters.`);
  }

  return value;
}

export function requirePasswordRevision(value: number, fieldName: string): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${fieldName} must be an integer >= 1.`);
  }

  return value;
}

export function requirePositiveByteLength(value: number, fieldName: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer.`);
  }

  return value;
}

const VERSION_LABEL = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/;

export function requireVersionLabel(value: string, fieldName: string): string {
  if (!VERSION_LABEL.test(value) || value.length > 64) {
    throw new Error(`${fieldName} must be a bounded version label.`);
  }

  return value;
}

export function normalizeSlug(value: string, fieldName: string): string {
  const slug = value.trim().toLowerCase();
  if (!SLUG_PATTERN.test(slug) || slug.length < 2 || slug.length > 64) {
    throw new Error(`${fieldName} must be a 2-64 character lowercase slug.`);
  }

  return slug;
}

export function normalizeEmail(value: string): string {
  const email = value.trim().toLowerCase();
  // Length-cap before the regex so adversarial input cannot drive backtracking.
  if (email.length > 320 || !EMAIL_PATTERN.test(email)) {
    throw new Error('email must be a valid instance-level address.');
  }

  return email;
}

export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

export function asJsonObject(value: Prisma.JsonValue, fieldName: string): Prisma.InputJsonValue {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} must be a JSON object with schemaVersion.`);
  }

  if (!('schemaVersion' in value)) {
    throw new Error(`${fieldName} must include schemaVersion.`);
  }

  return value;
}

export function readJsonObject<T>(value: unknown, fieldName: string): T {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} must be a JSON object.`);
  }

  return value as T;
}

export function omitUndefined<T extends Record<string, unknown>>(input: T): T {
  const result = { ...input };
  for (const key of Object.keys(result)) {
    if (result[key] === undefined) {
      delete result[key];
    }
  }

  return result;
}
