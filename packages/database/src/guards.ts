import { Prisma } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';

export type PrismaClientLike = PrismaClient | Prisma.TransactionClient;

export const SHA256_HEX = /^[a-f0-9]{64}$/;
export const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function requireSha256(value: string, fieldName: string): string {
  if (!SHA256_HEX.test(value)) {
    throw new Error(`${fieldName} must be 64 lowercase hexadecimal characters.`);
  }

  return value;
}

export function requirePositiveByteLength(value: number, fieldName: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer.`);
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
  if (!EMAIL_PATTERN.test(email) || email.length > 320) {
    throw new Error('email must be a valid instance-level address.');
  }

  return email;
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
