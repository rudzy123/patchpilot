import { err, ok, type Result } from '../result.js';
import { SBOM_LIST_CURSOR_VERSION, SBOM_RAW_TEXT_MAX_LENGTH, UUID_PATTERN } from './constants.js';
import { SBOM_INVALID_CURSOR } from './errors.js';
import type { SbomListCursor } from './types.js';

const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

export function encodeSbomListCursor(cursor: SbomListCursor): string {
  const payload = JSON.stringify({ v: cursor.v, r: cursor.r, i: cursor.i });
  return Buffer.from(payload, 'utf8').toString('base64url');
}

export function decodeSbomListCursor(raw: string): Result<SbomListCursor> {
  if (raw.length === 0 || raw.length > SBOM_RAW_TEXT_MAX_LENGTH) {
    return err(SBOM_INVALID_CURSOR);
  }

  let parsed: unknown;
  try {
    const json = Buffer.from(raw, 'base64url').toString('utf8');
    parsed = JSON.parse(json) as unknown;
  } catch {
    return err(SBOM_INVALID_CURSOR);
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return err(SBOM_INVALID_CURSOR);
  }

  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 3 || !keys.includes('v') || !keys.includes('r') || !keys.includes('i')) {
    return err(SBOM_INVALID_CURSOR);
  }

  if (record['v'] !== SBOM_LIST_CURSOR_VERSION) {
    return err(SBOM_INVALID_CURSOR);
  }

  const receivedAt = record['r'];
  const id = record['i'];
  if (typeof receivedAt !== 'string' || typeof id !== 'string') {
    return err(SBOM_INVALID_CURSOR);
  }

  if (!UTC_TIMESTAMP_PATTERN.test(receivedAt) || !UUID_PATTERN.test(id)) {
    return err(SBOM_INVALID_CURSOR);
  }

  return ok({
    v: SBOM_LIST_CURSOR_VERSION,
    r: receivedAt,
    i: id.toLowerCase(),
  });
}
