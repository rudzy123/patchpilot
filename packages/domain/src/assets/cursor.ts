import { err, ok, type Result } from '../result.js';
import { ASSET_LIST_CURSOR_VERSION } from './constants.js';
import { ASSET_INVALID_CURSOR } from './errors.js';
import type { AssetListCursor } from './types.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function encodeAssetListCursor(cursor: AssetListCursor): string {
  const payload = JSON.stringify({ v: cursor.v, n: cursor.n, i: cursor.i });
  return Buffer.from(payload, 'utf8').toString('base64url');
}

export function decodeAssetListCursor(raw: string): Result<AssetListCursor> {
  if (raw.length === 0 || raw.length > 4096) {
    return err(ASSET_INVALID_CURSOR);
  }

  let parsed: unknown;
  try {
    const json = Buffer.from(raw, 'base64url').toString('utf8');
    parsed = JSON.parse(json) as unknown;
  } catch {
    return err(ASSET_INVALID_CURSOR);
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return err(ASSET_INVALID_CURSOR);
  }

  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 3 || !keys.includes('v') || !keys.includes('n') || !keys.includes('i')) {
    return err(ASSET_INVALID_CURSOR);
  }

  if (record['v'] !== ASSET_LIST_CURSOR_VERSION) {
    return err(ASSET_INVALID_CURSOR);
  }

  const name = record['n'];
  const id = record['i'];
  if (typeof name !== 'string' || name.length === 0 || typeof id !== 'string') {
    return err(ASSET_INVALID_CURSOR);
  }

  if (!UUID_PATTERN.test(id)) {
    return err(ASSET_INVALID_CURSOR);
  }

  return ok({
    v: ASSET_LIST_CURSOR_VERSION,
    n: name,
    i: id.toLowerCase(),
  });
}
