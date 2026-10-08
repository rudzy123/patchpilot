/**
 * Opaque discovery cursor.
 * The value binds a page to one ingestion and one examined pair.
 * It is not an acknowledgement and not authority.
 */

import {
  FINDING_DISCOVERY_CURSOR_SCHEMA_VERSION,
  FINDING_DISCOVERY_MAX_CURSOR_LENGTH,
} from './policy.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type FindingDiscoveryCursor = {
  readonly ingestionId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
};

export function encodeFindingDiscoveryCursor(cursor: FindingDiscoveryCursor): string {
  const payload = [
    FINDING_DISCOVERY_CURSOR_SCHEMA_VERSION,
    cursor.ingestionId,
    cursor.componentId,
    cursor.vulnerabilityId,
  ].join('.');
  return Buffer.from(payload, 'utf8').toString('base64url');
}

export function decodeFindingDiscoveryCursor(
  value: string,
): { readonly ok: true; readonly cursor: FindingDiscoveryCursor } | { readonly ok: false } {
  if (value.length === 0 || value.length > FINDING_DISCOVERY_MAX_CURSOR_LENGTH) {
    return { ok: false };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    return { ok: false };
  }
  const decoded = Buffer.from(value, 'base64url').toString('utf8');
  if (decoded.includes('\u0000') || decoded.length === 0) {
    return { ok: false };
  }
  const parts = decoded.split('.');
  if (parts.length !== 4 || parts[0] !== FINDING_DISCOVERY_CURSOR_SCHEMA_VERSION) {
    return { ok: false };
  }
  const ingestionId = parts[1];
  const componentId = parts[2];
  const vulnerabilityId = parts[3];
  if (
    ingestionId === undefined ||
    componentId === undefined ||
    vulnerabilityId === undefined ||
    !UUID_LOWER_PATTERN.test(ingestionId) ||
    !UUID_LOWER_PATTERN.test(componentId) ||
    !UUID_LOWER_PATTERN.test(vulnerabilityId)
  ) {
    return { ok: false };
  }
  return {
    ok: true,
    cursor: { ingestionId, componentId, vulnerabilityId },
  };
}
