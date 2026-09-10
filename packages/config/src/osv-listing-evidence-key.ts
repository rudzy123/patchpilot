/**
 * Session 13 Batch 3D-C protected listing-evidence key provisioning.
 * Operator-supplied runtime secret. No default. Not loaded by
 * loadServerConfig. Process environment is read only here.
 */

import { inspect } from 'node:util';

import { readOptional } from './read-env.js';

export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME =
  'INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL' as const;
export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME =
  'INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS' as const;
export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME =
  'INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE' as const;

export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_BYTES = 32 as const;
export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_HEX_PATTERN = /^[a-f0-9]{64}$/;
export const INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_PATTERN =
  /^osv\.listing\.evidence\.k[a-z0-9]{1,24}$/;

export const intelligenceOsvListingEvidenceKeyStates = [
  'current',
  'decrypt_only',
  'rotation_required',
  'retired',
  'destroyed',
  'unavailable',
  'malformed',
  'inconsistent',
] as const;
export type IntelligenceOsvListingEvidenceKeyState =
  (typeof intelligenceOsvListingEvidenceKeyStates)[number];

export type OsvProtectedListingEvidenceKeyProvisioningHandle = {
  readonly kind: 'osv_protected_listing_evidence_key_provisioning';
  readonly alias: string;
  readonly state: IntelligenceOsvListingEvidenceKeyState;
  readonly byteLength: 32;
  readonly encoding: 'hex';
  readonly returnsRawKeyMaterial: false;
};

export type OsvProtectedListingEvidenceKeyProvisioningResult<T> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly code: 'key_unavailable' | 'key_malformed' | 'invalid_key_reference' | 'invalid_enum';
    };

const materialByHandle = new WeakMap<object, Uint8Array>();

function redactHandle(handle: OsvProtectedListingEvidenceKeyProvisioningHandle): void {
  Object.defineProperty(handle, 'toString', {
    value: () => 'OsvProtectedListingEvidenceKeyProvisioning{redacted}',
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(handle, inspect.custom, {
    value: () => 'OsvProtectedListingEvidenceKeyProvisioning{redacted}',
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(handle, 'toJSON', {
    value: () => ({
      kind: 'osv_protected_listing_evidence_key_provisioning',
      encoding: 'hex',
      byteLength: 32,
      returnsRawKeyMaterial: false,
    }),
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.freeze(handle);
}

function isAllZero(value: Uint8Array): boolean {
  let acc = 0;
  for (const byte of value) {
    acc |= byte;
  }
  return acc === 0;
}

function parseHexKeyMaterial(
  raw: string,
): OsvProtectedListingEvidenceKeyProvisioningResult<Uint8Array> {
  if (!INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_HEX_PATTERN.test(raw)) {
    return { ok: false, code: 'key_malformed' };
  }
  const bytes = new Uint8Array(INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_BYTES);
  for (let index = 0; index < INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_BYTES; index += 1) {
    const slice = raw.slice(index * 2, index * 2 + 2);
    bytes[index] = Number.parseInt(slice, 16);
  }
  if (isAllZero(bytes)) {
    bytes.fill(0);
    return { ok: false, code: 'key_malformed' };
  }
  return { ok: true, value: bytes };
}

export function loadOsvProtectedListingEvidenceKeyProvisioningFrom(
  env: Readonly<Record<string, string | undefined>>,
): OsvProtectedListingEvidenceKeyProvisioningResult<OsvProtectedListingEvidenceKeyProvisioningHandle> {
  const material = readOptional(env, INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME);
  if (material === undefined) {
    return { ok: false, code: 'key_unavailable' };
  }
  const alias = readOptional(env, INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME);
  if (alias === undefined || !INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_PATTERN.test(alias)) {
    return { ok: false, code: 'invalid_key_reference' };
  }
  if (alias.includes('://') || alias.includes('/') || alias.startsWith('arn:')) {
    return { ok: false, code: 'invalid_key_reference' };
  }
  const stateRaw = readOptional(env, INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME);
  if (
    stateRaw === undefined ||
    !(intelligenceOsvListingEvidenceKeyStates as readonly string[]).includes(stateRaw)
  ) {
    return { ok: false, code: 'invalid_enum' };
  }
  const parsed = parseHexKeyMaterial(material);
  if (!parsed.ok) {
    return parsed;
  }
  const handle: OsvProtectedListingEvidenceKeyProvisioningHandle = {
    kind: 'osv_protected_listing_evidence_key_provisioning',
    alias,
    state: stateRaw as IntelligenceOsvListingEvidenceKeyState,
    byteLength: INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_BYTES,
    encoding: 'hex',
    returnsRawKeyMaterial: false,
  };
  redactHandle(handle);
  materialByHandle.set(handle, Uint8Array.from(parsed.value));
  parsed.value.fill(0);
  return { ok: true, value: handle };
}

export function releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure(
  handle: OsvProtectedListingEvidenceKeyProvisioningHandle,
): OsvProtectedListingEvidenceKeyProvisioningResult<{
  readonly alias: string;
  readonly state: IntelligenceOsvListingEvidenceKeyState;
  readonly keyMaterial: Uint8Array;
}> {
  if (handle.kind !== 'osv_protected_listing_evidence_key_provisioning') {
    return { ok: false, code: 'key_malformed' };
  }
  const stored = materialByHandle.get(handle);
  if (stored === undefined) {
    return { ok: false, code: 'key_unavailable' };
  }
  return {
    ok: true,
    value: {
      alias: handle.alias,
      state: handle.state,
      keyMaterial: Uint8Array.from(stored),
    },
  };
}
