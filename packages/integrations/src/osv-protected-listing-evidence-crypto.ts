/**
 * Session 13 Batch 3D-C Node.js 24 AES-256-GCM protected listing-evidence
 * cryptographic capability. Construction performs no encryption, nonce
 * generation, provider call, or database call. Production composition does
 * not construct this factory. Test nonce seams are not accepted by the
 * production factory.
 */

import { createCipheriv, createDecipheriv, getCiphers, randomBytes } from 'node:crypto';

import {
  releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure,
  type OsvProtectedListingEvidenceKeyProvisioningHandle,
} from '@patchpilot/config/osv-listing-evidence-key';
import {
  createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform,
  type OsvProtectedListingEvidenceCryptographicCapabilityPort,
  type OsvProtectedListingEvidenceCryptographicEventSink,
  type OsvProtectedListingEvidenceKeyInspection,
  type OsvProtectedListingEvidencePlatformAeadPort,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityPort,
} from '@patchpilot/vulnerability-intelligence';

const KEY_BYTES = 32 as const;
const NONCE_BYTES = 12 as const;
const TAG_BYTES = 16 as const;
const AUTH_TAG_LENGTH = 16 as const;
const ALGORITHM = 'aes-256-gcm' as const;

type OsvProtectedListingEvidenceKeyState =
  | 'unconfigured'
  | 'configured'
  | 'current'
  | 'decrypt_only'
  | 'rotation_required'
  | 'retired'
  | 'destroyed'
  | 'unavailable'
  | 'malformed'
  | 'inconsistent'
  | 'failed';

type KeyRecord = {
  readonly alias: string;
  state: OsvProtectedListingEvidenceKeyState;
  readonly keyMaterial: Uint8Array;
};

type HandleRecords = WeakMap<object, KeyRecord>;

const verificationRecordsByHandle: HandleRecords = new WeakMap();
const currentRecordByCapability = new WeakMap<object, KeyRecord>();

const ADMITTED_KEY_STATES = new Set<OsvProtectedListingEvidenceKeyState>([
  'unconfigured',
  'configured',
  'current',
  'decrypt_only',
  'rotation_required',
  'retired',
  'destroyed',
  'unavailable',
  'malformed',
  'inconsistent',
  'failed',
]);

function isAllZero(value: Uint8Array): boolean {
  let acc = 0;
  for (const byte of value) {
    acc |= byte;
  }
  return acc === 0;
}

function copyBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value);
}

function joinBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const joined = new Uint8Array(left.byteLength + right.byteLength);
  joined.set(left, 0);
  joined.set(right, left.byteLength);
  return joined;
}

function zeroFill(value: Uint8Array): void {
  value.fill(0);
}

function fail<T extends string>(code: T): { readonly ok: false; readonly code: T } {
  return { ok: false, code };
}

function succeed<T>(value: T): { readonly ok: true; readonly value: T } {
  return { ok: true, value };
}

function keyStatePermitsEncryption(state: OsvProtectedListingEvidenceKeyState): boolean {
  return state === 'current';
}

function keyStatePermitsDecryption(state: OsvProtectedListingEvidenceKeyState): boolean {
  return state === 'current' || state === 'decrypt_only' || state === 'rotation_required';
}

function createHandle(
  record: KeyRecord,
  records: HandleRecords,
): OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle {
  const handle: OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle = {
    kind: 'osv_protected_listing_evidence_key_capability_handle',
    get keyState() {
      return record.state;
    },
    get encryptionPermitted() {
      return keyStatePermitsEncryption(record.state);
    },
    get decryptionPermitted() {
      return keyStatePermitsDecryption(record.state);
    },
    get keyVersionClassification() {
      return record.state === 'current' ? ('current' as const) : ('historical' as const);
    },
    returnsRawKeyMaterial: false,
  };
  Object.freeze(handle);
  records.set(handle, record);
  verificationRecordsByHandle.set(handle, record);
  return handle;
}

function admitKeyMaterial(input: {
  readonly alias: string;
  readonly state: OsvProtectedListingEvidenceKeyState;
  readonly keyMaterial: Uint8Array;
}):
  { ok: true; value: KeyRecord } | { ok: false; code: 'key_malformed' | 'invalid_key_reference' } {
  if (
    typeof input.alias !== 'string' ||
    !/^osv\.listing\.evidence\.k[a-z0-9]{1,24}$/.test(input.alias)
  ) {
    return fail('invalid_key_reference');
  }
  if (!(input.keyMaterial instanceof Uint8Array) || input.keyMaterial.byteLength !== KEY_BYTES) {
    return fail('key_malformed');
  }
  if (isAllZero(input.keyMaterial)) {
    return fail('key_malformed');
  }
  if (!ADMITTED_KEY_STATES.has(input.state)) {
    return fail('key_malformed');
  }
  return succeed({
    alias: input.alias,
    state: input.state,
    keyMaterial: copyBytes(input.keyMaterial),
  });
}

function createOsvProtectedListingEvidenceRuntimeKeyCapability(input: {
  readonly current: KeyRecord;
  readonly historical?: readonly KeyRecord[];
  readonly records: HandleRecords;
}): OsvProtectedListingEvidenceRuntimeKeyCapabilityPort {
  const current = input.current;
  const historical = input.historical === undefined ? [] : [...input.historical];
  const all = [current, ...historical];
  const records = input.records;

  function inspect() {
    const inspection: OsvProtectedListingEvidenceKeyInspection = {
      currentKeyState: current.state,
      encryptionPermitted: keyStatePermitsEncryption(current.state),
      decryptionPermitted: keyStatePermitsDecryption(current.state),
      rotationStatus: current.state,
      returnsRawKeyMaterial: false,
      genericDecryptAuthority: false,
    };
    return succeed(inspection);
  }

  function currentEncryptionCapability() {
    if (!keyStatePermitsEncryption(current.state)) {
      if (current.state === 'retired') {
        return fail('key_retired' as const);
      }
      if (current.state === 'destroyed') {
        return fail('key_destroyed' as const);
      }
      if (current.state === 'unavailable') {
        return fail('key_unavailable' as const);
      }
      if (current.state === 'malformed') {
        return fail('key_malformed' as const);
      }
      if (current.state === 'inconsistent') {
        return fail('key_state_inconsistent' as const);
      }
      if (current.state === 'rotation_required') {
        return fail('rotation_required' as const);
      }
      return fail('key_state_prohibited' as const);
    }
    return succeed(createHandle(current, records));
  }

  function approvedDecryptionCapability(keyReference: string) {
    if (typeof keyReference !== 'string') {
      return fail('unknown_key_reference' as const);
    }
    const record = all.find((candidate) => candidate.alias === keyReference);
    if (record === undefined) {
      return fail('unknown_key_reference' as const);
    }
    if (!keyStatePermitsDecryption(record.state)) {
      if (record.state === 'destroyed') {
        return fail('key_destroyed' as const);
      }
      if (record.state === 'retired') {
        return fail('key_retired' as const);
      }
      if (record.state === 'unavailable') {
        return fail('key_unavailable' as const);
      }
      if (record.state === 'malformed') {
        return fail('key_malformed' as const);
      }
      return fail('key_state_prohibited' as const);
    }
    return succeed(createHandle(record, records));
  }

  return {
    inspect,
    currentEncryptionCapability,
    approvedDecryptionCapability,
  };
}

function createNodeAes256GcmAead(input: {
  readonly nonceSource: () => Uint8Array;
  readonly rejectReusedNonce: boolean;
  readonly seenNonces: Set<string>;
  readonly records: HandleRecords;
}): OsvProtectedListingEvidencePlatformAeadPort {
  const records = input.records;
  return {
    inspectAvailability() {
      if (!getCiphers().includes(ALGORITHM)) {
        return fail('unknown_algorithm' as const);
      }
      return succeed({
        algorithmId: ALGORITHM,
        nonceBytes: NONCE_BYTES,
        tagBytes: TAG_BYTES,
        keyBytes: KEY_BYTES,
        nonceCapabilityAvailable: true as const,
        callerSelectedNonce: false as const,
        callerSelectedAlgorithm: false as const,
      });
    },
    generateNonce() {
      const supplied = input.nonceSource();
      if (!(supplied instanceof Uint8Array) || supplied.byteLength !== NONCE_BYTES) {
        return fail('nonce_generation_unavailable' as const);
      }
      const nonce = copyBytes(supplied);
      if (nonce.byteLength !== NONCE_BYTES || isAllZero(nonce)) {
        zeroFill(nonce);
        return fail('nonce_generation_unavailable' as const);
      }
      if (input.rejectReusedNonce === true) {
        const hex = Buffer.from(nonce).toString('hex');
        if (input.seenNonces.has(hex)) {
          zeroFill(nonce);
          return fail('nonce_reused' as const);
        }
        input.seenNonces.add(hex);
      }
      return succeed(nonce);
    },
    seal(request) {
      const record = records.get(request.keyHandle);
      if (record === undefined) {
        return fail('key_unavailable' as const);
      }
      if (!keyStatePermitsEncryption(record.state)) {
        return fail('key_state_prohibited' as const);
      }
      if (request.nonce.byteLength !== NONCE_BYTES || isAllZero(request.nonce)) {
        return fail('malformed_nonce' as const);
      }
      const key = copyBytes(record.keyMaterial);
      const nonce = copyBytes(request.nonce);
      const plaintext = copyBytes(request.plaintext);
      const associatedData = copyBytes(request.associatedData);
      let encrypted: Uint8Array | undefined;
      try {
        const cipher = createCipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LENGTH });
        cipher.setAAD(associatedData);
        encrypted = joinBytes(
          Uint8Array.from(cipher.update(plaintext)),
          Uint8Array.from(cipher.final()),
        );
        const tag = Uint8Array.from(cipher.getAuthTag());
        const ciphertext = copyBytes(encrypted);
        zeroFill(encrypted);
        encrypted = undefined;
        if (tag.byteLength !== TAG_BYTES) {
          zeroFill(ciphertext);
          zeroFill(tag);
          return fail('encryption_failed' as const);
        }
        return succeed({
          ciphertext,
          authenticationTag: tag,
          keyReference: record.alias,
        });
      } catch {
        if (encrypted !== undefined) {
          zeroFill(encrypted);
        }
        return fail('encryption_failed' as const);
      } finally {
        zeroFill(key);
        zeroFill(nonce);
        zeroFill(plaintext);
        zeroFill(associatedData);
      }
    },
    open(request) {
      const record = records.get(request.keyHandle);
      if (record === undefined) {
        return fail('key_unavailable' as const);
      }
      if (!keyStatePermitsDecryption(record.state)) {
        if (record.state === 'destroyed') {
          return fail('key_destroyed' as const);
        }
        return fail('key_state_prohibited' as const);
      }
      if (
        request.nonce.byteLength !== NONCE_BYTES ||
        isAllZero(request.nonce) ||
        request.authenticationTag.byteLength !== TAG_BYTES
      ) {
        return fail('authentication_failed' as const);
      }
      const key = copyBytes(record.keyMaterial);
      const nonce = copyBytes(request.nonce);
      const ciphertext = copyBytes(request.ciphertext);
      const tag = copyBytes(request.authenticationTag);
      const associatedData = copyBytes(request.associatedData);
      let unauthenticated: Uint8Array | undefined;
      let last: Uint8Array | undefined;
      try {
        const decipher = createDecipheriv(ALGORITHM, key, nonce, {
          authTagLength: AUTH_TAG_LENGTH,
        });
        decipher.setAAD(associatedData);
        decipher.setAuthTag(tag);
        unauthenticated = Uint8Array.from(decipher.update(ciphertext));
        last = Uint8Array.from(decipher.final());
        const combined = joinBytes(unauthenticated, last);
        zeroFill(unauthenticated);
        zeroFill(last);
        unauthenticated = undefined;
        last = undefined;
        return succeed(combined);
      } catch {
        if (unauthenticated !== undefined) {
          zeroFill(unauthenticated);
        }
        if (last !== undefined) {
          zeroFill(last);
        }
        return fail('authentication_failed' as const);
      } finally {
        zeroFill(key);
        zeroFill(nonce);
        zeroFill(ciphertext);
        zeroFill(tag);
        zeroFill(associatedData);
      }
    },
  };
}

function recordFromProvisioningHandle(
  handle: OsvProtectedListingEvidenceKeyProvisioningHandle,
):
  | { ok: true; value: KeyRecord }
  | { ok: false; code: 'key_unavailable' | 'key_malformed' | 'invalid_key_reference' } {
  const released = releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure(handle);
  if (!released.ok) {
    return fail(released.code === 'invalid_enum' ? 'key_malformed' : released.code);
  }
  const admitted = admitKeyMaterial({
    alias: released.value.alias,
    state: released.value.state as OsvProtectedListingEvidenceKeyState,
    keyMaterial: released.value.keyMaterial,
  });
  zeroFill(released.value.keyMaterial);
  return admitted;
}

function createCapabilityFromRecords(input: {
  readonly current: KeyRecord;
  readonly historical?: readonly KeyRecord[];
  readonly eventSink?: OsvProtectedListingEvidenceCryptographicEventSink;
  readonly nonceSource: () => Uint8Array;
  readonly rejectReusedNonce: boolean;
}): OsvProtectedListingEvidenceCryptographicCapabilityPort {
  const records: HandleRecords = new WeakMap();
  const keyCapability = createOsvProtectedListingEvidenceRuntimeKeyCapability({
    current: input.current,
    records,
    ...(input.historical === undefined ? {} : { historical: input.historical }),
  });
  const aead = createNodeAes256GcmAead({
    nonceSource: input.nonceSource,
    rejectReusedNonce: input.rejectReusedNonce,
    seenNonces: new Set<string>(),
    records,
  });
  const dependencies: {
    readonly keyCapability: OsvProtectedListingEvidenceRuntimeKeyCapabilityPort;
    readonly aead: OsvProtectedListingEvidencePlatformAeadPort;
    readonly eventSink?: OsvProtectedListingEvidenceCryptographicEventSink;
  } = {
    keyCapability,
    aead,
  };
  if (input.eventSink !== undefined) {
    const capability = createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform({
      ...dependencies,
      eventSink: input.eventSink,
    });
    currentRecordByCapability.set(capability, input.current);
    return capability;
  }
  const capability =
    createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform(dependencies);
  currentRecordByCapability.set(capability, input.current);
  return capability;
}

function productionNonceSource(): Uint8Array {
  return Uint8Array.from(randomBytes(NONCE_BYTES));
}

export function createOsvProtectedListingEvidenceCryptographicCapability(input: {
  readonly currentKey: OsvProtectedListingEvidenceKeyProvisioningHandle;
  readonly historicalKeys?: readonly OsvProtectedListingEvidenceKeyProvisioningHandle[];
  readonly eventSink?: OsvProtectedListingEvidenceCryptographicEventSink;
}): OsvProtectedListingEvidenceCryptographicCapabilityPort {
  if (
    typeof input !== 'object' ||
    input === null ||
    Object.getPrototypeOf(input) !== Object.prototype
  ) {
    throw new Error('cryptographic capability construction is malformed');
  }
  const allowed = new Set(['currentKey', 'historicalKeys', 'eventSink']);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) {
      throw new Error('cryptographic capability construction is malformed');
    }
  }
  if (Object.hasOwn(input, 'nonceProvider') || Object.hasOwn(input, 'algorithm')) {
    throw new Error('cryptographic capability construction is malformed');
  }
  const current = recordFromProvisioningHandle(input.currentKey);
  if (!current.ok) {
    throw new Error('cryptographic capability construction is malformed');
  }
  const historical: KeyRecord[] = [];
  if (input.historicalKeys !== undefined) {
    for (const handle of input.historicalKeys) {
      const record = recordFromProvisioningHandle(handle);
      if (!record.ok) {
        throw new Error('cryptographic capability construction is malformed');
      }
      historical.push(record.value);
    }
  }
  return createCapabilityFromRecords({
    current: current.value,
    ...(historical.length > 0 ? { historical } : {}),
    ...(input.eventSink === undefined ? {} : { eventSink: input.eventSink }),
    nonceSource: productionNonceSource,
    rejectReusedNonce: false,
  });
}

export function createOsvProtectedListingEvidenceCryptographicCapabilityForVerification(input: {
  readonly currentKey: {
    readonly alias: string;
    readonly state: OsvProtectedListingEvidenceKeyState;
    readonly keyMaterial: Uint8Array;
  };
  readonly historicalKeys?: readonly {
    readonly alias: string;
    readonly state: OsvProtectedListingEvidenceKeyState;
    readonly keyMaterial: Uint8Array;
  }[];
  readonly nonceProvider?: () => Uint8Array;
  readonly eventSink?: OsvProtectedListingEvidenceCryptographicEventSink;
}): OsvProtectedListingEvidenceCryptographicCapabilityPort {
  const current = admitKeyMaterial(input.currentKey);
  if (!current.ok) {
    throw new Error('verification cryptographic capability is malformed');
  }
  const historical: KeyRecord[] = [];
  if (input.historicalKeys !== undefined) {
    for (const key of input.historicalKeys) {
      const record = admitKeyMaterial(key);
      if (!record.ok) {
        throw new Error('verification cryptographic capability is malformed');
      }
      historical.push(record.value);
    }
  }
  const injectedNonce = input.nonceProvider;
  const nonceSource = injectedNonce === undefined ? productionNonceSource : () => injectedNonce();
  return createCapabilityFromRecords({
    current: current.value,
    ...(historical.length > 0 ? { historical } : {}),
    ...(input.eventSink === undefined ? {} : { eventSink: input.eventSink }),
    nonceSource,
    rejectReusedNonce: input.nonceProvider !== undefined,
  });
}

export function mutateOsvProtectedListingEvidenceRuntimeKeyStateForVerification(
  handle: OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle,
  state: OsvProtectedListingEvidenceKeyState,
): void {
  const record = verificationRecordsByHandle.get(handle);
  if (record === undefined) {
    return;
  }
  if (!ADMITTED_KEY_STATES.has(state)) {
    return;
  }
  record.state = state;
}

export function mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification(
  capability: OsvProtectedListingEvidenceCryptographicCapabilityPort,
  state: OsvProtectedListingEvidenceKeyState,
): void {
  const record = currentRecordByCapability.get(capability);
  if (record === undefined) {
    return;
  }
  if (!ADMITTED_KEY_STATES.has(state)) {
    return;
  }
  record.state = state;
}
