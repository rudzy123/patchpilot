/**
 * Session 13 Batch 3D-C Node.js AES-256-GCM cryptographic capability.
 * Synthetic protected identities and ephemeral test keys only.
 */

import { inspect } from 'node:util';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  admitOsvProtectedListingEvidenceAssociatedDataContext,
  admitOsvProtectedListingEvidenceCiphertextEnvelope,
  admitOsvProtectedListingObservation,
  classifyOsvPreRetrieval,
  cryptographicCapabilityOmitsGenericEncrypt,
  isOsvObjectKeyParsed,
  osvCanaryRuntimeVersionSetFingerprint,
  parseOsvObjectKey,
  type OsvProtectedListingObservation,
} from '@patchpilot/vulnerability-intelligence';

import { readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted } from '../../vulnerability-intelligence/dist/osv/canary-listing-observation-evidence-encryption/envelope.js';
import { readOsvProtectedListingObjectIdentitySecrets } from '../../vulnerability-intelligence/dist/osv/canary-listing-observation-evidence/identity.js';

import {
  createOsvProtectedListingEvidenceCryptographicCapability,
  createOsvProtectedListingEvidenceCryptographicCapabilityForVerification,
} from './osv-protected-listing-evidence-crypto.js';
import * as integrations from './index.js';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = join(here, '..', '..', '..');

const SYNTHETIC_KEY = 'crates.io/RUSTSEC-2000-0001.json';
const EVIDENCE_SET_ID = '99999999-9999-4999-8999-999999999999';
const OBSERVATION_ID = '88888888-8888-4888-8888-888888888888';
const LISTING_EXECUTION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROVIDER_CONTACT_AUTHORIZATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const REQUEST_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const RUN_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const PRODUCTION_COMPOSITION_FILES = [
  'apps/worker/src/main.ts',
  'apps/worker/src/app.ts',
  'apps/worker/src/intelligence-composition.ts',
  'apps/worker/src/intelligence-runtime.ts',
  'apps/worker/src/intelligence-scheduler.ts',
  'apps/worker/src/intelligence-sync-processor.ts',
  'apps/worker/src/queue-job-router.ts',
  'apps/worker/src/sbom-ingest-processor.ts',
  'apps/worker/src/outbox-relay-runtime.ts',
  'apps/api/src/app.ts',
  'apps/api/src/server.ts',
  'apps/api/src/intelligence-runtime.ts',
  'apps/api/src/intelligence-routes.ts',
  'apps/api/src/auth-runtime.ts',
  'packages/database/src/index.ts',
  'packages/config/src/intelligence.ts',
  'packages/config/src/server.ts',
] as const;

function classificationFor(key: string) {
  const parsed = parseOsvObjectKey(key);
  if (!isOsvObjectKeyParsed(parsed)) {
    throw new Error('invalid_object_key');
  }
  return classifyOsvPreRetrieval(parsed);
}

function admitObservation(overrides: Record<string, unknown> = {}): OsvProtectedListingObservation {
  const result = admitOsvProtectedListingObservation({
    listingExecutionId: LISTING_EXECUTION_ID,
    providerContactAuthorizationId: PROVIDER_CONTACT_AUTHORIZATION_ID,
    synchronizationRequestId: REQUEST_ID,
    synchronizationRunId: RUN_ID,
    runtimeVersionSetFingerprint: osvCanaryRuntimeVersionSetFingerprint(),
    observationOrdinal: 1,
    providerObjectKey: SYNTHETIC_KEY,
    providerGeneration: '1',
    declaredSizeBytes: 128,
    classification: classificationFor(
      typeof overrides['providerObjectKey'] === 'string'
        ? overrides['providerObjectKey']
        : SYNTHETIC_KEY,
    ),
    ...overrides,
  });
  if (!result.ok) {
    throw new Error(result.code);
  }
  return result.value;
}

function associatedDataInput(
  observation: OsvProtectedListingObservation,
  overrides: Record<string, unknown> = {},
) {
  return {
    evidenceSetId: EVIDENCE_SET_ID,
    observationId: OBSERVATION_ID,
    listingExecutionId: observation.listingExecutionId,
    providerContactAuthorizationId: observation.providerContactAuthorizationId,
    synchronizationRequestId: observation.synchronizationRequestId,
    synchronizationRunId: observation.synchronizationRunId,
    providerGeneration: '1',
    runtimeVersionSetFingerprint: observation.runtimeVersionSetFingerprint,
    declaredSizeBytes: 128,
    sourceFamilyClassification: 'known:RUSTSEC',
    classificationStatus: 'eligible',
    ...overrides,
  };
}

function authorization(
  context: {
    readonly evidenceSetId: string;
    readonly observationId: string;
    readonly synchronizationRequestId: string;
    readonly synchronizationRunId: string;
  },
  purpose = 'deterministic_candidate_selection_raw_identity_required',
) {
  return {
    purpose,
    evidenceSetId: context.evidenceSetId,
    observationId: context.observationId,
    synchronizationRequestId: context.synchronizationRequestId,
    synchronizationRunId: context.synchronizationRunId,
  };
}

function currentCapability(
  overrides: {
    readonly state?:
      | 'current'
      | 'decrypt_only'
      | 'rotation_required'
      | 'retired'
      | 'destroyed'
      | 'unavailable'
      | 'malformed'
      | 'inconsistent';
    readonly alias?: string;
    readonly keyMaterial?: Uint8Array;
    readonly historicalKeys?: readonly {
      readonly alias: string;
      readonly state: 'current' | 'decrypt_only' | 'rotation_required' | 'retired' | 'destroyed';
      readonly keyMaterial: Uint8Array;
    }[];
    readonly nonceProvider?: () => Uint8Array;
  } = {},
) {
  return createOsvProtectedListingEvidenceCryptographicCapabilityForVerification({
    currentKey: {
      alias: overrides.alias ?? 'osv.listing.evidence.k1',
      state: overrides.state ?? 'current',
      keyMaterial: overrides.keyMaterial ?? Uint8Array.from(randomBytes(32)),
    },
    ...(overrides.historicalKeys === undefined ? {} : { historicalKeys: overrides.historicalKeys }),
    ...(overrides.nonceProvider === undefined ? {} : { nonceProvider: overrides.nonceProvider }),
  });
}

function expectOk<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: string },
): T {
  if (!result.ok) {
    throw new Error(result.code);
  }
  return result.value;
}

function contextOf(
  observation: OsvProtectedListingObservation,
  overrides: Record<string, unknown> = {},
) {
  return expectOk(
    admitOsvProtectedListingEvidenceAssociatedDataContext(
      associatedDataInput(observation, overrides),
    ),
  );
}

describe('Session 13 Batch 3D-C AES-256-GCM capability', () => {
  it('protects and reveals a synthetic identity for an authorized purpose', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const keyMaterial = Uint8Array.from(randomBytes(32));
    const capability = currentCapability({ keyMaterial });
    expect(cryptographicCapabilityOmitsGenericEncrypt(capability)).toBe(true);
    const readiness = expectOk(await capability.inspectProtectedEvidenceCryptographicReadiness());
    expect(readiness.algorithmId).toBe('aes-256-gcm');
    expect(readiness.genericReady).toBe(false);
    expect(readiness.encryptionPermitted).toBe(true);
    expect(readiness.persistenceAvailable).toBe(false);
    expect(readiness.providerContactAuthorized).toBe(false);
    expect(readiness.plaintextFallbackConfigured).toBe(false);
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    expect(protectedValue.plaintextReturned).toBe(false);
    expect(protectedValue.persistenceOccurred).toBe(false);
    expect(protectedValue.providerContactOccurred).toBe(false);
    expect(protectedValue.retries).toBe(0);
    expect(protectedValue.envelope.algorithmId).toBe('aes-256-gcm');
    expect(protectedValue.envelope.encryptionExecuted).toBe(true);
    expect(protectedValue.envelope.containsPlaintext).toBe(false);
    expect(protectedValue.envelope.plaintextLength).toBe(Buffer.byteLength(SYNTHETIC_KEY, 'utf8'));
    const publicBlob = [
      JSON.stringify(protectedValue),
      inspect(protectedValue),
      JSON.stringify(protectedValue.envelope),
    ].join('\n');
    expect(publicBlob).not.toContain(SYNTHETIC_KEY);
    expect(publicBlob).not.toContain('"ciphertext"');
    expect(publicBlob).not.toContain('"nonce"');
    expect(publicBlob).not.toContain('"authenticationTag"');
    const revealed = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(contextOf(observation)),
      }),
    );
    expect(revealed.providerContactAuthorized).toBe(false);
    expect(revealed.bodyRetrievalAuthorized).toBe(false);
    expect(revealed.genericDecrypt).toBe(false);
    expect(JSON.stringify(revealed)).not.toContain(SYNTHETIC_KEY);
    const secrets = expectOk(readOsvProtectedListingObjectIdentitySecrets(revealed.identity));
    expect(secrets.providerObjectKey).toBe(SYNTHETIC_KEY);
    keyMaterial.fill(0);
  });

  it('rejects caller-selected nonce, algorithm, associated-data bytes, and unauthorized purposes', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const nonce = Uint8Array.from(randomBytes(12));
    expect(
      (
        await capability.protectOsvListingObjectIdentity({
          protectedIdentity: observation.protectedObjectIdentity,
          associatedDataContext: context,
          nonce,
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await capability.protectOsvListingObjectIdentity({
          protectedIdentity: observation.protectedObjectIdentity,
          associatedDataContext: context,
          algorithm: 'aes-256-gcm',
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await capability.protectOsvListingObjectIdentity({
          protectedIdentity: observation.protectedObjectIdentity,
          associatedDataContext: context,
          associatedData: new Uint8Array([1, 2, 3]),
        })
      ).ok,
    ).toBe(false);
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const unauthorized = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(contextOf(observation), 'debugging'),
    });
    expect(unauthorized.ok).toBe(false);
    if (!unauthorized.ok) {
      expect(unauthorized.code).toBe('reveal_purpose_unauthorized');
    }
    expect(JSON.stringify(unauthorized)).not.toContain(SYNTHETIC_KEY);
    const requestConstruction = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(
          contextOf(observation),
          'exact_generation_bound_request_construction',
        ),
      }),
    );
    expect(requestConstruction.decryptionExecuted).toBe(true);
    expect(requestConstruction.bodyRetrievalAuthorized).toBe(false);
  });

  it('rejects tampered ciphertext, nonce, and tag without returning plaintext', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const restricted = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(protectedValue.envelope),
    );
    const tampers = [
      {
        ciphertext: Uint8Array.from(restricted.ciphertext, (byte, index) =>
          index === 0 ? byte ^ 1 : byte,
        ),
      },
      {
        ciphertext: Uint8Array.from(restricted.ciphertext, (byte, index) =>
          index === Math.floor(restricted.ciphertext.byteLength / 2) ? byte ^ 1 : byte,
        ),
      },
      {
        ciphertext: Uint8Array.from(restricted.ciphertext, (byte, index) =>
          index === restricted.ciphertext.byteLength - 1 ? byte ^ 1 : byte,
        ),
      },
      {
        nonce: Uint8Array.from(restricted.nonce, (byte, index) => (index === 0 ? byte ^ 1 : byte)),
      },
      {
        authenticationTag: Uint8Array.from(restricted.authenticationTag, (byte, index) =>
          index === 0 ? byte ^ 1 : byte,
        ),
      },
    ] as const;
    for (const tamper of tampers) {
      const admitted = expectOk(
        admitOsvProtectedListingEvidenceCiphertextEnvelope({
          envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
          cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
          algorithmId: protectedValue.envelope.algorithmId,
          associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
          plaintextLength: protectedValue.envelope.plaintextLength,
          ciphertext: 'ciphertext' in tamper ? tamper.ciphertext : restricted.ciphertext,
          nonce: 'nonce' in tamper ? tamper.nonce : restricted.nonce,
          authenticationTag:
            'authenticationTag' in tamper ? tamper.authenticationTag : restricted.authenticationTag,
          keyReference: restricted.keyReference,
          rotationState: 'current',
          erasureState: 'not_erased',
        }),
      );
      const revealed = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: admitted,
        associatedDataContext: context,
        authorization: authorization(contextOf(observation)),
      });
      expect(revealed.ok).toBe(false);
      if (!revealed.ok) {
        expect(revealed.code).toBe('authentication_failed');
      }
      expect(JSON.stringify(revealed)).not.toContain(SYNTHETIC_KEY);
    }
  });

  it('rejects ciphertext transplanted across immutable context fields', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const substitutions: Record<string, unknown>[] = [
      { evidenceSetId: '11111111-1111-4111-8111-111111111111' },
      { observationId: '22222222-2222-4222-8222-222222222222' },
      { listingExecutionId: '33333333-3333-4333-8333-333333333333' },
      { providerContactAuthorizationId: '44444444-4444-4444-8444-444444444444' },
      { synchronizationRequestId: '55555555-5555-4555-8555-555555555555' },
      { synchronizationRunId: '66666666-6666-4666-8666-666666666666' },
      { providerGeneration: '2' },
      { declaredSizeBytes: 64 },
      { sourceFamilyClassification: 'known:GHSA' },
      {
        runtimeVersionSetFingerprint:
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    ];
    for (const substitution of substitutions) {
      const transplanted = associatedDataInput(observation, substitution);
      const admitted = expectOk(
        admitOsvProtectedListingEvidenceAssociatedDataContext(transplanted),
      );
      const revealed = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: transplanted,
        authorization: authorization(admitted),
      });
      expect(revealed.ok).toBe(false);
      if (!revealed.ok) {
        expect(['authentication_failed', 'binding_mismatch', 'associated_data_mismatch']).toContain(
          revealed.code,
        );
      }
      expect(JSON.stringify(revealed)).not.toContain(SYNTHETIC_KEY);
    }
  });

  it('rejects wrong, unknown, retired, destroyed, and decrypt-only encryption keys', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const current = Uint8Array.from(randomBytes(32));
    const other = Uint8Array.from(randomBytes(32));
    const capability = currentCapability({ keyMaterial: current });
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const wrong = currentCapability({ keyMaterial: other });
    const wrongReveal = await wrong.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(contextOf(observation)),
    });
    expect(wrongReveal.ok).toBe(false);
    const decryptOnly = currentCapability({ state: 'decrypt_only', keyMaterial: current });
    const decryptOnlyProtect = await decryptOnly.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    expect(decryptOnlyProtect.ok).toBe(false);
    const retired = currentCapability({ state: 'retired', keyMaterial: current });
    expect(
      (
        await retired.protectOsvListingObjectIdentity({
          protectedIdentity: observation.protectedObjectIdentity,
          associatedDataContext: context,
        })
      ).ok,
    ).toBe(false);
    const destroyed = currentCapability({
      state: 'destroyed',
      keyMaterial: current,
      historicalKeys: [
        { alias: 'osv.listing.evidence.k1', state: 'destroyed', keyMaterial: current },
      ],
    });
    const destroyedReveal = await destroyed.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(contextOf(observation)),
    });
    expect(destroyedReveal.ok).toBe(false);
    const historical = currentCapability({
      alias: 'osv.listing.evidence.k2',
      keyMaterial: other,
      historicalKeys: [
        { alias: 'osv.listing.evidence.k1', state: 'decrypt_only', keyMaterial: current },
      ],
    });
    const historicalReveal = expectOk(
      await historical.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(contextOf(observation)),
      }),
    );
    expect(historicalReveal.decryptionExecuted).toBe(true);
    current.fill(0);
    other.fill(0);
  });

  it('generates unique 12-byte nonces and rejects reused test-seam nonces', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const seen = new Set<string>();
    const capability = currentCapability({
      nonceProvider: () => Uint8Array.from(randomBytes(12)),
    });
    const first = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const second = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const firstNonce = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(first.envelope),
    );
    const secondNonce = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(second.envelope),
    );
    expect(firstNonce.nonce.byteLength).toBe(12);
    expect(secondNonce.nonce.byteLength).toBe(12);
    expect(Buffer.from(firstNonce.nonce).toString('hex')).not.toBe(
      Buffer.from(secondNonce.nonce).toString('hex'),
    );
    seen.add(Buffer.from(firstNonce.nonce).toString('hex'));
    seen.add(Buffer.from(secondNonce.nonce).toString('hex'));
    expect(seen.size).toBe(2);
    const fixed = Uint8Array.from(randomBytes(12));
    const reused = currentCapability({ nonceProvider: () => Uint8Array.from(fixed) });
    expectOk(
      await reused.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const duplicate = await reused.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) {
      expect(duplicate.code).toBe('nonce_reused');
    }
  });

  it('rotates under a new current key, verifies the replacement, and retains the prior envelope on failure', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const oldKey = Uint8Array.from(randomBytes(32));
    const newKey = Uint8Array.from(randomBytes(32));
    const original = currentCapability({ alias: 'osv.listing.evidence.kold', keyMaterial: oldKey });
    const protectedValue = expectOk(
      await original.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const rotating = currentCapability({
      alias: 'osv.listing.evidence.knew',
      keyMaterial: newKey,
      historicalKeys: [
        { alias: 'osv.listing.evidence.kold', state: 'decrypt_only', keyMaterial: oldKey },
      ],
    });
    const rotated = expectOk(
      await rotating.reprotectOsvListingObjectIdentityForAuthorizedRotation({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(contextOf(observation), 'approved_rotation_or_reencryption'),
      }),
    );
    expect(rotated.priorEnvelopeRetained).toBe(true);
    expect(rotated.replacementVerified).toBe(true);
    expect(rotated.plaintextReturned).toBe(false);
    expect(rotated.persistenceOccurred).toBe(false);
    expect(rotated.automaticRotation).toBe(false);
    const priorNonce = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(rotated.priorEnvelope),
    );
    const nextNonce = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(rotated.replacementEnvelope),
    );
    expect(Buffer.from(priorNonce.nonce).toString('hex')).not.toBe(
      Buffer.from(nextNonce.nonce).toString('hex'),
    );
    const destroyedCurrent = currentCapability({
      alias: 'osv.listing.evidence.knew',
      state: 'destroyed',
      keyMaterial: newKey,
      historicalKeys: [
        { alias: 'osv.listing.evidence.kold', state: 'decrypt_only', keyMaterial: oldKey },
      ],
    });
    const failed = await destroyedCurrent.reprotectOsvListingObjectIdentityForAuthorizedRotation({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(contextOf(observation), 'approved_rotation_or_reencryption'),
    });
    expect(failed.ok).toBe(false);
    const stillReadable = expectOk(
      await rotating.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(contextOf(observation), 'approved_rotation_or_reencryption'),
      }),
    );
    expect(stillReadable.decryptionExecuted).toBe(true);
    oldKey.fill(0);
    newKey.fill(0);
  });

  it('honors cancellation before encryption and after decryption without returning plaintext', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const aborted = new AbortController();
    aborted.abort();
    const cancelled = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
      signal: aborted.signal,
    });
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok) {
      expect(cancelled.code).toBe('cancelled');
    }
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const revealAbort = new AbortController();
    revealAbort.abort();
    const cancelledReveal = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(contextOf(observation)),
      signal: revealAbort.signal,
    });
    expect(cancelledReveal.ok).toBe(false);
    if (!cancelledReveal.ok) {
      expect(cancelledReveal.code).toBe('cancelled');
    }
  });

  it('protects concurrently without nonce reuse or plaintext fallback', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        capability.protectOsvListingObjectIdentity({
          protectedIdentity: observation.protectedObjectIdentity,
          associatedDataContext: context,
        }),
      ),
    );
    const envelopes = results.map((result) => expectOk(result).envelope);
    const nonces = envelopes.map((envelope) =>
      Buffer.from(
        expectOk(readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(envelope)).nonce,
      ).toString('hex'),
    );
    expect(new Set(nonces).size).toBe(nonces.length);
    const revealed = await Promise.all(
      envelopes.map((envelope) =>
        capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
          envelope,
          associatedDataContext: context,
          authorization: authorization(contextOf(observation)),
        }),
      ),
    );
    for (const result of revealed) {
      expect(result.ok).toBe(true);
    }
  });

  it('rejects a 513-byte identity and accepts a 512-byte synthetic identity', async () => {
    const exact = 'crates.io/' + 'A'.repeat(512 - 'crates.io/'.length - '.json'.length) + '.json';
    expect(Buffer.byteLength(exact, 'utf8')).toBe(512);
    const observation = admitObservation({ providerObjectKey: exact });
    const context = associatedDataInput(observation);
    const capability = currentCapability();
    const protectedValue = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    expect(protectedValue.ok).toBe(true);
    const over =
      'crates.io/' + 'A'.repeat(512 - 'crates.io/'.length - '.json'.length + 1) + '.json';
    expect(
      admitOsvProtectedListingObservation({
        listingExecutionId: LISTING_EXECUTION_ID,
        providerContactAuthorizationId: PROVIDER_CONTACT_AUTHORIZATION_ID,
        synchronizationRequestId: REQUEST_ID,
        synchronizationRunId: RUN_ID,
        runtimeVersionSetFingerprint: osvCanaryRuntimeVersionSetFingerprint(),
        observationOrdinal: 1,
        providerObjectKey: over,
        providerGeneration: '1',
        declaredSizeBytes: 128,
        classification: classificationFor(SYNTHETIC_KEY),
      }).ok,
    ).toBe(false);
  });

  it('does not export test seams or generic crypto from the public package index', () => {
    expect('createOsvProtectedListingEvidenceCryptographicCapability' in integrations).toBe(true);
    expect(
      'createOsvProtectedListingEvidenceCryptographicCapabilityForVerification' in integrations,
    ).toBe(false);
    expect('mutateOsvProtectedListingEvidenceRuntimeKeyStateForVerification' in integrations).toBe(
      false,
    );
    expect('mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification' in integrations).toBe(
      false,
    );
    expect('createOsvProtectedListingEvidenceRuntimeKeyCapability' in integrations).toBe(false);
    expect('encrypt' in integrations).toBe(false);
    expect('decrypt' in integrations).toBe(false);
    expect(() =>
      createOsvProtectedListingEvidenceCryptographicCapability({
        currentKey: {
          kind: 'osv_protected_listing_evidence_key_provisioning',
          alias: 'osv.listing.evidence.k1',
          state: 'current',
          byteLength: 32,
          encoding: 'hex',
          returnsRawKeyMaterial: false,
        },
        nonceProvider: () => Uint8Array.from(randomBytes(12)),
      } as never),
    ).toThrow(/malformed/);
  });

  it('is excluded from production composition and keeps OSV disabled', () => {
    for (const relative of PRODUCTION_COMPOSITION_FILES) {
      const source = readFileSync(join(workspaceRoot, relative), 'utf8');
      expect(source, relative).not.toContain(
        'createOsvProtectedListingEvidenceCryptographicCapability',
      );
      expect(source, relative).not.toContain('osv-protected-listing-evidence-crypto');
      expect(source, relative).not.toContain(
        'createOsvProtectedListingEvidenceCryptographicCapabilityForVerification',
      );
    }
    const intelligence = readFileSync(
      join(workspaceRoot, 'packages/config/src/intelligence.ts'),
      'utf8',
    );
    expect(intelligence).toContain('INTELLIGENCE_OSV_ENABLED must be false');
    expect(intelligence).toContain('INTELLIGENCE_OSV_ACQUISITION_HALT_DEFAULT = true');
    expect(existsSync(join(workspaceRoot, 'SESSION_13_BATCH_3D_C_COMPLETION.md'))).toBe(false);
    const source = readFileSync(join(here, 'osv-protected-listing-evidence-crypto.ts'), 'utf8');
    expect(source).not.toContain('organizationId');
    expect(source).not.toContain('findingId');
    expect(source).not.toContain('@prisma/client');
    expect(source).not.toContain('storage.googleapis.com');
    expect(source).not.toContain('createOsvGcsListingHttpsAdapter');
  });

  it('swallows event-sink failures without changing cryptographic outcomes', async () => {
    const observation = admitObservation();
    const context = associatedDataInput(observation);
    const capability = createOsvProtectedListingEvidenceCryptographicCapabilityForVerification({
      currentKey: {
        alias: 'osv.listing.evidence.k1',
        state: 'current',
        keyMaterial: Uint8Array.from(randomBytes(32)),
      },
      eventSink: {
        emit() {
          throw new Error('sink-must-not-become-authority');
        },
      },
    });
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    expect(protectedValue.encryptionExecuted).toBe(true);
  });
});
