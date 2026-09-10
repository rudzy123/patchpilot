/**
 * Session 13 Batch 3D-C-R adversarial review of the uncomposed AES-256-GCM
 * capability. Synthetic identities and ephemeral test keys only.
 */

import { inspect } from 'node:util';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  admitOsvProtectedListingEvidenceAssociatedDataContext,
  admitOsvProtectedListingEvidenceCiphertextEnvelope,
  admitOsvProtectedListingObservation,
  classifyOsvPreRetrieval,
  isOsvObjectKeyParsed,
  osvCanaryRuntimeVersionSetFingerprint,
  parseOsvObjectKey,
  type OsvProtectedListingObservation,
} from '@patchpilot/vulnerability-intelligence';

import { readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted } from '../../vulnerability-intelligence/dist/osv/canary-listing-observation-evidence-encryption/envelope.js';
import { readOsvProtectedListingObjectIdentitySecrets } from '../../vulnerability-intelligence/dist/osv/canary-listing-observation-evidence/identity.js';

import {
  createOsvProtectedListingEvidenceCryptographicCapabilityForVerification,
  mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification,
} from './osv-protected-listing-evidence-crypto.js';
import * as integrations from './index.js';

const here = dirname(fileURLToPath(import.meta.url));

const SYNTHETIC_KEY = 'crates.io/RUSTSEC-2000-0001.json';
const EVIDENCE_SET_ID = '99999999-9999-4999-8999-999999999999';
const OBSERVATION_ID = '88888888-8888-4888-8888-888888888888';
const LISTING_EXECUTION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROVIDER_CONTACT_AUTHORIZATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const REQUEST_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const RUN_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const PROHIBITED_PURPOSES = [
  'public_evidence_rendering',
  'logs',
  'metrics',
  'general_administration',
  'tenant_api',
  'web_ui',
  'listing_report',
  'bulk_export',
  'debugging',
  'arbitrary_search',
  'package_matching',
  'finding_creation',
  'provider_inventory_browsing',
  'true',
  'canDecrypt',
] as const;

function classificationFor(key: string) {
  const parsed = parseOsvObjectKey(key);
  if (!isOsvObjectKeyParsed(parsed)) {
    throw new Error('invalid_object_key');
  }
  return classifyOsvPreRetrieval(parsed);
}

function admitObservation(): OsvProtectedListingObservation {
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
    classification: classificationFor(SYNTHETIC_KEY),
  });
  if (!result.ok) {
    throw new Error(result.code);
  }
  return result.value;
}

function associatedDataInput(overrides: Record<string, unknown> = {}) {
  return {
    evidenceSetId: EVIDENCE_SET_ID,
    observationId: OBSERVATION_ID,
    listingExecutionId: LISTING_EXECUTION_ID,
    providerContactAuthorizationId: PROVIDER_CONTACT_AUTHORIZATION_ID,
    synchronizationRequestId: REQUEST_ID,
    synchronizationRunId: RUN_ID,
    providerGeneration: '1',
    runtimeVersionSetFingerprint: osvCanaryRuntimeVersionSetFingerprint(),
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

describe('Session 13 Batch 3D-C-R cryptographic capability adversarial review', () => {
  it('cancels after invocation begins without returning plaintext or an envelope', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const capability = currentCapability();
    const protectAbort = new AbortController();
    const protectPending = capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
      signal: protectAbort.signal,
    });
    protectAbort.abort();
    const cancelledProtect = await protectPending;
    expect(cancelledProtect.ok).toBe(false);
    if (!cancelledProtect.ok) {
      expect(cancelledProtect.code).toBe('cancelled');
    }
    expect(JSON.stringify(cancelledProtect)).not.toContain(SYNTHETIC_KEY);
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const revealAbort = new AbortController();
    const revealPending = capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
      ),
      signal: revealAbort.signal,
    });
    revealAbort.abort();
    const cancelledReveal = await revealPending;
    expect(cancelledReveal.ok).toBe(false);
    if (!cancelledReveal.ok) {
      expect(cancelledReveal.code).toBe('cancelled');
    }
    expect(JSON.stringify(cancelledReveal)).not.toContain(SYNTHETIC_KEY);
  });

  it('rejects encryption after a same-invocation current-key retirement race', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const capability = currentCapability({
      nonceProvider: () => {
        mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification(capability, 'retired');
        return Uint8Array.from(randomBytes(12));
      },
    });
    const result = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['key_retired', 'key_state_prohibited']).toContain(result.code);
    }
    expect(JSON.stringify(result)).not.toContain(SYNTHETIC_KEY);
  });

  it('rejects unknown, URL-shaped, and substituted key references without plaintext', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const current = Uint8Array.from(randomBytes(32));
    const other = Uint8Array.from(randomBytes(32));
    const capability = currentCapability({ keyMaterial: current });
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const restricted = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(protectedValue.envelope),
    );
    const unknownReference = expectOk(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
        cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
        algorithmId: protectedValue.envelope.algorithmId,
        associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
        plaintextLength: protectedValue.envelope.plaintextLength,
        ciphertext: restricted.ciphertext,
        nonce: restricted.nonce,
        authenticationTag: restricted.authenticationTag,
        keyReference: 'osv.listing.evidence.kmissing',
        rotationState: 'current',
        erasureState: 'not_erased',
      }),
    );
    const unknown = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: unknownReference,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
      ),
    });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) {
      expect(unknown.code).toBe('unknown_key_reference');
    }
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
        cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
        algorithmId: protectedValue.envelope.algorithmId,
        associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
        plaintextLength: protectedValue.envelope.plaintextLength,
        ciphertext: restricted.ciphertext,
        nonce: restricted.nonce,
        authenticationTag: restricted.authenticationTag,
        keyReference: 'https://kms.example/keys/1',
        rotationState: 'current',
        erasureState: 'not_erased',
      }).ok,
    ).toBe(false);
    const otherCapability = currentCapability({
      alias: 'osv.listing.evidence.k2',
      keyMaterial: other,
    });
    const substituted = expectOk(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
        cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
        algorithmId: protectedValue.envelope.algorithmId,
        associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
        plaintextLength: protectedValue.envelope.plaintextLength,
        ciphertext: restricted.ciphertext,
        nonce: restricted.nonce,
        authenticationTag: restricted.authenticationTag,
        keyReference: 'osv.listing.evidence.k2',
        rotationState: 'current',
        erasureState: 'not_erased',
      }),
    );
    const swapped = await otherCapability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: substituted,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
      ),
    });
    expect(swapped.ok).toBe(false);
    if (!swapped.ok) {
      expect(swapped.code).toBe('authentication_failed');
    }
    current.fill(0);
    other.fill(0);
  });

  it('rejects structurally invalid envelopes before decryption', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
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
    const base = {
      envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
      cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
      algorithmId: protectedValue.envelope.algorithmId,
      associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
      plaintextLength: protectedValue.envelope.plaintextLength,
      ciphertext: restricted.ciphertext,
      nonce: restricted.nonce,
      authenticationTag: restricted.authenticationTag,
      keyReference: restricted.keyReference,
      rotationState: 'current',
      erasureState: 'not_erased',
    };
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v0',
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        algorithmId: 'aes-128-gcm',
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        cryptographicPolicyId: 'osv_protected_listing_evidence_encryption_policy_v0',
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        nonce: Uint8Array.from(randomBytes(11)),
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        authenticationTag: Uint8Array.from(randomBytes(15)),
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        organizationId: '11111111-1111-4111-8111-111111111111',
      }).ok,
    ).toBe(false);
    expect(
      admitOsvProtectedListingEvidenceCiphertextEnvelope({
        ...base,
        findingId: '11111111-1111-4111-8111-111111111111',
      }).ok,
    ).toBe(false);
    const forged = {
      envelopeSchemaVersion: protectedValue.envelope.envelopeSchemaVersion,
      cryptographicPolicyId: protectedValue.envelope.cryptographicPolicyId,
      algorithmId: 'aes-256-gcm',
      associatedDataPolicyId: protectedValue.envelope.associatedDataPolicyId,
      plaintextLength: protectedValue.envelope.plaintextLength,
    };
    const forgedReveal = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: forged,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
      ),
    });
    expect(forgedReveal.ok).toBe(false);
    if (!forgedReveal.ok) {
      expect(forgedReveal.code).toBe('ciphertext_malformed');
    }
  });

  it('rejects classification-status transplantation and wrong-set reveal authorization', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const capability = currentCapability();
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const admitted = expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context));
    const classificationSwap = associatedDataInput({
      classificationStatus: 'ineligible',
    });
    const transplanted = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: classificationSwap,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(classificationSwap)),
      ),
    });
    expect(transplanted.ok).toBe(false);
    if (!transplanted.ok) {
      expect(['authentication_failed', 'associated_data_mismatch']).toContain(transplanted.code);
    }
    const wrongSet = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(
        admitted,
        'deterministic_candidate_selection_raw_identity_required',
      ),
    });
    expect(wrongSet.ok).toBe(true);
    const mismatchedAuthorization =
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: {
          purpose: 'deterministic_candidate_selection_raw_identity_required',
          evidenceSetId: '11111111-1111-4111-8111-111111111111',
          observationId: admitted.observationId,
          synchronizationRequestId: admitted.synchronizationRequestId,
          synchronizationRunId: admitted.synchronizationRunId,
        },
      });
    expect(mismatchedAuthorization.ok).toBe(false);
    if (!mismatchedAuthorization.ok) {
      expect(mismatchedAuthorization.code).toBe('binding_mismatch');
    }
  });

  it('rejects prohibited reveal purposes and does not infer provider authority', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const capability = currentCapability();
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const admitted = expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context));
    for (const purpose of PROHIBITED_PURPOSES) {
      const revealed = await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(admitted, purpose),
      });
      expect(revealed.ok, purpose).toBe(false);
      if (!revealed.ok) {
        expect(revealed.code).toBe('reveal_purpose_unauthorized');
      }
    }
    const incident = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(admitted, 'protected_evidence_incident_review'),
      }),
    );
    expect(incident.providerContactAuthorized).toBe(false);
    expect(incident.bodyRetrievalAuthorized).toBe(false);
    expect(incident.findingWritesAuthorized).toBe(false);
  });

  it('rejects rotation-required, unavailable, malformed, and inconsistent encryption', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    for (const state of [
      'rotation_required',
      'unavailable',
      'malformed',
      'inconsistent',
    ] as const) {
      const capability = currentCapability({ state });
      const result = await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      });
      expect(result.ok, state).toBe(false);
    }
  });

  it('keeps associated-data encoding stable across input key order and rejects output mutation', async () => {
    const observation = admitObservation();
    const first = associatedDataInput();
    const second = {
      classificationStatus: first.classificationStatus,
      sourceFamilyClassification: first.sourceFamilyClassification,
      declaredSizeBytes: first.declaredSizeBytes,
      runtimeVersionSetFingerprint: first.runtimeVersionSetFingerprint,
      providerGeneration: first.providerGeneration,
      synchronizationRunId: first.synchronizationRunId,
      synchronizationRequestId: first.synchronizationRequestId,
      providerContactAuthorizationId: first.providerContactAuthorizationId,
      listingExecutionId: first.listingExecutionId,
      observationId: first.observationId,
      evidenceSetId: first.evidenceSetId,
    };
    const capability = currentCapability();
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: first,
      }),
    );
    const revealed = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: second,
        authorization: authorization(
          expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(second)),
        ),
      }),
    );
    expect(
      expectOk(readOsvProtectedListingObjectIdentitySecrets(revealed.identity)).providerObjectKey,
    ).toBe(SYNTHETIC_KEY);
    const restricted = expectOk(
      readOsvProtectedListingEvidenceCiphertextEnvelopeRestricted(protectedValue.envelope),
    );
    restricted.ciphertext[0] = (restricted.ciphertext[0] ?? 0) ^ 1;
    const still = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: first,
        authorization: authorization(
          expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(first)),
        ),
      }),
    );
    expect(
      expectOk(readOsvProtectedListingObjectIdentitySecrets(still.identity)).providerObjectKey,
    ).toBe(SYNTHETIC_KEY);
  });

  it('does not accept a forged protected identity or leak plaintext through inspect', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const capability = currentCapability();
    const forged = {
      kind: 'osv_protected_listing_object_identity_v1',
      providerObjectKey: SYNTHETIC_KEY,
    };
    const result = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: forged,
      associatedDataContext: context,
    });
    expect(result.ok).toBe(false);
    const protectedValue = expectOk(
      await capability.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const revealed = expectOk(
      await capability.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(
          expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
        ),
      }),
    );
    expect(inspect(revealed.identity)).not.toContain(SYNTHETIC_KEY);
    expect(JSON.stringify(revealed.identity)).not.toContain(SYNTHETIC_KEY);
    expect({ ...revealed.identity }).not.toHaveProperty('providerObjectKey');
  });

  it('copies caller key material and hostile nonce buffers before cryptographic use', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const keyMaterial = Uint8Array.from(randomBytes(32));
    const reused = Uint8Array.from(randomBytes(12));
    const capability = currentCapability({
      keyMaterial,
      nonceProvider: () => reused,
    });
    keyMaterial.fill(0);
    const first = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    reused.fill(0);
    expect(first.ok).toBe(true);
    const second = await capability.protectOsvListingObjectIdentity({
      protectedIdentity: observation.protectedObjectIdentity,
      associatedDataContext: context,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(['nonce_reused', 'nonce_generation_unavailable']).toContain(second.code);
    }
  });

  it('isolates two synthetic instances and swallows hostile event sinks', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const leftKey = Uint8Array.from(randomBytes(32));
    const rightKey = Uint8Array.from(randomBytes(32));
    const left = currentCapability({ alias: 'osv.listing.evidence.kleft', keyMaterial: leftKey });
    const right = currentCapability({
      alias: 'osv.listing.evidence.kright',
      keyMaterial: rightKey,
    });
    const leftEnvelope = expectOk(
      await left.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    ).envelope;
    const cross = await right.revealOsvListingObjectIdentityForAuthorizedPurpose({
      envelope: leftEnvelope,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
      ),
    });
    expect(cross.ok).toBe(false);
    let nested = 0;
    const recursive = createOsvProtectedListingEvidenceCryptographicCapabilityForVerification({
      currentKey: {
        alias: 'osv.listing.evidence.k1',
        state: 'current',
        keyMaterial: Uint8Array.from(randomBytes(32)),
      },
      eventSink: {
        emit() {
          nested += 1;
          return Promise.reject(new Error('sink-must-not-become-authority'));
        },
      },
    });
    expectOk(
      await recursive.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    expect(nested).toBe(1);
    leftKey.fill(0);
    rightKey.fill(0);
  });

  it('does not treat ordinary reveal as rotation and keeps the prior envelope on verify failure', async () => {
    const observation = admitObservation();
    const context = associatedDataInput();
    const oldKey = Uint8Array.from(randomBytes(32));
    const newKey = Uint8Array.from(randomBytes(32));
    const original = currentCapability({ alias: 'osv.listing.evidence.kold', keyMaterial: oldKey });
    const protectedValue = expectOk(
      await original.protectOsvListingObjectIdentity({
        protectedIdentity: observation.protectedObjectIdentity,
        associatedDataContext: context,
      }),
    );
    const revealed = expectOk(
      await original.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(
          expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
        ),
      }),
    );
    expect(revealed.decryptionExecuted).toBe(true);
    const rotating = currentCapability({
      alias: 'osv.listing.evidence.knew',
      keyMaterial: newKey,
      historicalKeys: [
        { alias: 'osv.listing.evidence.kold', state: 'decrypt_only', keyMaterial: oldKey },
      ],
    });
    mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification(rotating, 'retired');
    const failed = await rotating.reprotectOsvListingObjectIdentityForAuthorizedRotation({
      envelope: protectedValue.envelope,
      associatedDataContext: context,
      authorization: authorization(
        expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
        'approved_rotation_or_reencryption',
      ),
    });
    expect(failed.ok).toBe(false);
    const stillReadable = expectOk(
      await original.revealOsvListingObjectIdentityForAuthorizedPurpose({
        envelope: protectedValue.envelope,
        associatedDataContext: context,
        authorization: authorization(
          expectOk(admitOsvProtectedListingEvidenceAssociatedDataContext(context)),
          'approved_rotation_or_reencryption',
        ),
      }),
    );
    expect(stillReadable.decryptionExecuted).toBe(true);
    oldKey.fill(0);
    newKey.fill(0);
  });

  it('keeps verification seams off the public package index', () => {
    expect('mutateOsvProtectedListingEvidenceCurrentKeyStateForVerification' in integrations).toBe(
      false,
    );
    const source = readFileSync(join(here, 'osv-protected-listing-evidence-crypto.ts'), 'utf8');
    expect(source).toContain(
      'createCipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LENGTH })',
    );
    expect(source).toContain('authTagLength');
    expect(source).not.toContain('aes-128-gcm');
    expect(source).not.toContain('createCipheriv(request.algorithm');
  });
});
