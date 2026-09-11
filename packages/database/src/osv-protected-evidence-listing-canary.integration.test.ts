/**
 * Session 13 Batch 3D synthetic protected-evidence listing-canary rehearsal.
 * Real authorization, persistence, AES-256-GCM, halt, lease, heartbeat, and
 * deadline adapters. Scripted listing port only. No real provider contact.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import {
  createOsvListedObjectObservation,
  createOsvListingCanaryRestoreableHaltState,
  createOsvListingContinuationToken,
  createOsvListingObservationEvidenceInspectForRunQuery,
  createOsvListingPage,
  createOsvListingPageTransportSuccess,
  createOsvProtectedEvidenceListingCanaryService,
  createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform,
  createOsvRuntimeTrustedHaltSnapshot,
  createOsvTransportFailure,
  OSV_PROTECTED_EVIDENCE_LISTING_CANARY_DRY_RUN_OUTCOME,
  OSV_PROTECTED_EVIDENCE_LISTING_CANARY_SUCCESS_OUTCOME,
  osvProtectedEvidenceListingCanaryCallBudgetWithinLimits,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
  type OsvListingRequest,
  type OsvProtectedListingEvidenceCryptographicCapabilityPort,
  type OsvProtectedListingEvidencePlatformAeadPort,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityPort,
  type OsvTransportPort,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvCanaryPreflightReadiness } from './osv-canary-preflight-readiness.js';
import { createOsvListingObservationEvidencePersistence } from './osv-listing-observation-evidence-persistence.js';
import { createOsvListingProviderContactAuthorizationPersistence } from './osv-listing-provider-contact-authorization-persistence.js';
import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createListingCanaryRehearsalEgressPort,
  createProtectedEvidenceListingCanaryExecutionInput,
  createProtectedEvidenceListingPersistenceReadinessPort,
  seedOsvProtectedEvidenceListingCanaryAuthority,
  type OsvProtectedEvidenceListingCanaryAuthoritySeed,
} from './osv-protected-evidence-listing-canary-authority-seed.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const TOKEN = 'opaque-next-page-token-value';
const KEY_ALIAS = 'osv.listing.evidence.krehearse3d';
const MARKERS = [
  TOKEN,
  'holder-token-proof',
  'organizationId',
  'findingId',
  'crates.io/RUSTSEC-0000-0001.json',
  'providerObjectKey',
  'ciphertext',
];

function expectOk<T>(
  result: { ok: true; value: T } | { ok: false; code: string },
  label = 'ok',
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
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

function createRehearsalCapability(): OsvProtectedListingEvidenceCryptographicCapabilityPort {
  const keyMaterial = copyBytes(randomBytes(32));
  const record = {
    alias: KEY_ALIAS,
    state: 'current' as const,
    keyMaterial,
  };
  const handles = new WeakMap<object, typeof record>();
  const handle: OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle = Object.freeze({
    kind: 'osv_protected_listing_evidence_key_capability_handle',
    keyState: 'current',
    encryptionPermitted: true,
    decryptionPermitted: true,
    keyVersionClassification: 'current',
    returnsRawKeyMaterial: false,
  });
  handles.set(handle, record);
  const keyCapability: OsvProtectedListingEvidenceRuntimeKeyCapabilityPort = {
    inspect() {
      return {
        ok: true,
        value: {
          currentKeyState: 'current',
          encryptionPermitted: true,
          decryptionPermitted: true,
          rotationStatus: 'current',
          returnsRawKeyMaterial: false,
          genericDecryptAuthority: false,
        },
      };
    },
    currentEncryptionCapability() {
      return { ok: true, value: handle };
    },
    approvedDecryptionCapability(keyReference) {
      if (keyReference !== KEY_ALIAS) {
        return { ok: false, code: 'unknown_key_reference' };
      }
      return { ok: true, value: handle };
    },
  };
  const aead: OsvProtectedListingEvidencePlatformAeadPort = {
    inspectAvailability() {
      return {
        ok: true,
        value: {
          algorithmId: 'aes-256-gcm',
          nonceBytes: 12,
          tagBytes: 16,
          keyBytes: 32,
          nonceCapabilityAvailable: true,
          callerSelectedNonce: false,
          callerSelectedAlgorithm: false,
        },
      };
    },
    generateNonce() {
      return { ok: true, value: Uint8Array.from(randomBytes(12)) };
    },
    seal(request) {
      const stored = handles.get(request.keyHandle);
      if (stored === undefined) {
        return { ok: false, code: 'key_unavailable' };
      }
      const cipher = createCipheriv('aes-256-gcm', stored.keyMaterial, request.nonce, {
        authTagLength: 16,
      });
      cipher.setAAD(request.associatedData);
      const ciphertext = joinBytes(
        Uint8Array.from(cipher.update(request.plaintext)),
        Uint8Array.from(cipher.final()),
      );
      return {
        ok: true,
        value: {
          ciphertext,
          authenticationTag: Uint8Array.from(cipher.getAuthTag()),
          keyReference: stored.alias,
        },
      };
    },
    open(request) {
      const stored = handles.get(request.keyHandle);
      if (stored === undefined) {
        return { ok: false, code: 'key_unavailable' };
      }
      try {
        const decipher = createDecipheriv('aes-256-gcm', stored.keyMaterial, request.nonce, {
          authTagLength: 16,
        });
        decipher.setAAD(request.associatedData);
        decipher.setAuthTag(request.authenticationTag);
        const plaintext = joinBytes(
          Uint8Array.from(decipher.update(request.ciphertext)),
          Uint8Array.from(decipher.final()),
        );
        return { ok: true, value: plaintext };
      } catch {
        return { ok: false, code: 'authentication_failed' };
      }
    },
  };
  return createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform({
    keyCapability,
    aead,
  });
}

function createFakeClock(start = 0): OsvCanaryMonotonicClockPort {
  const now = start;
  return {
    now: () => now,
  };
}

function createFakeScheduler(clock: { now(): number }): OsvCanaryOneShotSchedulerPort {
  const items: Array<{ fireAt: number; callback: () => void; cancelled: boolean }> = [];
  return {
    schedule(delayMs, callback) {
      const item = { fireAt: clock.now() + delayMs, callback, cancelled: false };
      items.push(item);
      return {
        cancel() {
          item.cancelled = true;
        },
      };
    },
  };
}

function createScriptedListing(options?: {
  readonly withToken?: boolean;
  readonly failureKind?: 'timeout' | 'temporary_dns_failure';
}): OsvTransportPort & { readonly calls: OsvListingRequest[] } {
  const calls: OsvListingRequest[] = [];
  return {
    calls,
    async listPage(request) {
      calls.push(request);
      if (options?.failureKind !== undefined) {
        const failure = createOsvTransportFailure({ kind: options.failureKind });
        if (!failure.ok) {
          throw new Error(failure.code);
        }
        return { ok: false, failure: failure.value };
      }
      const observation = expectOk(
        createOsvListedObjectObservation({
          objectKey: 'crates.io/RUSTSEC-0000-0001.json',
          generation: '1',
          declaredSizeBytes: 12,
          contentType: 'application/json',
        }),
      );
      const token =
        options?.withToken === true ? expectOk(createOsvListingContinuationToken(TOKEN)) : null;
      const page = expectOk(
        createOsvListingPage({
          providerPrefix: 'crates.io/',
          items: [observation],
          itemCount: 1,
          complete: token === null,
          ...(token === null ? {} : { continuationToken: token }),
        }),
      );
      return expectOk(
        createOsvListingPageTransportSuccess({
          page,
          responseByteCount: 48,
        }),
      );
    },
  };
}

describe(
  'session 13 Batch 3D protected-evidence listing-canary synthetic rehearsal',
  { timeout: 180_000 },
  () => {
    let databaseName: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
    });

    afterAll(async () => {
      if (prisma !== undefined) {
        await prisma.$disconnect();
      }
      if (admin !== undefined && databaseName !== undefined) {
        await dropEphemeralDatabase(admin, databaseName);
      }
    });

    async function compose(
      listing: ReturnType<typeof createScriptedListing>,
      seed: OsvProtectedEvidenceListingCanaryAuthoritySeed,
      haltControl: 'halted' | 'permitted_by_halt_control' = 'permitted_by_halt_control',
    ) {
      const haltRestoration = createOsvListingCanaryRestoreableHaltState(
        createOsvRuntimeTrustedHaltSnapshot({
          control: haltControl,
          source: 'explicit',
        }),
      );
      const clock = createFakeClock();
      const capability = createRehearsalCapability();
      const persistence = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      const service = createOsvProtectedEvidenceListingCanaryService({
        authentication: {
          authenticate() {
            return { outcome: 'authenticated', operator: seed.identity };
          },
        },
        authorization: createOsvCanaryAuthorizationPersistence(prisma),
        providerContact: createOsvListingProviderContactAuthorizationPersistence(prisma),
        synchronization: createOsvCanaryPreflightReadiness(prisma).synchronization,
        coordination: createOsvRuntimeCoordinationPersistence(prisma),
        haltState: haltRestoration.port,
        egressReadiness: createListingCanaryRehearsalEgressPort(),
        cryptographicReadiness: {
          inspect: () => capability.inspectProtectedEvidenceCryptographicReadiness(),
        },
        persistenceReadiness: createProtectedEvidenceListingPersistenceReadinessPort(),
        clock,
        scheduler: createFakeScheduler(clock),
        listingPage: listing,
        haltRestoration,
        leaseInspection: createOsvCanaryPreflightReadiness(prisma).leaseInspection,
        persistence,
      });
      return { service, haltRestoration, persistence };
    }

    it('invokes the scripted listing port once, encrypts before Prisma, restores halt, and releases the lease', async () => {
      const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
      const listing = createScriptedListing();
      const { service, haltRestoration, persistence } = await compose(listing, seed);
      const dry = await service.dryRun(createProtectedEvidenceListingCanaryExecutionInput(seed));
      expect(dry.ok).toBe(true);
      if (!dry.ok || dry.outcome !== OSV_PROTECTED_EVIDENCE_LISTING_CANARY_DRY_RUN_OUTCOME) {
        throw new Error('expected dry-run');
      }
      expect(dry.executionAuthorityFromDryRun).toBe(false);
      expect(listing.calls).toHaveLength(0);
      expect(await prisma.osvListingObservationEvidenceSet.count()).toBe(0);
      const result = await service.execute(
        createProtectedEvidenceListingCanaryExecutionInput(seed),
      );
      expect(result.ok).toBe(true);
      if (!result.ok || result.outcome !== OSV_PROTECTED_EVIDENCE_LISTING_CANARY_SUCCESS_OUTCOME) {
        throw new Error(inspect(result));
      }
      expect(listing.calls).toHaveLength(1);
      expect(listing.calls[0]?.continuationToken).toBeUndefined();
      expect(result.providerRequestsAttempted).toBe(1);
      expect(result.retriesPerformed).toBe(0);
      expect(result.paginationRequests).toBe(0);
      expect(result.bodyRequests).toBe(0);
      expect(result.candidateSelections).toBe(0);
      expect(result.parserWorkerExecutions).toBe(0);
      expect(result.activationCalls).toBe(0);
      expect(result.matchingCalls).toBe(0);
      expect(result.findingWrites).toBe(0);
      expect(result.tenantOperations).toBe(0);
      expect(result.evidence.protectedObservationCount).toBe(1);
      expect(result.evidence.encryptionClassification).toBe('encrypted_before_prisma');
      expect(result.evidence.persistenceClassification).toBe('persisted');
      expect(haltRestoration.port.current().control).toBe('halted');
      expect(result.evidence.haltRestoration).toBe('restored');
      expect(result.evidence.leaseRelease).toBe('released');
      expect(
        osvProtectedEvidenceListingCanaryCallBudgetWithinLimits(service.lastCallBudget()),
      ).toBe(true);
      expect(
        await prisma.osvListingObservationEvidenceSet.count({
          where: {
            synchronizationRequestId: seed.requestId,
            synchronizationRunId: seed.runId,
          },
        }),
      ).toBe(1);
      expect(
        await prisma.osvListingObservationEvidence.count({
          where: {
            evidenceSet: {
              synchronizationRequestId: seed.requestId,
              synchronizationRunId: seed.runId,
            },
          },
        }),
      ).toBe(1);
      expect(
        await prisma.osvListingObservationEvidenceEnvelope.count({
          where: {
            observation: {
              evidenceSet: {
                synchronizationRequestId: seed.requestId,
                synchronizationRunId: seed.runId,
              },
            },
          },
        }),
      ).toBe(1);
      const inspected = expectOk(
        await persistence.inspectForRun(
          expectOk(
            createOsvListingObservationEvidenceInspectForRunQuery({
              synchronizationRequestId: seed.requestId,
              synchronizationRunId: seed.runId,
            }),
          ),
        ),
      );
      expect(inspected.protectedObservationCount).toBe(1);
      expect(JSON.stringify(inspected)).not.toContain('ciphertext');
      expect(JSON.stringify(inspected)).not.toContain('opaqueKeyAlias');
      expect(JSON.stringify(inspected)).not.toContain('crates.io/RUSTSEC-0000-0001.json');
      const replay = await service.execute(
        createProtectedEvidenceListingCanaryExecutionInput(seed),
      );
      expect(replay.ok).toBe(false);
      expect(listing.calls).toHaveLength(1);
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
      expect(await prisma.finding.count()).toBe(0);
    });

    it('records continuation-token presence without a second request or token leak', async () => {
      const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
      const listing = createScriptedListing({ withToken: true });
      const { service } = await compose(listing, seed);
      const result = await service.execute(
        createProtectedEvidenceListingCanaryExecutionInput(seed),
      );
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error(inspect(result));
      }
      expect(listing.calls).toHaveLength(1);
      expect(result.evidence.continuationTokenPresent).toBe(true);
      expect(result.evidence.terminalPage).toBe(false);
      const blob = `${JSON.stringify(result)}\n${inspect(result)}`;
      for (const marker of MARKERS) {
        expect(blob).not.toContain(marker);
      }
    });

    it('does not retry a transport failure and still restores halt', async () => {
      const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
      const listing = createScriptedListing({ failureKind: 'timeout' });
      const { service, haltRestoration } = await compose(listing, seed);
      const result = await service.execute(
        createProtectedEvidenceListingCanaryExecutionInput(seed),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected failure');
      }
      expect(result.code).toBe('total_deadline_exceeded');
      expect(listing.calls).toHaveLength(1);
      expect(result.retriesPerformed).toBe(0);
      expect(haltRestoration.port.current().control).toBe('halted');
      expect(
        await prisma.osvListingObservationEvidenceSet.count({
          where: {
            synchronizationRequestId: seed.requestId,
            synchronizationRunId: seed.runId,
          },
        }),
      ).toBe(0);
    });

    it('blocks execute while halt is engaged', async () => {
      const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
      const listing = createScriptedListing();
      const { service } = await compose(listing, seed, 'halted');
      const result = await service.execute(
        createProtectedEvidenceListingCanaryExecutionInput(seed),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        return;
      }
      expect(result.code).toBe('halt_engaged');
      expect(listing.calls).toHaveLength(0);
      expect(result.providerRequestsAttempted).toBe(0);
    });

    it('leaves the active catalog pointer and Finding tables unchanged', async () => {
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
      expect(await prisma.finding.count()).toBe(0);
      expect(await prisma.findingObservation.count()).toBe(0);
    });
  },
);
