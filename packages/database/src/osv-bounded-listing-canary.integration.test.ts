/**
 * Session 13 Batch 3C synthetic listing-canary cross-layer rehearsal.
 * Real persistence, halt, lease, heartbeat, and deadline adapters.
 * Scripted listing port only. No real provider contact.
 */

import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import {
  createOsvBoundedListingCanaryService,
  createOsvListedObjectObservation,
  createOsvListingCanaryRestoreableHaltState,
  createOsvListingContinuationToken,
  createOsvListingPage,
  createOsvListingPageTransportSuccess,
  createOsvRuntimeTrustedHaltSnapshot,
  createOsvTransportFailure,
  OSV_BOUNDED_LISTING_CANARY_DRY_RUN_OUTCOME,
  OSV_BOUNDED_LISTING_CANARY_SUCCESS_OUTCOME,
  osvBoundedListingCanaryCallBudgetWithinLimits,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
  type OsvListingRequest,
  type OsvTransportPort,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvCanaryPreflightReadiness } from './osv-canary-preflight-readiness.js';
import { createOsvListingProviderContactAuthorizationPersistence } from './osv-listing-provider-contact-authorization-persistence.js';
import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createBoundedListingCanaryExecutionInput,
  createListingCanaryRehearsalEgressPort,
  seedOsvBoundedListingCanaryAuthority,
  type OsvBoundedListingCanaryAuthoritySeed,
} from './osv-bounded-listing-canary-authority-seed.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const TOKEN = 'opaque-next-page-token-value';
const MARKERS = [TOKEN, 'holder-token-proof', 'organizationId', 'findingId'];

function expectOk<T>(result: { ok: true; value: T } | { ok: false; code: string }): T {
  if (!result.ok) {
    throw new Error(result.code);
  }
  return result.value;
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
  'session 13 Batch 3C bounded listing-canary synthetic rehearsal',
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
      seed: OsvBoundedListingCanaryAuthoritySeed,
      haltControl: 'halted' | 'permitted_by_halt_control' = 'permitted_by_halt_control',
    ) {
      const haltRestoration = createOsvListingCanaryRestoreableHaltState(
        createOsvRuntimeTrustedHaltSnapshot({
          control: haltControl,
          source: 'explicit',
        }),
      );
      const clock = createFakeClock();
      const service = createOsvBoundedListingCanaryService({
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
        clock,
        scheduler: createFakeScheduler(clock),
        listingPage: listing,
        haltRestoration,
        leaseInspection: createOsvCanaryPreflightReadiness(prisma).leaseInspection,
      });
      return { service, haltRestoration };
    }

    it('invokes the scripted listing port once, restores halt, and releases the lease', async () => {
      const seed = await seedOsvBoundedListingCanaryAuthority(prisma);
      const listing = createScriptedListing();
      const { service, haltRestoration } = await compose(listing, seed);
      const input = createBoundedListingCanaryExecutionInput(seed);
      const dry = await service.dryRun(input);
      expect(dry.ok).toBe(true);
      if (!dry.ok || dry.outcome !== OSV_BOUNDED_LISTING_CANARY_DRY_RUN_OUTCOME) {
        throw new Error('expected dry-run');
      }
      expect(dry.executionAuthorityFromDryRun).toBe(false);
      expect(listing.calls).toHaveLength(0);
      const result = await service.execute(createBoundedListingCanaryExecutionInput(seed));
      expect(result.ok).toBe(true);
      if (!result.ok || result.outcome !== OSV_BOUNDED_LISTING_CANARY_SUCCESS_OUTCOME) {
        throw new Error(inspect(result));
      }
      expect(listing.calls).toHaveLength(1);
      expect(listing.calls[0]?.continuationToken).toBeUndefined();
      expect(result.providerRequestsAttempted).toBe(1);
      expect(result.retriesPerformed).toBe(0);
      expect(result.paginationRequests).toBe(0);
      expect(result.bodyRequests).toBe(0);
      expect(result.storageWrites).toBe(0);
      expect(result.parserExecutions).toBe(0);
      expect(result.activationCalls).toBe(0);
      expect(result.matchingCalls).toBe(0);
      expect(result.findingWrites).toBe(0);
      expect(result.tenantOperations).toBe(0);
      expect(haltRestoration.port.current().control).toBe('halted');
      expect(result.evidence.haltRestoration).toBe('restored');
      expect(result.evidence.leaseRelease).toBe('released');
      expect(osvBoundedListingCanaryCallBudgetWithinLimits(service.lastCallBudget())).toBe(true);
      const replay = await service.execute(createBoundedListingCanaryExecutionInput(seed));
      expect(replay.ok).toBe(false);
      expect(listing.calls).toHaveLength(1);
      const pointer = await prisma.osvActiveCatalogPointer.findMany();
      expect(pointer).toHaveLength(0);
      const findings = await prisma.finding.findMany();
      expect(findings).toHaveLength(0);
    });

    it('records continuation-token presence without a second request or token leak', async () => {
      const seed = await seedOsvBoundedListingCanaryAuthority(prisma);
      const listing = createScriptedListing({ withToken: true });
      const { service } = await compose(listing, seed);
      const result = await service.execute(createBoundedListingCanaryExecutionInput(seed));
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
      const seed = await seedOsvBoundedListingCanaryAuthority(prisma);
      const listing = createScriptedListing({ failureKind: 'timeout' });
      const { service, haltRestoration } = await compose(listing, seed);
      const result = await service.execute(createBoundedListingCanaryExecutionInput(seed));
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected failure');
      }
      expect(result.code).toBe('total_deadline_exceeded');
      expect(listing.calls).toHaveLength(1);
      expect(result.retriesPerformed).toBe(0);
      expect(haltRestoration.port.current().control).toBe('halted');
    });

    it('blocks execute while halt is engaged', async () => {
      const seed = await seedOsvBoundedListingCanaryAuthority(prisma);
      const listing = createScriptedListing();
      const { service } = await compose(listing, seed, 'halted');
      const result = await service.execute(createBoundedListingCanaryExecutionInput(seed));
      expect(result.ok).toBe(false);
      if (result.ok) {
        return;
      }
      expect(result.code).toBe('halt_engaged');
      expect(listing.calls).toHaveLength(0);
      expect(result.providerRequestsAttempted).toBe(0);
    });

    it('leaves the active catalog pointer and Finding tables unchanged', async () => {
      expect(randomUUID().length).toBeGreaterThan(0);
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
      expect(await prisma.finding.count()).toBe(0);
      expect(await prisma.findingObservation.count()).toBe(0);
    });
  },
);
