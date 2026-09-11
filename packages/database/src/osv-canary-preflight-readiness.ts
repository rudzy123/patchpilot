/**
 * Session 13 Batch 2F read-only OSV canary preflight readiness adapters.
 * Inspects request/run identity, lease scope, database health, active-pointer
 * baseline, zero-Finding baseline, and acquisition-table reachability.
 * Does not acquire, heartbeat, release, or take over a lease. Does not
 * modify the active catalog pointer, activation history, or Findings.
 * Production composition does not construct this factory.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  fingerprintOsvCatalogScope,
  OSV_CANARY_PREFLIGHT_ACTIVE_POINTER_BASELINE_POLICY,
  OSV_CANARY_PREFLIGHT_ZERO_FINDING_BASELINE_POLICY,
  OSV_CATALOG_VERSION_SET_V1,
  OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
  type OsvCanaryPreflightAcquisitionPersistenceReadinessPort,
  type OsvCanaryPreflightActivePointerBaselinePort,
  type OsvCanaryPreflightDatabaseReadinessPort,
  type OsvCanaryPreflightLeaseInspectionPort,
  type OsvCanaryPreflightSynchronizationPort,
  type OsvCanaryPreflightZeroFindingBaselinePort,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';
import { isDatabaseUnavailable } from './osv-runtime-coordination-errors.js';
import {
  mapRequest,
  mapRun,
  OsvRuntimeCoordinationMappingError,
} from './osv-runtime-coordination-mappers.js';

const ROOT_CLIENT_REQUIRED = 'OSV canary preflight readiness requires the root Prisma client.';
const READINESS_TIMEOUT_MS = 2_000;

export type OsvCanaryPreflightReadinessAdapters = {
  readonly synchronization: OsvCanaryPreflightSynchronizationPort;
  readonly leaseInspection: OsvCanaryPreflightLeaseInspectionPort;
  readonly databaseReadiness: OsvCanaryPreflightDatabaseReadinessPort;
  readonly acquisitionPersistenceReadiness: OsvCanaryPreflightAcquisitionPersistenceReadinessPort;
  readonly activePointerBaseline: OsvCanaryPreflightActivePointerBaselinePort;
  readonly zeroFindingBaseline: OsvCanaryPreflightZeroFindingBaselinePort;
};

export function createOsvCanaryPreflightReadiness(
  client: PrismaClient,
): OsvCanaryPreflightReadinessAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new Error(ROOT_CLIENT_REQUIRED);
  }
  return {
    synchronization: {
      inspectByIdentities: (input) => inspectRequestAndRun(client, input),
    },
    leaseInspection: {
      inspectScope: (input) => inspectLeaseScope(client, input.expectedRunId),
    },
    databaseReadiness: {
      inspect: () => inspectSelectOne(client),
    },
    acquisitionPersistenceReadiness: {
      inspect: () => inspectAcquisitionTables(client),
    },
    activePointerBaseline: {
      capture: () => captureActivePointerBaseline(client),
    },
    zeroFindingBaseline: {
      capture: () => captureZeroFindingBaseline(client),
    },
  };
}

function asSqlBoolean(value: unknown): boolean {
  return value === true || value === 't' || value === 'true';
}

async function withTimeout<T>(operation: Promise<T>, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(message));
        }, READINESS_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

async function inspectRequestAndRun(
  client: PrismaClient,
  input: { readonly requestId: string; readonly runId: string },
): Promise<Awaited<ReturnType<OsvCanaryPreflightSynchronizationPort['inspectByIdentities']>>> {
  try {
    const [request, run] = await withTimeout(
      Promise.all([
        client.osvRuntimeSynchronizationRequest.findUnique({
          where: { id: input.requestId },
        }),
        client.osvRuntimeSynchronizationRun.findUnique({
          where: { id: input.runId },
        }),
      ]),
      'canary preflight request/run inspection timed out',
    );
    if (request === null || run === null) {
      return { status: 'absent' };
    }
    return {
      status: 'found',
      request: mapRequest(request),
      run: mapRun(run),
    };
  } catch (error) {
    if (error instanceof OsvRuntimeCoordinationMappingError) {
      return { status: 'malformed' };
    }
    if (isDatabaseUnavailable(error)) {
      return { status: 'database_unavailable' };
    }
    return { status: 'database_unavailable' };
  }
}

async function inspectLeaseScope(
  client: PrismaClient,
  expectedRunId: string,
): Promise<Record<string, unknown>> {
  try {
    const rows = await withTimeout(
      client.$queryRaw<Array<Record<string, unknown>>>`
        SELECT
          "state",
          "run_id",
          (CURRENT_TIMESTAMP < "expires_at") AS "ownership_current",
          (CURRENT_TIMESTAMP >= "expires_at") AS "expired"
        FROM "osv_runtime_lease_projection"
        WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
      `,
      'canary preflight lease inspection timed out',
    );
    if (rows.length > 1) {
      return leaseObservation('ownership_ambiguous', 'none');
    }
    const raw = rows[0];
    if (raw === undefined) {
      return leaseObservation('available', 'exact_acquire');
    }
    const state = raw['state'];
    const runId = raw['run_id'] ?? raw['runId'];
    const unexpired = asSqlBoolean(raw['ownership_current'] ?? raw['ownershipCurrent']);
    const expired = asSqlBoolean(raw['expired']);
    if (typeof state !== 'string' || typeof runId !== 'string') {
      return leaseObservation('ownership_ambiguous', 'none');
    }
    if (Object.hasOwn(raw, 'holder_token_digest') || Object.hasOwn(raw, 'holderTokenDigest')) {
      return leaseObservation('ownership_ambiguous', 'none');
    }
    if (state === 'released') {
      return leaseObservation('released_and_available', 'exact_acquire');
    }
    if (state !== 'held') {
      return leaseObservation('ownership_ambiguous', 'none');
    }
    if (expired || !unexpired) {
      return leaseObservation(
        'expired_projection_takeover_required_later',
        'guarded_stale_takeover',
      );
    }
    if (runId === expectedRunId) {
      return leaseObservation('held_by_same_prepared_run', 'none');
    }
    return leaseObservation('held_by_another', 'none');
  } catch {
    return leaseObservation('database_unavailable', 'none');
  }
}

function leaseObservation(
  status:
    | 'available'
    | 'released_and_available'
    | 'held_by_same_prepared_run'
    | 'held_by_another'
    | 'expired_projection_takeover_required_later'
    | 'ownership_ambiguous'
    | 'database_unavailable',
  laterAcquisitionAction: 'exact_acquire' | 'guarded_stale_takeover' | 'none',
): Record<string, unknown> {
  return {
    status,
    laterAcquisitionAction,
    acquired: false,
    mutated: false,
  };
}

async function inspectSelectOne(client: PrismaClient): Promise<Record<string, unknown>> {
  try {
    await withTimeout(client.$queryRaw`SELECT 1`, 'canary preflight database readiness timed out');
    return { ready: true, mutated: false };
  } catch {
    return { ready: false, mutated: false };
  }
}

async function inspectAcquisitionTables(client: PrismaClient): Promise<Record<string, unknown>> {
  try {
    await withTimeout(
      client.$queryRaw`SELECT 1 FROM "osv_active_catalog_pointer" WHERE FALSE`,
      'canary preflight acquisition persistence readiness timed out',
    );
    return { ready: true, mutated: false };
  } catch {
    return { ready: false, mutated: false };
  }
}

async function captureActivePointerBaseline(
  client: PrismaClient,
): Promise<Record<string, unknown>> {
  try {
    const scopeFingerprint = fingerprintOsvCatalogScope(OSV_CATALOG_VERSION_SET_V1);
    const captured = await withTimeout(
      client.$transaction(
        async (tx) => {
          const [pointer, historyCount, clock] = await Promise.all([
            tx.osvActiveCatalogPointer.findUnique({
              where: { scopeFingerprint },
              select: { generationId: true },
            }),
            tx.osvActivationRecord.count({ where: { scopeFingerprint } }),
            tx.$queryRaw<Array<{ now: Date }>>`SELECT CURRENT_TIMESTAMP AS now`,
          ]);
          return { pointer, historyCount, clock };
        },
        { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
      ),
      'canary preflight active-pointer baseline timed out',
    );
    const now = captured.clock[0]?.now;
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
      return failedPointerBaseline();
    }
    const present = captured.pointer !== null && captured.pointer.generationId !== null;
    if (present && captured.historyCount === 0) {
      return failedPointerBaseline();
    }
    return {
      captured: true,
      currentActiveCatalog: present ? 'present' : 'absent',
      activationHistoryCount: captured.historyCount,
      capturedAt: now.toISOString(),
      policyIdentifier: OSV_CANARY_PREFLIGHT_ACTIVE_POINTER_BASELINE_POLICY,
      activePointerModified: false,
      activationCallCount: 0,
      activationProhibited: true,
    };
  } catch {
    return failedPointerBaseline();
  }
}

function failedPointerBaseline(): Record<string, unknown> {
  return {
    captured: false,
    currentActiveCatalog: 'absent',
    activationHistoryCount: 0,
    capturedAt: '1970-01-01T00:00:00.000Z',
    policyIdentifier: OSV_CANARY_PREFLIGHT_ACTIVE_POINTER_BASELINE_POLICY,
    activePointerModified: false,
    activationCallCount: 0,
    activationProhibited: true,
  };
}

async function captureZeroFindingBaseline(client: PrismaClient): Promise<Record<string, unknown>> {
  try {
    const [findingCount, findingObservationCount] = await withTimeout(
      Promise.all([client.finding.count(), client.findingObservation.count()]),
      'canary preflight zero-Finding baseline timed out',
    );
    void OSV_CANARY_PREFLIGHT_ZERO_FINDING_BASELINE_POLICY;
    return {
      captured: true,
      tenantContextPresent: false,
      tenantScopedOperationPlanned: false,
      findingWritePlanned: false,
      findingRecalculatePlanned: false,
      canaryAttributedFindingWriteCount: 0,
      canaryAttributedFindingRecalculateCount: 0,
      globalFindingAbsenceNotRequired: true,
      findingCount,
      findingObservationCount,
      countsUnchangedByPreflight: true,
    };
  } catch {
    return {
      captured: false,
      tenantContextPresent: false,
      tenantScopedOperationPlanned: false,
      findingWritePlanned: false,
      findingRecalculatePlanned: false,
      canaryAttributedFindingWriteCount: 0,
      canaryAttributedFindingRecalculateCount: 0,
      globalFindingAbsenceNotRequired: true,
      findingCount: 0,
      findingObservationCount: 0,
      countsUnchangedByPreflight: true,
    };
  }
}
