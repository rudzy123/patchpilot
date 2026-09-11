/**
 * Session 13 Batch 3C nonpublic operator composition root.
 * Explicit invocation only. Not registered in worker, API, or application
 * startup. Dry-run contacts no provider. execute-one-listing-request sends
 * exactly one real GCS listing HTTPS request.
 *
 * Excluded from the database production build.
 */

import { inspect } from 'node:util';
import { PrismaClient } from '@prisma/client';
import {
  createOsvBoundedListingCanaryConfirmationSummary,
  createOsvBoundedListingCanaryPlan,
  createOsvBoundedListingCanaryService,
  createOsvListingCanaryRestoreableHaltState,
  createOsvRuntimeTrustedHaltSnapshot,
  parseOsvBoundedListingCanaryArgv,
  type OsvBoundedListingCanaryResult,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
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
} from './osv-bounded-listing-canary-authority-seed.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const PROHIBITED_PRINT_MARKERS = [
  'holderToken',
  'holderDigest',
  'fencingToken',
  'rowRevision',
  'pageToken',
  'nextPageToken',
  'Authorization',
  'cookie',
  'Location',
  'organizationId',
  'tenantId',
  'findingId',
  'listing-canary-one-shot-confirmation-proof',
];

function createProcessClock(): OsvCanaryMonotonicClockPort {
  return {
    now() {
      return Math.trunc(performance.now());
    },
  };
}

function createProcessScheduler(): OsvCanaryOneShotSchedulerPort {
  return {
    schedule(delayMs, callback) {
      const handle = setTimeout(callback, delayMs);
      return {
        cancel() {
          clearTimeout(handle);
        },
      };
    },
  };
}

function forbiddenListingPort(): OsvTransportPort {
  return {
    listPage() {
      return Promise.reject(new Error('dry_run_must_not_contact_provider'));
    },
  };
}

async function loadRealListingAdapter(): Promise<OsvTransportPort> {
  const adapterUrl = new URL(
    '../../integrations/src/osv-gcs-listing-https-adapter.ts',
    import.meta.url,
  );
  const loaded = (await import(adapterUrl.href)) as {
    createOsvGcsListingHttpsAdapter?: () => OsvTransportPort;
  };
  if (typeof loaded.createOsvGcsListingHttpsAdapter !== 'function') {
    throw new Error('listing_adapter_unavailable');
  }
  return loaded.createOsvGcsListingHttpsAdapter();
}

function printBounded(label: string, value: unknown, stream: NodeJS.WriteStream): void {
  const blob = `${JSON.stringify(value)}\n${inspect(value, { depth: 4, compact: true })}`;
  for (const marker of PROHIBITED_PRINT_MARKERS) {
    if (blob.includes(marker)) {
      stream.write(`${label}: redacted_bounded_output\n`);
      return;
    }
  }
  stream.write(`${label}:\n${JSON.stringify(value, null, 2)}\n`);
}

function exitForResult(result: OsvBoundedListingCanaryResult): number {
  if (result.ok) {
    return 0;
  }
  if (result.code === 'halt_restoration_failure' || result.code === 'release_uncertainty') {
    return 2;
  }
  return 1;
}

async function withEphemeralPrisma<T>(work: (prisma: PrismaClient) => Promise<T>): Promise<T> {
  const ephemeral = await createEphemeralDatabase('it');
  let prisma: PrismaClient | undefined;
  try {
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    return await work(prisma);
  } finally {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
  }
}

async function composeAndRun(input: {
  readonly action: 'dry-run' | 'execute-one-listing-request';
  readonly listingPage: OsvTransportPort;
  readonly haltControl: 'halted' | 'permitted_by_halt_control';
}): Promise<OsvBoundedListingCanaryResult> {
  return withEphemeralPrisma(async (prisma) => {
    const seed = await seedOsvBoundedListingCanaryAuthority(prisma);
    const canary = createOsvCanaryAuthorizationPersistence(prisma);
    const coordination = createOsvRuntimeCoordinationPersistence(prisma);
    const providerContact = createOsvListingProviderContactAuthorizationPersistence(prisma);
    const readiness = createOsvCanaryPreflightReadiness(prisma);
    const haltRestoration = createOsvListingCanaryRestoreableHaltState(
      createOsvRuntimeTrustedHaltSnapshot({
        control: input.haltControl,
        source: 'explicit',
      }),
    );
    const service = createOsvBoundedListingCanaryService({
      authentication: {
        authenticate() {
          return { outcome: 'authenticated', operator: seed.identity };
        },
      },
      authorization: canary,
      providerContact,
      synchronization: readiness.synchronization,
      coordination,
      haltState: haltRestoration.port,
      egressReadiness: createListingCanaryRehearsalEgressPort(),
      clock: createProcessClock(),
      scheduler: createProcessScheduler(),
      listingPage: input.listingPage,
      haltRestoration,
      leaseInspection: readiness.leaseInspection,
    });
    const executionInput = createBoundedListingCanaryExecutionInput(seed);
    if (input.action === 'dry-run') {
      return service.dryRun(executionInput);
    }
    printBounded(
      'confirmation_summary',
      createOsvBoundedListingCanaryConfirmationSummary({
        requestId: seed.requestId,
        runId: seed.runId,
      }),
      process.stderr,
    );
    return service.execute(executionInput);
  });
}

async function main(): Promise<void> {
  const parsed = parseOsvBoundedListingCanaryArgv(process.argv.slice(2));
  if (!parsed.ok) {
    process.stderr.write('unknown_or_rejected_argument\n');
    process.exitCode = 1;
    return;
  }
  printBounded('plan', createOsvBoundedListingCanaryPlan(), process.stdout);
  if (parsed.value.action === 'dry-run') {
    const result = await composeAndRun({
      action: 'dry-run',
      listingPage: forbiddenListingPort(),
      haltControl: 'halted',
    });
    printBounded('dry_run_result', result, process.stdout);
    process.exitCode = exitForResult(result);
    return;
  }
  process.stderr.write(
    'WARNING: executing exactly one real HTTPS listing request to storage.googleapis.com. No retry. No pagination. No body retrieval.\n',
  );
  const listingPage = await loadRealListingAdapter();
  const result = await composeAndRun({
    action: 'execute-one-listing-request',
    listingPage,
    haltControl: 'permitted_by_halt_control',
  });
  printBounded('canary_result', result, process.stdout);
  process.exitCode = exitForResult(result);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'operator_failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
