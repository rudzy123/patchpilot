/**
 * Session 13 Batch 3D nonpublic operator composition root.
 * Explicit invocation only. Not registered in worker, API, or application
 * startup. Dry-run contacts no provider and writes no evidence. Execute sends
 * exactly one real GCS listing HTTPS request and persists one protected
 * evidence set on the development database.
 *
 * Excluded from the database production build.
 */

import { randomBytes } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME,
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME,
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME,
  loadOsvProtectedListingEvidenceKeyProvisioningFrom,
} from '@patchpilot/config/osv-listing-evidence-key';
import {
  createOsvListingCanaryRestoreableHaltState,
  createOsvListingObservationEvidenceInspectForRunQuery,
  createOsvProtectedEvidenceListingCanaryConfirmationSummary,
  createOsvProtectedEvidenceListingCanaryPlan,
  createOsvProtectedEvidenceListingCanaryService,
  createOsvRuntimeTrustedHaltSnapshot,
  parseOsvProtectedEvidenceListingCanaryArgv,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
  type OsvListingObservationEvidencePersistencePort,
  type OsvProtectedEvidenceListingCanaryResult,
  type OsvProtectedListingEvidenceCryptographicCapabilityPort,
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
  createProtectedEvidenceListingCryptographicReadinessPort,
  createProtectedEvidenceListingPersistenceReadinessPort,
  seedOsvProtectedEvidenceListingCanaryAuthority,
} from './osv-protected-evidence-listing-canary-authority-seed.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const PROHIBITED_PRINT_MARKERS = [
  '"holderToken"',
  '"holderDigest"',
  '"fencingToken"',
  '"rowRevision"',
  '"pageToken"',
  '"nextPageToken"',
  '"continuationToken":',
  'Authorization',
  'cookie',
  '"Location"',
  '"organizationId"',
  '"tenantId"',
  '"findingId"',
  'protected-evidence-listing-one-shot-confirmation-proof',
  '"providerObjectKey"',
  '"ciphertext"',
  '"authenticationTag"',
  '"opaqueKeyAlias"',
  'INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL',
];

const PROCESS_LOCAL_KEY_ALIAS = 'osv.listing.evidence.kcanary3d';

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

function forbiddenPersistence(): OsvListingObservationEvidencePersistencePort {
  return {
    ensure() {
      return Promise.reject(new Error('dry_run_must_not_persist_protected_evidence'));
    },
    inspect() {
      return Promise.reject(new Error('dry_run_must_not_inspect_protected_evidence'));
    },
    inspectForRun() {
      return Promise.reject(new Error('dry_run_must_not_inspect_protected_evidence'));
    },
    readProtected() {
      return Promise.reject(new Error('dry_run_must_not_reveal_protected_evidence'));
    },
    recordReview() {
      return Promise.reject(new Error('dry_run_must_not_record_review'));
    },
    setLegalHold() {
      return Promise.reject(new Error('dry_run_must_not_set_legal_hold'));
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

async function loadRealCryptographicCapability(): Promise<OsvProtectedListingEvidenceCryptographicCapabilityPort> {
  const material = randomBytes(32).toString('hex');
  const loaded = loadOsvProtectedListingEvidenceKeyProvisioningFrom({
    [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: material,
    [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: PROCESS_LOCAL_KEY_ALIAS,
    [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
  });
  if (!loaded.ok) {
    throw new Error('process_local_listing_evidence_key_unavailable');
  }
  const cryptoUrl = new URL(
    '../../integrations/src/osv-protected-listing-evidence-crypto.ts',
    import.meta.url,
  );
  const module = (await import(cryptoUrl.href)) as {
    createOsvProtectedListingEvidenceCryptographicCapability?: (input: {
      readonly currentKey: typeof loaded.value;
    }) => OsvProtectedListingEvidenceCryptographicCapabilityPort;
  };
  if (typeof module.createOsvProtectedListingEvidenceCryptographicCapability !== 'function') {
    throw new Error('cryptographic_capability_unavailable');
  }
  return module.createOsvProtectedListingEvidenceCryptographicCapability({
    currentKey: loaded.value,
  });
}

function printBounded(label: string, value: unknown, stream: NodeJS.WriteStream): void {
  const blob = JSON.stringify(value);
  for (const marker of PROHIBITED_PRINT_MARKERS) {
    if (blob.includes(marker)) {
      stream.write(`${label}: redacted_bounded_output\n`);
      return;
    }
  }
  stream.write(`${label}:\n${JSON.stringify(value, null, 2)}\n`);
}

function exitForResult(result: OsvProtectedEvidenceListingCanaryResult): number {
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

async function dryRun(): Promise<OsvProtectedEvidenceListingCanaryResult> {
  return withEphemeralPrisma(async (prisma) => {
    const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
    const haltRestoration = createOsvListingCanaryRestoreableHaltState(
      createOsvRuntimeTrustedHaltSnapshot({
        control: 'halted',
        source: 'explicit',
      }),
    );
    const readiness = createOsvCanaryPreflightReadiness(prisma);
    const service = createOsvProtectedEvidenceListingCanaryService({
      authentication: {
        authenticate() {
          return { outcome: 'authenticated', operator: seed.identity };
        },
      },
      authorization: createOsvCanaryAuthorizationPersistence(prisma),
      providerContact: createOsvListingProviderContactAuthorizationPersistence(prisma),
      synchronization: readiness.synchronization,
      coordination: createOsvRuntimeCoordinationPersistence(prisma),
      haltState: haltRestoration.port,
      egressReadiness: createListingCanaryRehearsalEgressPort(),
      cryptographicReadiness: createProtectedEvidenceListingCryptographicReadinessPort(),
      persistenceReadiness: createProtectedEvidenceListingPersistenceReadinessPort(),
      clock: createProcessClock(),
      scheduler: createProcessScheduler(),
      listingPage: forbiddenListingPort(),
      haltRestoration,
      leaseInspection: readiness.leaseInspection,
      persistence: forbiddenPersistence(),
    });
    return service.dryRun(createProtectedEvidenceListingCanaryExecutionInput(seed));
  });
}

async function executeOneListingRequest(): Promise<OsvProtectedEvidenceListingCanaryResult> {
  const prisma = new PrismaClient();
  try {
    const existing = await prisma.osvListingObservationEvidenceSet.count();
    if (existing !== 0) {
      throw new Error('protected_evidence_set_already_present');
    }
    const seed = await seedOsvProtectedEvidenceListingCanaryAuthority(prisma);
    const capability = await loadRealCryptographicCapability();
    const persistence = createOsvListingObservationEvidencePersistence(prisma, {
      cryptographicCapability: capability,
    });
    const haltRestoration = createOsvListingCanaryRestoreableHaltState(
      createOsvRuntimeTrustedHaltSnapshot({
        control: 'permitted_by_halt_control',
        source: 'explicit',
      }),
    );
    const readiness = createOsvCanaryPreflightReadiness(prisma);
    const listingPage = await loadRealListingAdapter();
    const service = createOsvProtectedEvidenceListingCanaryService({
      authentication: {
        authenticate() {
          return { outcome: 'authenticated', operator: seed.identity };
        },
      },
      authorization: createOsvCanaryAuthorizationPersistence(prisma),
      providerContact: createOsvListingProviderContactAuthorizationPersistence(prisma),
      synchronization: readiness.synchronization,
      coordination: createOsvRuntimeCoordinationPersistence(prisma),
      haltState: haltRestoration.port,
      egressReadiness: createListingCanaryRehearsalEgressPort(),
      cryptographicReadiness: {
        inspect: () => capability.inspectProtectedEvidenceCryptographicReadiness(),
      },
      persistenceReadiness: createProtectedEvidenceListingPersistenceReadinessPort(),
      clock: createProcessClock(),
      scheduler: createProcessScheduler(),
      listingPage,
      haltRestoration,
      leaseInspection: readiness.leaseInspection,
      persistence,
    });
    printBounded(
      'confirmation_summary',
      createOsvProtectedEvidenceListingCanaryConfirmationSummary({
        requestId: seed.requestId,
        runId: seed.runId,
      }),
      process.stderr,
    );
    const result = await service.execute(createProtectedEvidenceListingCanaryExecutionInput(seed));
    const inspectQuery = createOsvListingObservationEvidenceInspectForRunQuery({
      synchronizationRequestId: seed.requestId,
      synchronizationRunId: seed.runId,
    });
    if (inspectQuery.ok) {
      const inspected = await persistence.inspectForRun(inspectQuery.value);
      if (inspected.ok) {
        const record = inspected.value;
        printBounded(
          'public_evidence_inspection',
          {
            evidenceSetId: record.evidenceSetId,
            evidenceState: record.evidenceState,
            pageOrdinal: record.pageOrdinal,
            protectedObservationCount: record.protectedObservationCount,
            acceptedObservationCount: record.acceptedObservationCount,
            exactDuplicateCount: record.exactDuplicateCount,
            immutableConflictCount: record.immutableConflictCount,
            candidateSelectionAuthorized: record.candidateSelectionAuthorized,
            bodyRetrievalAuthorized: record.bodyRetrievalAuthorized,
            batch4pPermitted: record.batch4pPermitted,
            envelopeFieldsPresent: false,
            opaqueKeyAliasPresent: false,
          },
          process.stdout,
        );
      }
    }
    printBounded(
      'downstream_counts',
      {
        evidenceSetCount: await prisma.osvListingObservationEvidenceSet.count(),
        observationCount: await prisma.osvListingObservationEvidence.count(),
        envelopeCount: await prisma.osvListingObservationEvidenceEnvelope.count(),
        activePointerCount: await prisma.osvActiveCatalogPointer.count(),
        findingCount: await prisma.finding.count(),
        findingObservationCount: await prisma.findingObservation.count(),
      },
      process.stdout,
    );
    return result;
  } finally {
    await prisma.$disconnect();
  }
}

async function main(): Promise<void> {
  const parsed = parseOsvProtectedEvidenceListingCanaryArgv(process.argv.slice(2));
  if (!parsed.ok) {
    process.stderr.write('unknown_or_rejected_argument\n');
    process.exitCode = 1;
    return;
  }
  printBounded('plan', createOsvProtectedEvidenceListingCanaryPlan(), process.stdout);
  if (parsed.value.action === 'dry-run') {
    const result = await dryRun();
    printBounded('dry_run_result', result, process.stdout);
    process.exitCode = exitForResult(result);
    return;
  }
  process.stderr.write(
    'WARNING: executing exactly one real HTTPS listing request to storage.googleapis.com. No retry. No pagination. No body retrieval. Protected observation identities will be encrypted and persisted.\n',
  );
  const result = await executeOneListingRequest();
  printBounded('canary_result', result, process.stdout);
  process.exitCode = exitForResult(result);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'operator_failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
