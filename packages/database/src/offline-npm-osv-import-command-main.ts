/**
 * Deployment-local offline npm GHSA OSV import.
 * Explicit invocation only. API, web, worker, seed, and migration startup
 * do not import this module. One process imports one directory.
 */

import { createHash } from 'node:crypto';

import { inspectDatabaseUrl, loadServerConfig } from '@patchpilot/config';
import {
  OFFLINE_NPM_ADVISORY_FILE_PERSISTENCE_COMMAND_SCHEMA_VERSION,
  OFFLINE_NPM_OSV_IMPORT_EXIT,
  OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES,
  OFFLINE_NPM_OSV_IMPORT_MAX_FILES,
  OFFLINE_NPM_OSV_IMPORT_STDERR,
  OFFLINE_NPM_OSV_IMPORT_USAGE,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  buildOfflineNpmImportSummary,
  normalizeOfflineNpmGhsaBytes,
  offlineNpmImportAdvisoryIdCandidate,
  offlineNpmImportEntryNameRejection,
  offlineNpmImportManifestSha256,
  orderOfflineNpmImportFiles,
  parseOfflineNpmOsvImportArgv,
  type OfflineNpmImportFileOutcome,
  type OfflineNpmImportSummary,
  type OfflineNpmImportSummaryOutcome,
  type PersistOfflineNpmAdvisoryFileResult,
} from '@patchpilot/vulnerability-intelligence';

import { createAdvisoryRevisionPersistence } from './advisory-revision-persistence.js';
import { disconnectPrisma, getPrismaClient } from './client.js';
import {
  readOfflineNpmImportDirectory,
  type OfflineNpmImportAdmittedFile,
  type OfflineNpmImportDirectoryRead,
} from './offline-npm-osv-import-directory.js';
import {
  createOfflineNpmOsvImportPersistence,
  type OfflineNpmImportBatchBegin,
  type OfflineNpmImportBatchBeginInput,
  type OfflineNpmImportBatchComplete,
  type OfflineNpmImportBatchCompleteInput,
  type OfflineNpmSupersessionInput,
  type OfflineNpmSupersessionResolution,
} from './offline-npm-osv-import-persistence.js';

export class OfflineNpmOsvImportCommandConfigurationError extends Error {
  public constructor() {
    super('database_configuration_invalid');
    this.name = 'OfflineNpmOsvImportCommandConfigurationError';
  }
}

export type OfflineNpmOsvImportCommandPort = {
  beginBatch(input: OfflineNpmImportBatchBeginInput): Promise<OfflineNpmImportBatchBegin>;
  resolveSupersession(
    input: OfflineNpmSupersessionInput,
  ): Promise<OfflineNpmSupersessionResolution>;
  persistFile(command: unknown): Promise<PersistOfflineNpmAdvisoryFileResult>;
  completeBatch(input: OfflineNpmImportBatchCompleteInput): Promise<OfflineNpmImportBatchComplete>;
};

export type OfflineNpmOsvImportCommandSession = {
  readonly port: OfflineNpmOsvImportCommandPort;
  readonly close: () => Promise<void>;
};

type CommandTextStream = {
  write(chunk: string): void;
};

export type OfflineNpmOsvImportCommandIO = {
  readonly argv: readonly unknown[];
  readonly stdout: CommandTextStream;
  readonly stderr: CommandTextStream;
  readonly loadDatabaseUrl: () => string;
  readonly openBoundary: (databaseUrl: string) => Promise<OfflineNpmOsvImportCommandSession>;
  readonly readDirectory: (directory: string) => Promise<OfflineNpmImportDirectoryRead>;
};

type DescribedFile = {
  readonly name: string;
  readonly bytes: Uint8Array;
  readonly byteLength: number;
  readonly sha256: string;
};

type PreparedDirectory = {
  readonly files: readonly DescribedFile[];
  readonly manifestSha256: string;
  readonly byteLength: number;
};

export function requireOfflineNpmOsvImportCommandDatabaseUrl(databaseUrl: string): string {
  try {
    inspectDatabaseUrl(databaseUrl);
    return databaseUrl;
  } catch {
    throw new OfflineNpmOsvImportCommandConfigurationError();
  }
}

export function loadOfflineNpmOsvImportCommandDatabaseUrl(): string {
  try {
    return requireOfflineNpmOsvImportCommandDatabaseUrl(loadServerConfig().databaseUrl);
  } catch (error) {
    if (error instanceof OfflineNpmOsvImportCommandConfigurationError) {
      throw error;
    }
    throw new OfflineNpmOsvImportCommandConfigurationError();
  }
}

export async function openOfflineNpmOsvImportCommandBoundary(
  databaseUrl: string,
): Promise<OfflineNpmOsvImportCommandSession> {
  const client = getPrismaClient({ databaseUrl });
  const revisions = createAdvisoryRevisionPersistence(client);
  const batches = createOfflineNpmOsvImportPersistence(client);
  return {
    port: {
      beginBatch(input) {
        return batches.beginBatch(input);
      },
      resolveSupersession(input) {
        return batches.resolveSupersession(input);
      },
      persistFile(command) {
        return revisions.persistOfflineNpmAdvisoryFile(command);
      },
      completeBatch(input) {
        return batches.completeBatch(input);
      },
    },
    close() {
      return disconnectPrisma();
    },
  };
}

export async function runOfflineNpmOsvImportCommand(
  io: OfflineNpmOsvImportCommandIO,
): Promise<number> {
  const parsed = parseOfflineNpmOsvImportArgv(io.argv);
  if (!parsed.ok && parsed.outcome === 'help') {
    io.stderr.write(`${OFFLINE_NPM_OSV_IMPORT_USAGE}\n`);
    return OFFLINE_NPM_OSV_IMPORT_EXIT.completed;
  }
  if (!parsed.ok) {
    return finish(
      io,
      earlySummary('invalid_command', 'rejected', 'invalid_command'),
      3,
      'directoryRejected',
      [],
    );
  }

  let directory: OfflineNpmImportDirectoryRead;
  try {
    directory = await io.readDirectory(parsed.directory);
  } catch {
    directory = { ok: false, reason: 'directory_rejected' };
  }
  if (!directory.ok) {
    const reason =
      directory.reason === 'unreadable_file' ? 'unreadable_file' : 'directory_rejected';
    return finish(
      io,
      earlySummary('directory_rejected', 'rejected', reason, parsed.correlationId),
      OFFLINE_NPM_OSV_IMPORT_EXIT.rejected,
      'directoryRejected',
      concealmentMarkers(null, parsed.directory),
    );
  }

  const prepared = prepareDirectory(directory.files);
  if (prepared === null) {
    return finish(
      io,
      earlySummary('directory_rejected', 'rejected', 'directory_rejected', parsed.correlationId),
      OFFLINE_NPM_OSV_IMPORT_EXIT.rejected,
      'directoryRejected',
      concealmentMarkers(null, parsed.directory),
    );
  }

  let databaseUrl: string;
  try {
    databaseUrl = io.loadDatabaseUrl();
  } catch {
    return finish(
      io,
      earlySummary(
        'database_unavailable',
        'failed',
        'database_unavailable',
        parsed.correlationId,
        prepared.manifestSha256,
      ),
      OFFLINE_NPM_OSV_IMPORT_EXIT.databaseUnavailable,
      'databaseUnavailable',
      concealmentMarkers(null, parsed.directory),
    );
  }

  const concealed = concealmentMarkers(databaseUrl, parsed.directory);
  let session: OfflineNpmOsvImportCommandSession | undefined;
  try {
    session = await io.openBoundary(databaseUrl);
  } catch {
    return finish(
      io,
      earlySummary(
        'database_unavailable',
        'failed',
        'database_unavailable',
        parsed.correlationId,
        prepared.manifestSha256,
      ),
      OFFLINE_NPM_OSV_IMPORT_EXIT.databaseUnavailable,
      'databaseUnavailable',
      concealed,
    );
  }

  try {
    return await importPreparedDirectory(
      io,
      session.port,
      parsed.correlationId,
      prepared,
      concealed,
    );
  } catch {
    return finish(
      io,
      earlySummary(
        'failed',
        'failed',
        'internal_failure',
        parsed.correlationId,
        prepared.manifestSha256,
      ),
      OFFLINE_NPM_OSV_IMPORT_EXIT.failed,
      'failed',
      concealed,
    );
  } finally {
    await session.close().catch(() => undefined);
  }
}

async function importPreparedDirectory(
  io: OfflineNpmOsvImportCommandIO,
  port: OfflineNpmOsvImportCommandPort,
  correlationId: string,
  prepared: PreparedDirectory,
  concealed: readonly string[],
): Promise<number> {
  const begun = await port.beginBatch({
    correlationId,
    manifestSha256: prepared.manifestSha256,
    byteLength: prepared.byteLength,
  });
  if (begun.kind === 'immutable_conflict') {
    return finish(
      io,
      earlySummary(
        'directory_rejected',
        'rejected',
        'immutable_conflict',
        correlationId,
        prepared.manifestSha256,
      ),
      OFFLINE_NPM_OSV_IMPORT_EXIT.rejected,
      'directoryRejected',
      concealed,
    );
  }
  if (begun.kind === 'database_unavailable') {
    return finish(
      io,
      earlySummary(
        'database_unavailable',
        'failed',
        'database_unavailable',
        correlationId,
        prepared.manifestSha256,
      ),
      OFFLINE_NPM_OSV_IMPORT_EXIT.databaseUnavailable,
      'databaseUnavailable',
      concealed,
    );
  }
  if (begun.kind !== 'started' && begun.kind !== 'already_applied') {
    const reason =
      begun.kind === 'transaction_aborted' ? 'transaction_aborted' : 'internal_failure';
    return finish(
      io,
      earlySummary('failed', 'failed', reason, correlationId, prepared.manifestSha256),
      OFFLINE_NPM_OSV_IMPORT_EXIT.failed,
      'failed',
      concealed,
    );
  }

  const reports: OfflineNpmImportFileOutcome[] = [];
  let failed = false;
  for (const file of prepared.files) {
    let report: OfflineNpmImportFileOutcome;
    try {
      report = await importOneFile(port, file, begun.batchId, correlationId);
    } catch {
      report = { advisoryId: null, group: 'failed', reasonCode: 'internal_failure' };
    }
    reports.push(report);
    if (report.group === 'failed') {
      failed = true;
      break;
    }
  }

  let outcome: OfflineNpmImportSummaryOutcome = failed ? 'failed' : 'completed';
  let commandReason: { readonly group: 'failed'; readonly reasonCode: string } | null = null;
  if (!failed) {
    let completed: OfflineNpmImportBatchComplete;
    try {
      completed = await port.completeBatch({
        batchId: begun.batchId,
        correlationId,
        manifestSha256: prepared.manifestSha256,
        byteLength: prepared.byteLength,
        summary: buildOfflineNpmImportSummary({
          correlationId,
          batchId: begun.batchId,
          manifestSha256: prepared.manifestSha256,
          registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
          retrievedAt: begun.retrievedAt,
          outcome: 'completed',
          files: reports,
          commandReason: null,
        }),
      });
    } catch {
      completed = { kind: 'internal_failure' };
    }
    if (completed.kind !== 'recorded' && completed.kind !== 'already_applied') {
      outcome = 'failed';
      commandReason = {
        group: 'failed',
        reasonCode:
          completed.kind === 'transaction_aborted' ? 'transaction_aborted' : 'internal_failure',
      };
    }
  }

  const summary = buildOfflineNpmImportSummary({
    correlationId,
    batchId: begun.batchId,
    manifestSha256: prepared.manifestSha256,
    registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
    retrievedAt: begun.retrievedAt,
    outcome,
    files: reports,
    commandReason,
  });
  if (outcome === 'failed') {
    return finish(io, summary, OFFLINE_NPM_OSV_IMPORT_EXIT.failed, 'failed', concealed);
  }
  return finish(io, summary, OFFLINE_NPM_OSV_IMPORT_EXIT.completed, null, concealed);
}

async function importOneFile(
  port: OfflineNpmOsvImportCommandPort,
  file: DescribedFile,
  batchId: string,
  correlationId: string,
): Promise<OfflineNpmImportFileOutcome> {
  if (file.byteLength < 1) {
    return {
      advisoryId: offlineNpmImportAdvisoryIdCandidate(file.bytes),
      group: 'rejected',
      reasonCode: 'malformed_json',
    };
  }
  const normalized = normalizeOfflineNpmGhsaBytes(file.bytes);
  if (!normalized.accepted) {
    return {
      advisoryId: offlineNpmImportAdvisoryIdCandidate(file.bytes),
      group: normalized.reason === 'internal_failure' ? 'failed' : 'rejected',
      reasonCode: normalized.reason,
    };
  }
  const revisions: { readonly command: unknown; readonly purl: string | null }[] = [];
  for (const revision of normalized.revisions) {
    const resolved = await port.resolveSupersession({
      source: normalized.source,
      advisoryId: normalized.advisoryId,
      packageIdentityKey: revision.packageIdentityKey,
      rawContentSha256: normalized.rawContentSha256,
    });
    if (resolved.kind !== 'ready') {
      return resolutionOutcome(resolved.kind, normalized.advisoryId);
    }
    revisions.push({
      command: {
        ...revision.persistenceCommand,
        supersedesRevisionDigest: resolved.supersedesRevisionDigest,
      },
      purl: revision.purl,
    });
  }
  if (revisions.length === 0) {
    return {
      advisoryId: normalized.advisoryId,
      group: 'rejected',
      reasonCode: 'empty_affectedness',
    };
  }
  const persisted = await port.persistFile({
    commandSchemaVersion: OFFLINE_NPM_ADVISORY_FILE_PERSISTENCE_COMMAND_SCHEMA_VERSION,
    batchId,
    correlationId,
    byteLength: file.byteLength,
    revisions,
  });
  return persistedOutcome(persisted, normalized.advisoryId);
}

function resolutionOutcome(
  kind: Exclude<OfflineNpmSupersessionResolution['kind'], 'ready'>,
  advisoryId: string,
): OfflineNpmImportFileOutcome {
  if (kind === 'malformed_persisted_state') {
    return { advisoryId, group: 'rejected', reasonCode: 'malformed_persisted_state' };
  }
  if (kind === 'transaction_aborted') {
    return { advisoryId, group: 'failed', reasonCode: 'transaction_aborted' };
  }
  return { advisoryId, group: 'failed', reasonCode: 'internal_failure' };
}

function persistedOutcome(
  result: PersistOfflineNpmAdvisoryFileResult,
  advisoryId: string,
): OfflineNpmImportFileOutcome {
  if (result.kind === 'recorded') {
    return { advisoryId, group: 'accepted', reasonCode: null };
  }
  if (result.kind === 'already_applied') {
    return { advisoryId, group: 'skipped', reasonCode: 'already_applied' };
  }
  if (result.kind === 'immutable_conflict') {
    return { advisoryId, group: 'rejected', reasonCode: 'immutable_conflict' };
  }
  if (result.code === 'malformed_persisted_state') {
    return { advisoryId, group: 'rejected', reasonCode: 'malformed_persisted_state' };
  }
  if (result.code === 'supersession_rejected') {
    return { advisoryId, group: 'rejected', reasonCode: 'immutable_conflict' };
  }
  if (result.code === 'transaction_aborted' || result.code === 'timeout') {
    return { advisoryId, group: 'failed', reasonCode: 'transaction_aborted' };
  }
  return { advisoryId, group: 'failed', reasonCode: 'internal_failure' };
}

function prepareDirectory(
  files: readonly OfflineNpmImportAdmittedFile[],
): PreparedDirectory | null {
  if (files.length > OFFLINE_NPM_OSV_IMPORT_MAX_FILES) {
    return null;
  }
  const described: DescribedFile[] = [];
  for (const file of files) {
    if (
      offlineNpmImportEntryNameRejection(file.name) !== null ||
      !(file.bytes instanceof Uint8Array)
    ) {
      return null;
    }
    if (file.bytes.byteLength > OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES) {
      return null;
    }
    const bytes = new Uint8Array(file.bytes.byteLength);
    bytes.set(file.bytes);
    described.push({
      name: file.name,
      bytes,
      byteLength: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  }
  const ordered = orderOfflineNpmImportFiles(described);
  let byteLength = 0;
  for (const file of ordered) {
    byteLength += file.byteLength;
  }
  const manifestSha256 = offlineNpmImportManifestSha256(ordered);
  if (manifestSha256 === null || !Number.isSafeInteger(byteLength)) {
    return null;
  }
  return { files: ordered, manifestSha256, byteLength };
}

function earlySummary(
  outcome: OfflineNpmImportSummaryOutcome,
  group: 'rejected' | 'failed',
  reasonCode: string,
  correlationId: string | null = null,
  manifestSha256: string | null = null,
): OfflineNpmImportSummary {
  return buildOfflineNpmImportSummary({
    correlationId,
    batchId: null,
    manifestSha256,
    registryId: null,
    retrievedAt: null,
    outcome,
    files: [],
    commandReason: { group, reasonCode },
  });
}

function finish(
  io: OfflineNpmOsvImportCommandIO,
  summary: OfflineNpmImportSummary,
  exitCode: number,
  stderr: 'directoryRejected' | 'failed' | 'databaseUnavailable' | null,
  concealed: readonly string[],
): number {
  const line = `${JSON.stringify(summary)}\n`;
  if (concealed.some((marker) => marker.length > 0 && line.includes(marker))) {
    io.stdout.write(`${JSON.stringify(earlySummary('failed', 'failed', 'internal_failure'))}\n`);
    io.stderr.write(`${OFFLINE_NPM_OSV_IMPORT_STDERR.failed}\n`);
    return OFFLINE_NPM_OSV_IMPORT_EXIT.failed;
  }
  io.stdout.write(line);
  if (stderr !== null) {
    io.stderr.write(`${OFFLINE_NPM_OSV_IMPORT_STDERR[stderr]}\n`);
  }
  return exitCode;
}

function concealmentMarkers(databaseUrl: string | null, directory: string | null): string[] {
  const markers: string[] = [];
  if (databaseUrl !== null && databaseUrl.length > 0) {
    markers.push(databaseUrl);
  }
  if (directory !== null && directory.length >= 12) {
    markers.push(directory);
  }
  return markers;
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  return (
    entry.endsWith('/offline-npm-osv-import-command-main.js') ||
    entry.endsWith('/offline-npm-osv-import-command-main.ts')
  );
}

if (isDirectRun()) {
  runOfflineNpmOsvImportCommand({
    argv: process.argv.slice(2),
    stdout: process.stdout,
    stderr: process.stderr,
    loadDatabaseUrl: loadOfflineNpmOsvImportCommandDatabaseUrl,
    openBoundary: openOfflineNpmOsvImportCommandBoundary,
    readDirectory: readOfflineNpmImportDirectory,
  })
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch(() => {
      process.stderr.write(`${OFFLINE_NPM_OSV_IMPORT_STDERR.failed}\n`);
      process.exitCode = OFFLINE_NPM_OSV_IMPORT_EXIT.failed;
    });
}
