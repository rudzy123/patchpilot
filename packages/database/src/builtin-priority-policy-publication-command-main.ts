/**
 * Deployment-local built-in priority policy publication command.
 * Explicit invocation only. API, web, worker, seed, and migration startup
 * do not import this module. The production allowlist is checked before the
 * database is opened.
 */

import { createHash } from 'node:crypto';

import { inspectDatabaseUrl, loadServerConfig } from '@patchpilot/config';
import { ADMITTED_PRIORITY_POLICY_PAIRS, isAdmittedPriorityPolicyPair } from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
} from '@patchpilot/policy-engine';

import {
  publishBuiltinPriorityPolicy,
  type BuiltinPriorityPolicyPublicationRequest,
  type BuiltinPriorityPolicyPublicationResult,
  type CanonicalJsonResult,
} from './builtin-priority-policy-publication.js';
import { disconnectPrisma, getPrismaClient } from './client.js';

const USAGE = `Usage:
  pnpm publish-builtin-priority-policy -- --correlation-id <correlation-id>
  pnpm publish-builtin-priority-policy -- help`;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT = Object.freeze({
  success: 0,
  invalidCommand: 1,
  unvalidated: 2,
  immutableConflict: 3,
  persistenceFailure: 4,
});

export type BuiltinPriorityPolicyPublicationLoad = {
  readonly definition: unknown;
  readonly engineVersion: string;
  readonly canonicalJson: (value: unknown) => CanonicalJsonResult;
  readonly admittedPairs: BuiltinPriorityPolicyPublicationRequest['admittedPairs'];
};

type CommandTextStream = {
  write(chunk: string): void;
};

export type BuiltinPriorityPolicyPublicationSession = {
  readonly publish: (
    request: BuiltinPriorityPolicyPublicationRequest,
  ) => Promise<BuiltinPriorityPolicyPublicationResult>;
  readonly close: () => Promise<void>;
};

export type BuiltinPriorityPolicyPublicationCommandIO = {
  readonly argv: readonly unknown[];
  readonly stdout: CommandTextStream;
  readonly stderr: CommandTextStream;
  readonly loadDatabaseUrl: () => string;
  readonly openBoundary: (databaseUrl: string) => Promise<BuiltinPriorityPolicyPublicationSession>;
  readonly loadPublication?: () => BuiltinPriorityPolicyPublicationLoad;
};

export function loadBuiltinPriorityPolicyPublication(): BuiltinPriorityPolicyPublicationLoad {
  return {
    definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    engineVersion: POLICY_ENGINE_VERSION,
    canonicalJson,
    admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
  };
}

export function loadBuiltinPriorityPolicyPublicationDatabaseUrl(): string {
  const databaseUrl = loadServerConfig().databaseUrl;
  inspectDatabaseUrl(databaseUrl);
  return databaseUrl;
}

export async function openBuiltinPriorityPolicyPublicationBoundary(
  databaseUrl: string,
): Promise<BuiltinPriorityPolicyPublicationSession> {
  const client = getPrismaClient({ databaseUrl });
  return {
    publish(request) {
      return publishBuiltinPriorityPolicy(client, request);
    },
    close() {
      return disconnectPrisma();
    },
  };
}

export async function runBuiltinPriorityPolicyPublicationCommand(
  io: BuiltinPriorityPolicyPublicationCommandIO,
): Promise<number> {
  const parsed = parseArgv(io.argv);
  if (parsed.kind === 'help') {
    io.stderr.write(`${USAGE}\n`);
    return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.success;
  }
  if (parsed.kind === 'invalid') {
    writeJson(io.stdout, { outcome: 'invalid_command' }, []);
    io.stderr.write(`${USAGE}\n`);
    return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.invalidCommand;
  }

  const publication = (io.loadPublication ?? loadBuiltinPriorityPolicyPublication)();
  if (!publicationPairAdmitted(publication)) {
    writeJson(io.stdout, { outcome: 'unvalidated', correlationId: parsed.correlationId }, []);
    return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.unvalidated;
  }

  let databaseUrl = '';
  let session: BuiltinPriorityPolicyPublicationSession | undefined;
  try {
    databaseUrl = io.loadDatabaseUrl();
    session = await io.openBoundary(databaseUrl);
    const result = await session.publish({
      correlationId: parsed.correlationId,
      definition: publication.definition,
      canonicalJson: publication.canonicalJson,
      admittedPairs: publication.admittedPairs,
      engineVersion: publication.engineVersion,
    });
    writeJson(
      io.stdout,
      {
        schemaVersion: 'builtin_priority_policy_publication_v1',
        outcome: result.outcome,
        correlationId: parsed.correlationId,
        ...(result.outcome === 'inserted' || result.outcome === 'already_applied'
          ? { riskPolicyId: result.riskPolicyId }
          : {}),
      },
      [databaseUrl],
    );
    return exitCode(result.outcome);
  } catch {
    writeJson(io.stdout, { outcome: 'persistence_failure', correlationId: parsed.correlationId }, [
      databaseUrl,
    ]);
    return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.persistenceFailure;
  } finally {
    if (session !== undefined) {
      await session.close().catch(() => undefined);
    }
  }
}

function publicationPairAdmitted(publication: BuiltinPriorityPolicyPublicationLoad): boolean {
  let encoded: CanonicalJsonResult;
  try {
    encoded = publication.canonicalJson(publication.definition);
  } catch {
    return false;
  }
  if (!encoded.ok) {
    return false;
  }
  const hash = createHash('sha256').update(encoded.value, 'utf8').digest('hex');
  return isAdmittedPriorityPolicyPair(publication.admittedPairs, publication.engineVersion, hash);
}

function parseArgv(
  argv: readonly unknown[],
):
  | { readonly kind: 'help' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'run'; readonly correlationId: string } {
  if (argv.length === 1 && argv[0] === 'help') {
    return { kind: 'help' };
  }
  if (argv.length !== 2 || argv[0] !== '--correlation-id' || typeof argv[1] !== 'string') {
    return { kind: 'invalid' };
  }
  if (!UUID_PATTERN.test(argv[1])) {
    return { kind: 'invalid' };
  }
  return { kind: 'run', correlationId: argv[1] };
}

function exitCode(outcome: BuiltinPriorityPolicyPublicationResult['outcome']): number {
  switch (outcome) {
    case 'inserted':
    case 'already_applied':
      return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.success;
    case 'unvalidated':
      return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.unvalidated;
    case 'immutable_conflict':
      return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.immutableConflict;
    case 'persistence_failure':
      return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.persistenceFailure;
    default:
      return BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.persistenceFailure;
  }
}

function writeJson(
  stdout: CommandTextStream,
  body: Readonly<Record<string, string>>,
  concealed: readonly string[],
): void {
  const line = `${JSON.stringify(body)}\n`;
  if (concealed.some((marker) => marker.length > 0 && line.includes(marker))) {
    stdout.write(`${JSON.stringify({ outcome: 'persistence_failure' })}\n`);
    return;
  }
  stdout.write(line);
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  return (
    entry.endsWith('/builtin-priority-policy-publication-command-main.js') ||
    entry.endsWith('/builtin-priority-policy-publication-command-main.ts')
  );
}

if (isDirectRun()) {
  runBuiltinPriorityPolicyPublicationCommand({
    argv: process.argv.slice(2),
    stdout: process.stdout,
    stderr: process.stderr,
    loadDatabaseUrl: loadBuiltinPriorityPolicyPublicationDatabaseUrl,
    openBoundary: openBuiltinPriorityPolicyPublicationBoundary,
  })
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch(() => {
      process.stderr.write('persistence_failure\n');
      process.exitCode = BUILTIN_PRIORITY_POLICY_PUBLICATION_EXIT.persistenceFailure;
    });
}
