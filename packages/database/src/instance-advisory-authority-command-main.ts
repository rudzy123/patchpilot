/**
 * Deployment-local instance advisory authority command.
 * Explicit invocation only. API, web, worker, seed, and migration startup
 * do not import this module. One process performs one parsed command.
 */

import { inspectDatabaseUrl, loadServerConfig } from '@patchpilot/config';
import {
  executeInstanceAdvisoryAuthorityDeploymentCommand,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE,
  instanceAdvisoryAuthorityCommandExitCode,
  parseInstanceAdvisoryAuthorityArgv,
  presentInstanceAdvisoryAuthorityCommandResult,
  type InstanceAdvisoryAuthorityCommandPort,
  type InstanceAdvisoryAuthorityCommandPresentation,
  type InstanceAdvisoryAuthorityCommandResult,
} from '@patchpilot/domain/instance-advisory-authority';

import { disconnectPrisma, getPrismaClient } from './client.js';
import { createInstanceAdvisoryAuthorityPersistence } from './instance-advisory-authority-persistence.js';

export class InstanceAdvisoryAuthorityCommandConfigurationError extends Error {
  public constructor() {
    super('database_configuration_invalid');
    this.name = 'InstanceAdvisoryAuthorityCommandConfigurationError';
  }
}

export type InstanceAdvisoryAuthorityCommandSession = {
  readonly port: InstanceAdvisoryAuthorityCommandPort;
  readonly close: () => Promise<void>;
};

type CommandTextStream = {
  write(chunk: string): void;
};

export type InstanceAdvisoryAuthorityCommandIO = {
  readonly argv: readonly unknown[];
  readonly stdout: CommandTextStream;
  readonly stderr: CommandTextStream;
  readonly loadDatabaseUrl: () => string;
  readonly openBoundary: (databaseUrl: string) => Promise<InstanceAdvisoryAuthorityCommandSession>;
};

export function requireInstanceAdvisoryAuthorityCommandDatabaseUrl(databaseUrl: string): string {
  try {
    inspectDatabaseUrl(databaseUrl);
    return databaseUrl;
  } catch {
    throw new InstanceAdvisoryAuthorityCommandConfigurationError();
  }
}

export function loadInstanceAdvisoryAuthorityCommandDatabaseUrl(): string {
  try {
    return requireInstanceAdvisoryAuthorityCommandDatabaseUrl(loadServerConfig().databaseUrl);
  } catch (error) {
    if (error instanceof InstanceAdvisoryAuthorityCommandConfigurationError) {
      throw error;
    }
    throw new InstanceAdvisoryAuthorityCommandConfigurationError();
  }
}

export async function openInstanceAdvisoryAuthorityCommandBoundary(
  databaseUrl: string,
): Promise<InstanceAdvisoryAuthorityCommandSession> {
  const client = getPrismaClient({ databaseUrl });
  const persistence = createInstanceAdvisoryAuthorityPersistence(client);
  return {
    port: {
      execute(command) {
        return persistence.execute(command);
      },
    },
    close() {
      return disconnectPrisma();
    },
  };
}

export async function runInstanceAdvisoryAuthorityCommand(
  io: InstanceAdvisoryAuthorityCommandIO,
): Promise<number> {
  const parsed = parseInstanceAdvisoryAuthorityArgv(io.argv);
  if (!parsed.ok && parsed.outcome === 'help') {
    io.stderr.write(`${INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE}\n`);
    return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.help;
  }
  if (!parsed.ok) {
    writePresentation(io.stdout, presentInstanceAdvisoryAuthorityCommandResult(null, invalid()));
    io.stderr.write(`${INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE}\n`);
    return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.invalidCommand;
  }

  let databaseUrl: string;
  try {
    databaseUrl = io.loadDatabaseUrl();
  } catch {
    writePresentation(
      io.stdout,
      presentInstanceAdvisoryAuthorityCommandResult(parsed.command, {
        outcome: 'database_unavailable',
      }),
    );
    return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.databaseUnavailable;
  }

  let session: InstanceAdvisoryAuthorityCommandSession | undefined;
  try {
    session = await io.openBoundary(databaseUrl);
    const result = await executeInstanceAdvisoryAuthorityDeploymentCommand(
      session.port,
      parsed.command,
    );
    const exitCode = instanceAdvisoryAuthorityCommandExitCode(result.outcome);
    const wrote = writePresentation(
      io.stdout,
      presentInstanceAdvisoryAuthorityCommandResult(parsed.command, result),
      [databaseUrl],
    );
    return wrote ? exitCode : INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.internalFailure;
  } catch {
    writePresentation(
      io.stdout,
      presentInstanceAdvisoryAuthorityCommandResult(parsed.command, {
        outcome: 'internal_failure',
      }),
      [databaseUrl],
    );
    return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.internalFailure;
  } finally {
    if (session !== undefined) {
      await session.close().catch(() => undefined);
    }
  }
}

function invalid(): InstanceAdvisoryAuthorityCommandResult {
  return { outcome: 'invalid_command' };
}

function writePresentation(
  stdout: CommandTextStream,
  presentation: InstanceAdvisoryAuthorityCommandPresentation,
  concealed: readonly string[] = [],
): boolean {
  const line = `${JSON.stringify(presentation)}\n`;
  if (concealed.some((marker) => marker.length > 0 && line.includes(marker))) {
    stdout.write(
      `${JSON.stringify(
        presentInstanceAdvisoryAuthorityCommandResult(null, { outcome: 'internal_failure' }),
      )}\n`,
    );
    return false;
  }
  stdout.write(line);
  return true;
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  return (
    entry.endsWith('/instance-advisory-authority-command-main.js') ||
    entry.endsWith('/instance-advisory-authority-command-main.ts')
  );
}

if (isDirectRun()) {
  runInstanceAdvisoryAuthorityCommand({
    argv: process.argv.slice(2),
    stdout: process.stdout,
    stderr: process.stderr,
    loadDatabaseUrl: loadInstanceAdvisoryAuthorityCommandDatabaseUrl,
    openBoundary: openInstanceAdvisoryAuthorityCommandBoundary,
  })
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch(() => {
      process.stderr.write('internal_failure\n');
      process.exitCode = INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.internalFailure;
    });
}
