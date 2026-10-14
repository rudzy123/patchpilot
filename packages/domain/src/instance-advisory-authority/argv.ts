/**
 * Deployment-local argv parser for one instance advisory authority command.
 * Issuance is fixed by this entrypoint. The caller cannot select it.
 * Correlation is an explicit nonsecret UUID and is not replay authority.
 */

import {
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandParse,
} from './command.js';

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE = [
  'Instance advisory authority deployment-local command.',
  'One explicit operation. One existing canonical User ID. No prompt.',
  '',
  '  pnpm instance-advisory-authority -- grant --user-id <user-id> --authority <authority> --correlation-id <correlation-id>',
  '  pnpm instance-advisory-authority -- revoke --user-id <user-id> --expected-grant-id <grant-id> --expected-authority <authority> --correlation-id <correlation-id>',
  '  pnpm instance-advisory-authority -- disable-user --user-id <user-id> --correlation-id <correlation-id>',
  '  pnpm instance-advisory-authority -- enable-user --user-id <user-id> --correlation-id <correlation-id>',
  '',
  'Authority values:',
  '  advisory_submit_local',
  '  advisory_approve_for_product_evaluation',
  '',
  'Issuance is the deployment-local command and cannot be supplied.',
  'The command does not accept organization, membership, role, permission, email, or credential material.',
  'The command uses deployment server configuration and does not print the database location.',
  '',
  'Exit codes:',
  '  0 new mutation',
  '  1 internal failure',
  '  2 exact replay',
  '  3 invalid command',
  '  4 not found',
  '  5 conflict',
  '  6 authority or user-state rejection',
  '  7 database unavailable',
  '',
  'help writes this text and no result. A result is one JSON object on standard output.',
].join('\n');

const CLI_OPERATIONS = {
  grant: 'grant',
  revoke: 'revoke',
  'disable-user': 'disable_user',
  'enable-user': 'enable_user',
} as const;

type CliOperation = keyof typeof CLI_OPERATIONS;

const GRANT_FLAGS = ['--user-id', '--authority', '--correlation-id'] as const;
const REVOKE_FLAGS = [
  '--user-id',
  '--expected-grant-id',
  '--expected-authority',
  '--correlation-id',
] as const;
const USER_FLAGS = ['--user-id', '--correlation-id'] as const;

const MAX_ARGV_LENGTH = 9;

export type InstanceAdvisoryAuthorityArgvParse =
  | { readonly ok: true; readonly command: InstanceAdvisoryAuthorityCommand }
  | { readonly ok: false; readonly outcome: 'invalid_command' }
  | { readonly ok: false; readonly outcome: 'help' };

export function parseInstanceAdvisoryAuthorityArgv(
  argv: readonly unknown[],
): InstanceAdvisoryAuthorityArgvParse {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > MAX_ARGV_LENGTH) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (!argv.every((token) => typeof token === 'string' && token.length > 0)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const tokens: readonly string[] = argv;
  if (tokens.length === 1 && (tokens[0] === 'help' || tokens[0] === '--help')) {
    return { ok: false, outcome: 'help' };
  }
  const operationName = tokens[0];
  if (!isCliOperation(operationName)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const flags = readFlags(tokens.slice(1), flagNames(operationName));
  if (flags === null) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const parsed = commandFromFlags(operationName, flags);
  if (!parsed.ok) {
    return { ok: false, outcome: 'invalid_command' };
  }
  return { ok: true, command: parsed.command };
}

function isCliOperation(value: string | undefined): value is CliOperation {
  return (
    value === 'grant' || value === 'revoke' || value === 'disable-user' || value === 'enable-user'
  );
}

function flagNames(operation: CliOperation): readonly string[] {
  if (operation === 'grant') {
    return GRANT_FLAGS;
  }
  if (operation === 'revoke') {
    return REVOKE_FLAGS;
  }
  return USER_FLAGS;
}

function readFlags(
  tokens: readonly string[],
  allowed: readonly string[],
): ReadonlyMap<string, string> | null {
  if (tokens.length !== allowed.length * 2) {
    return null;
  }
  const values = new Map<string, string>();
  for (let index = 0; index < tokens.length; index += 2) {
    const flag = tokens[index];
    const value = tokens[index + 1];
    if (
      flag === undefined ||
      value === undefined ||
      !flag.startsWith('--') ||
      flag.includes('=') ||
      !allowed.includes(flag) ||
      values.has(flag) ||
      value.startsWith('-')
    ) {
      return null;
    }
    values.set(flag, value);
  }
  if (values.size !== allowed.length) {
    return null;
  }
  return values;
}

function commandFromFlags(
  operation: CliOperation,
  flags: ReadonlyMap<string, string>,
): InstanceAdvisoryAuthorityCommandParse {
  const targetUserId = flags.get('--user-id');
  const correlationId = flags.get('--correlation-id');
  const domainOperation = CLI_OPERATIONS[operation];
  if (domainOperation === 'grant') {
    return parseInstanceAdvisoryAuthorityCommand({
      schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
      operation: domainOperation,
      targetUserId,
      authority: flags.get('--authority'),
      issuanceClassification: 'deployment_local_command',
      correlationId,
    });
  }
  if (domainOperation === 'revoke') {
    return parseInstanceAdvisoryAuthorityCommand({
      schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
      operation: domainOperation,
      targetUserId,
      expectedGrantId: flags.get('--expected-grant-id'),
      expectedAuthority: flags.get('--expected-authority'),
      correlationId,
    });
  }
  return parseInstanceAdvisoryAuthorityCommand({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: domainOperation,
    targetUserId,
    correlationId,
  });
}
