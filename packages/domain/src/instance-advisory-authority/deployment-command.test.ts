import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  executeInstanceAdvisoryAuthorityDeploymentCommand,
  instanceAdvisoryAuthorityCommandAcknowledgement,
  instanceAdvisoryAuthorityCommandExitCode,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE,
  parseInstanceAdvisoryAuthorityArgv,
  presentInstanceAdvisoryAuthorityCommandResult,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandPort,
  type InstanceAdvisoryAuthorityCommandResult,
} from './index.js';

const USER_ID = 'abcdefab-cdef-4abc-8def-abcdefabcdef';
const CORRELATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const GRANT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const OTHER_GRANT_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const here = path.dirname(fileURLToPath(import.meta.url));

function grantArgv(authority = 'advisory_submit_local', userId = USER_ID): string[] {
  return [
    'grant',
    '--user-id',
    userId,
    '--authority',
    authority,
    '--correlation-id',
    CORRELATION_ID,
  ];
}

function requireCommand(argv: readonly string[]): InstanceAdvisoryAuthorityCommand {
  const parsed = parseInstanceAdvisoryAuthorityArgv(argv);
  if (!parsed.ok) {
    throw new Error('expected a command');
  }
  return parsed.command;
}

function recordingPort(
  result:
    | InstanceAdvisoryAuthorityCommandResult
    | ((
        call: number,
      ) =>
        InstanceAdvisoryAuthorityCommandResult | Promise<InstanceAdvisoryAuthorityCommandResult>),
): {
  readonly port: InstanceAdvisoryAuthorityCommandPort;
  readonly calls: InstanceAdvisoryAuthorityCommand[];
} {
  const calls: InstanceAdvisoryAuthorityCommand[] = [];
  return {
    calls,
    port: {
      execute(command) {
        calls.push(command);
        const resolved = typeof result === 'function' ? result(calls.length) : result;
        return Promise.resolve(resolved);
      },
    },
  };
}

describe('instance advisory authority deployment command parser', () => {
  it('requires exactly one operation and one target user', () => {
    expect(parseInstanceAdvisoryAuthorityArgv([])).toEqual({
      ok: false,
      outcome: 'invalid_command',
    });
    expect(parseInstanceAdvisoryAuthorityArgv(['grant', 'revoke'])).toEqual({
      ok: false,
      outcome: 'invalid_command',
    });
    expect(
      parseInstanceAdvisoryAuthorityArgv([
        'grant',
        '--user-id',
        USER_ID,
        '--user-id',
        OTHER_GRANT_ID,
        '--authority',
        'advisory_submit_local',
        '--correlation-id',
        CORRELATION_ID,
      ]),
    ).toEqual({ ok: false, outcome: 'invalid_command' });
    expect(parseInstanceAdvisoryAuthorityArgv(['disable_user', '--user-id', USER_ID])).toEqual({
      ok: false,
      outcome: 'invalid_command',
    });
  });

  it('rejects malformed, padded, uppercase, email, and username targets', () => {
    for (const userId of [
      'not-a-uuid',
      ` ${USER_ID}`,
      `${USER_ID} `,
      USER_ID.toUpperCase(),
      'person@example.com',
      'username',
      '',
      '*',
      'all',
    ]) {
      expect(
        parseInstanceAdvisoryAuthorityArgv(grantArgv('advisory_submit_local', userId)),
      ).toEqual({ ok: false, outcome: 'invalid_command' });
    }
  });

  it('rejects organization, membership, role, permission, and lookup selectors', () => {
    const extras = [
      '--organization-id',
      '--membership-id',
      '--role',
      '--permission',
      '--email',
      '--username',
      '--display-name',
      '--all',
      '--file',
      '--sql',
    ];
    for (const flag of extras) {
      expect(
        parseInstanceAdvisoryAuthorityArgv([
          ...grantArgv(),
          flag,
          'abcdefab-cdef-4abc-8def-abcdefabcdff',
        ]),
      ).toEqual({ ok: false, outcome: 'invalid_command' });
    }
  });

  it('accepts only the two exact authority values', () => {
    const submit = requireCommand(grantArgv('advisory_submit_local'));
    const approve = requireCommand(grantArgv('advisory_approve_for_product_evaluation'));
    expect(submit.operation === 'grant' && submit.authority).toBe('advisory_submit_local');
    expect(approve.operation === 'grant' && approve.authority).toBe(
      'advisory_approve_for_product_evaluation',
    );
    for (const authority of [
      'owner',
      'admin',
      'member',
      'viewer',
      'instance_operator',
      '*',
      'advisory_admin',
      'capability_issuer',
      'provider',
      'evaluator',
      'finding_authority',
      'lifecycle_authority',
      'Advisory_submit_local',
      ' advisory_submit_local',
      'advisory_submit_local ',
      'deployment_local_command',
    ]) {
      expect(parseInstanceAdvisoryAuthorityArgv(grantArgv(authority))).toEqual({
        ok: false,
        outcome: 'invalid_command',
      });
    }
  });

  it('derives issuance and rejects overrides, timestamps, audit fields, and persistence fields', () => {
    const command = requireCommand(grantArgv());
    expect(command.operation === 'grant' && command.issuanceClassification).toBe(
      'deployment_local_command',
    );
    expect(Object.keys(command).sort()).toEqual([
      'authority',
      'correlationId',
      'issuanceClassification',
      'operation',
      'schemaVersion',
      'targetUserId',
    ]);
    for (const flag of [
      '--issuance-classification',
      '--issued-at',
      '--revoked-at',
      '--audit-actor',
      '--audit-action',
      '--actor-user-id',
      '--grant-id',
      '--prisma',
      '--transaction',
    ]) {
      expect(
        parseInstanceAdvisoryAuthorityArgv([...grantArgv(), flag, 'deployment_local_command']),
      ).toEqual({ ok: false, outcome: 'invalid_command' });
    }
  });

  it('preserves revoke expected grant identity and rejects wildcard input', () => {
    const command = requireCommand([
      'revoke',
      '--expected-authority',
      'advisory_submit_local',
      '--user-id',
      USER_ID,
      '--correlation-id',
      CORRELATION_ID,
      '--expected-grant-id',
      GRANT_ID,
    ]);
    expect(command).toMatchObject({
      operation: 'revoke',
      targetUserId: USER_ID,
      expectedGrantId: GRANT_ID,
      expectedAuthority: 'advisory_submit_local',
      correlationId: CORRELATION_ID,
    });
    expect(parseInstanceAdvisoryAuthorityArgv(['revoke-all'])).toEqual({
      ok: false,
      outcome: 'invalid_command',
    });
    expect(parseInstanceAdvisoryAuthorityArgv(['grant', '--user-id', '*'])).toEqual({
      ok: false,
      outcome: 'invalid_command',
    });
  });

  it('accepts disable-user and enable-user with only the target and correlation', () => {
    expect(
      requireCommand(['disable-user', '--user-id', USER_ID, '--correlation-id', CORRELATION_ID]),
    ).toEqual({
      schemaVersion: 'instance_advisory_authority_command_v1',
      operation: 'disable_user',
      targetUserId: USER_ID,
      correlationId: CORRELATION_ID,
    });
    expect(
      requireCommand(['enable-user', '--correlation-id', CORRELATION_ID, '--user-id', USER_ID]),
    ).toMatchObject({ operation: 'enable_user', targetUserId: USER_ID });
    expect(
      parseInstanceAdvisoryAuthorityArgv([
        'enable-user',
        '--user-id',
        USER_ID,
        '--correlation-id',
        CORRELATION_ID,
        '--authority',
        'advisory_submit_local',
      ]),
    ).toEqual({ ok: false, outcome: 'invalid_command' });
  });

  it('does not read standard input or normalize unsupported authority text', () => {
    expect(parseInstanceAdvisoryAuthorityArgv(grantArgv('Advisory_Submit_Local')).ok).toBe(false);
    expect(INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE).not.toContain('postgresql://');
    expect(INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE).not.toContain('DATABASE_URL');
  });
});

describe('instance advisory authority deployment command invocation', () => {
  it('calls the persistence boundary once for grant, revoke, disable, and enable', async () => {
    const grant = recordingPort({ outcome: 'granted', grantId: GRANT_ID });
    const grantCommand = requireCommand(grantArgv());
    await executeInstanceAdvisoryAuthorityDeploymentCommand(grant.port, grantCommand);
    expect(grant.calls).toEqual([grantCommand]);

    const revokeCommand = requireCommand([
      'revoke',
      '--user-id',
      USER_ID,
      '--expected-grant-id',
      GRANT_ID,
      '--expected-authority',
      'advisory_submit_local',
      '--correlation-id',
      CORRELATION_ID,
    ]);
    const revoke = recordingPort({ outcome: 'revoked', grantId: GRANT_ID });
    await executeInstanceAdvisoryAuthorityDeploymentCommand(revoke.port, revokeCommand);
    expect(revoke.calls).toEqual([revokeCommand]);

    for (const operation of ['disable-user', 'enable-user'] as const) {
      const command = requireCommand([
        operation,
        '--user-id',
        USER_ID,
        '--correlation-id',
        CORRELATION_ID,
      ]);
      const recorded = recordingPort({
        outcome: operation === 'disable-user' ? 'user_disabled' : 'user_enabled',
      });
      await executeInstanceAdvisoryAuthorityDeploymentCommand(recorded.port, command);
      expect(recorded.calls).toEqual([command]);
    }
  });

  it('presents replay, conflict, absence, and replacement without relabeling them', () => {
    const grant = requireCommand(grantArgv());
    expect(
      presentInstanceAdvisoryAuthorityCommandResult(grant, { outcome: 'already_applied' }),
    ).toMatchObject({
      outcome: 'already_applied',
      acknowledgement: 'replayed',
      grantId: null,
    });
    expect(instanceAdvisoryAuthorityCommandExitCode('already_applied')).toBe(
      INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.alreadyApplied,
    );
    expect(
      presentInstanceAdvisoryAuthorityCommandResult(grant, { outcome: 'active_grant_conflict' }),
    ).toMatchObject({ outcome: 'active_grant_conflict', acknowledgement: 'unchanged' });
    expect(instanceAdvisoryAuthorityCommandExitCode('grant_absent')).toBe(
      INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.notFound,
    );
    expect(instanceAdvisoryAuthorityCommandExitCode('expected_grant_mismatch')).toBe(
      INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.conflict,
    );
    expect(instanceAdvisoryAuthorityCommandAcknowledgement('grant_absent')).not.toBe('replayed');
    expect(instanceAdvisoryAuthorityCommandAcknowledgement('expected_grant_mismatch')).not.toBe(
      'replayed',
    );
  });

  it('does not describe re-enablement as a grant', () => {
    const command = requireCommand([
      'enable-user',
      '--user-id',
      USER_ID,
      '--correlation-id',
      CORRELATION_ID,
    ]);
    const presented = presentInstanceAdvisoryAuthorityCommandResult(command, {
      outcome: 'user_enabled',
    });
    expect(presented.outcome).toBe('user_enabled');
    expect(presented.authority).toBeNull();
    expect(presented.grantId).toBeNull();
    expect(JSON.stringify(presented)).not.toContain('advisory_submit_local');
    expect(JSON.stringify(presented)).not.toContain('"granted"');
  });

  it('keeps uncertain acknowledgement for lost persistence results', () => {
    expect(instanceAdvisoryAuthorityCommandAcknowledgement('database_unavailable')).toBe(
      'uncertain',
    );
    expect(instanceAdvisoryAuthorityCommandAcknowledgement('transaction_aborted')).toBe(
      'uncertain',
    );
    expect(instanceAdvisoryAuthorityCommandAcknowledgement('internal_failure')).toBe('uncertain');
    expect(instanceAdvisoryAuthorityCommandExitCode('database_unavailable')).toBe(7);
    expect(instanceAdvisoryAuthorityCommandExitCode('internal_failure')).toBe(1);
    expect(instanceAdvisoryAuthorityCommandExitCode('user_inactive')).toBe(6);
    expect(instanceAdvisoryAuthorityCommandExitCode('user_absent')).toBe(4);
    expect(instanceAdvisoryAuthorityCommandExitCode('active_grant_conflict')).toBe(5);
    expect(instanceAdvisoryAuthorityCommandExitCode('invalid_command')).toBe(3);
    expect(instanceAdvisoryAuthorityCommandExitCode('granted')).toBe(0);
  });

  it('omits raw rows, credentials, and database locations from the result', () => {
    const presented = presentInstanceAdvisoryAuthorityCommandResult(requireCommand(grantArgv()), {
      outcome: 'granted',
      grantId: GRANT_ID,
    });
    const text = JSON.stringify(presented);
    expect(Object.keys(presented).sort()).toEqual([
      'acknowledgement',
      'authority',
      'grantId',
      'operation',
      'outcome',
      'schemaVersion',
      'targetUserId',
    ]);
    expect(text).not.toContain('postgresql://');
    expect(text).not.toContain('password');
    expect(text).not.toContain('organization');
    expect(text).not.toContain('membership');
    expect(text).not.toContain('SELECT');
  });

  it('inserts no audit event and performs no tenant lookup in the command sources', () => {
    const sources = ['argv.ts', 'deployment-command.ts', 'execution.ts']
      .map((name) => readFileSync(path.join(here, name), 'utf8'))
      .join('\n');
    expect(sources).not.toContain('auditEvent');
    expect(sources).not.toContain('organization.find');
    expect(sources).not.toContain('membership.find');
    expect(sources).not.toContain('@prisma/client');
    expect(sources).not.toContain('process.env');
    expect(sources).not.toContain('readFile');
    expect(sources).not.toContain('stdin');
  });
});
