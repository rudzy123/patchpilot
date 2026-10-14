/**
 * Instance advisory authority contracts. No database and no command runner.
 */

import { describe, expect, it } from 'vitest';

import {
  INSTANCE_ADVISORY_ACTIVE_GRANT_INVARIANTS,
  INSTANCE_ADVISORY_AUDIT_ACTIONS,
  INSTANCE_ADVISORY_AUDIT_FORBIDDEN_PAYLOAD_FIELDS,
  INSTANCE_ADVISORY_AUDIT_REPLAY,
  INSTANCE_ADVISORY_AUTHORITIES,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY,
  INSTANCE_ADVISORY_AUTHORITY_INVARIANTS,
  INSTANCE_ADVISORY_AUTHORITY_OPERATIONS,
  INSTANCE_ADVISORY_AUTHORITY_POWERS,
  INSTANCE_ADVISORY_AUTHORIZATION_EXTERNAL_COLLAPSE,
  INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES,
  INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
  INSTANCE_ADVISORY_CONCURRENT_GRANT_CONTRACT,
  INSTANCE_ADVISORY_DISABLEMENT_CONTRACT,
  INSTANCE_ADVISORY_GRANT_EXCLUDED_IDENTITY_FIELDS,
  INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS,
  INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES,
  INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS,
  INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS,
  INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS,
  INSTANCE_ADVISORY_PRINCIPAL_EXCLUDED_FIELDS,
  INSTANCE_ADVISORY_PRODUCT_NONAUTHORITY,
  INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS,
  INSTANCE_ADVISORY_REENABLEMENT_CONTRACT,
  INSTANCE_ADVISORY_REGRANT_CONTRACT,
  INSTANCE_ADVISORY_REJECTED_AUTHORITIES,
  INSTANCE_ADVISORY_REJECTED_GRANT_LIFECYCLE_STATES,
  INSTANCE_ADVISORY_REJECTED_ISSUANCE_CLASSIFICATIONS,
  INSTANCE_ADVISORY_REVOCATION_CONTRACT,
  INSTANCE_ADVISORY_REVOCATION_REPLAY,
  INSTANCE_ADVISORY_SEPARATION_RESIDUAL,
  INSTANCE_ADVISORY_TENANT_NONAUTHORITY,
  INSTANCE_ADVISORY_USER_ABSENCE_DISCLOSURE,
  canonicalInstanceAdvisoryPrincipalId,
  classifyInstanceAdvisoryAuthorityCommand,
  classifyInstanceAdvisoryAuthorization,
  classifyInstanceAdvisoryConcurrentGrantReread,
  classifyInstanceAdvisoryConcurrentRevocationReread,
  classifyInstanceAdvisoryGrantLifecycleMutation,
  collapseInstanceAdvisoryAuthorizationForExternalBoundary,
  compareInstanceAdvisoryPrincipals,
  instanceAdvisoryAuditIntent,
  instanceAdvisoryGrantLifecycle,
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryAuthorityCommandOutcome,
  parseInstanceAdvisoryAuthorizationReadRequest,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthoritySnapshot,
  type InstanceAdvisoryAuthorizationFacts,
  type InstanceAdvisoryAuthorizationReadRequest,
  type InstanceAdvisoryCommandDecision,
} from './index.js';

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_HEX = 'abcdefab-cdef-4abc-8abc-abcdefabcdef';
const USER_B = '22222222-2222-4222-8222-222222222222';
const CORRELATION = '10101010-1010-4101-8101-101010101010';
const OTHER_CORRELATION = '13131313-1313-4131-8131-131313131313';
const GRANT_ID = '33333333-3333-4333-8333-333333333333';
const NEW_GRANT_ID = '44444444-4444-4444-8444-444444444444';

type CommandLeak = Extract<
  keyof InstanceAdvisoryAuthorityCommand,
  | 'organizationId'
  | 'membershipId'
  | 'role'
  | 'permission'
  | 'issuedAt'
  | 'revokedAt'
  | 'grantId'
  | 'password'
  | 'transaction'
>;
const commandHasNoTenantOrPersistenceAuthority: CommandLeak extends never ? true : never = true;

type AuthorizationLeak = Extract<
  keyof InstanceAdvisoryAuthorizationReadRequest,
  'organizationId' | 'membershipId' | 'role' | 'permission'
>;
const authorizationOmitsTenantAuthority: AuthorizationLeak extends never ? true : never = true;

function grantBody(
  authority: InstanceAdvisoryAuthority,
  extras: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'grant',
    targetUserId: USER_A,
    authority,
    issuanceClassification: 'deployment_local_command',
    correlationId: CORRELATION,
    ...extras,
  };
}

function userBody(operation: 'disable_user' | 'enable_user'): Record<string, unknown> {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation,
    targetUserId: USER_A,
    correlationId: CORRELATION,
  };
}

function revokeBody(
  authority: InstanceAdvisoryAuthority = 'advisory_submit_local',
  expectedGrantId = GRANT_ID,
  extras: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'revoke',
    targetUserId: USER_A,
    expectedGrantId,
    expectedAuthority: authority,
    correlationId: CORRELATION,
    ...extras,
  };
}

function parsedGrant(authority: InstanceAdvisoryAuthority, correlationId = CORRELATION) {
  const parsed = parseInstanceAdvisoryAuthorityCommand({
    ...grantBody(authority),
    correlationId,
  });
  if (!parsed.ok || parsed.command.operation !== 'grant') {
    throw new Error('expected a legal grant command');
  }
  return parsed.command;
}

function parsedUser(operation: 'disable_user' | 'enable_user') {
  const parsed = parseInstanceAdvisoryAuthorityCommand(userBody(operation));
  if (!parsed.ok) {
    throw new Error('expected a legal user command');
  }
  return parsed.command;
}

function parsedRevoke(
  authority: InstanceAdvisoryAuthority = 'advisory_submit_local',
  expectedGrantId = GRANT_ID,
  correlationId = CORRELATION,
) {
  const parsed = parseInstanceAdvisoryAuthorityCommand({
    ...revokeBody(authority, expectedGrantId),
    correlationId,
  });
  if (!parsed.ok || parsed.command.operation !== 'revoke') {
    throw new Error('expected a legal revoke command');
  }
  return parsed.command;
}

function snapshot(
  overrides: Partial<InstanceAdvisoryAuthoritySnapshot> = {},
): InstanceAdvisoryAuthoritySnapshot {
  return {
    schemaVersion: 'instance_advisory_authority_snapshot_v1',
    user: { existence: 'present', status: 'active' },
    activeGrant: null,
    revokedGrants: [],
    malformed: false,
    ...overrides,
  };
}

function activeGrant(authority: InstanceAdvisoryAuthority, userId = USER_A) {
  return {
    grantId: GRANT_ID,
    userId,
    authority,
    issuanceClassification: 'deployment_local_command' as const,
    lifecycle: 'active' as const,
  };
}

function revokedGrant(authority: InstanceAdvisoryAuthority, grantId = GRANT_ID, userId = USER_A) {
  return {
    grantId,
    userId,
    authority,
    issuanceClassification: 'deployment_local_command' as const,
    lifecycle: 'revoked' as const,
  };
}

function readRequest(
  requiredAuthority: InstanceAdvisoryAuthority = 'advisory_submit_local',
  userId = USER_A,
): InstanceAdvisoryAuthorizationReadRequest {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
    userId,
    requiredAuthority,
  };
}

function facts(
  overrides: Partial<InstanceAdvisoryAuthorizationFacts> = {},
): InstanceAdvisoryAuthorizationFacts {
  return {
    schemaVersion: 'instance_advisory_authorization_facts_v1',
    availability: 'loaded',
    userId: USER_A,
    user: { existence: 'present', status: 'active' },
    activeGrant: {
      userId: USER_A,
      authority: 'advisory_submit_local',
      issuanceClassification: 'deployment_local_command',
    },
    malformed: false,
    ...overrides,
  };
}

function expectNoWrite(decision: InstanceAdvisoryCommandDecision, outcome: string): void {
  expect(decision.outcome).toBe(outcome);
  expect(decision.write).toEqual({ kind: 'none' });
  expect(decision.auditEvents).toBe(0);
  expect(decision.deletesGrant).toBe(false);
  expect(decision.reactivatesGrant).toBe(false);
  expect(decision.changesIssuedAt).toBe(false);
  expect(decision.correlationDefinesReplay).toBe(false);
}

describe('instance advisory authority classifications', () => {
  it('accepts exactly the two governed classifications', () => {
    expect(INSTANCE_ADVISORY_AUTHORITIES).toEqual([
      'advisory_submit_local',
      'advisory_approve_for_product_evaluation',
    ]);
    expect(isInstanceAdvisoryAuthority('advisory_submit_local')).toBe(true);
    expect(isInstanceAdvisoryAuthority('advisory_approve_for_product_evaluation')).toBe(true);
    expect(commandHasNoTenantOrPersistenceAuthority).toBe(true);
    expect(authorizationOmitsTenantAuthority).toBe(true);
  });

  it('rejects arbitrary and rejected authority strings', () => {
    for (const value of [
      ...INSTANCE_ADVISORY_REJECTED_AUTHORITIES,
      'owner',
      'admin',
      'advisory_submit_local ',
      'ADVISORY_SUBMIT_LOCAL',
      'advisory_submit_local\n',
      '\tadvisory_submit_local',
      '',
      null,
      undefined,
    ]) {
      expect(isInstanceAdvisoryAuthority(value)).toBe(false);
    }
  });

  it('gives neither classification a current product power', () => {
    for (const powers of Object.values(INSTANCE_ADVISORY_AUTHORITY_POWERS)) {
      expect(powers.grantsAuthorityInThisSession).toBe(false);
      for (const value of Object.values(powers)) {
        if (typeof value === 'boolean') {
          expect(value).toBe(false);
        }
      }
    }
    expect(INSTANCE_ADVISORY_AUTHORITY_POWERS.advisory_submit_local.futureMeaning).toBe(
      'submit_one_local_maintainer_reviewed_advisory_document',
    );
    expect(
      INSTANCE_ADVISORY_AUTHORITY_POWERS.advisory_approve_for_product_evaluation.futureMeaning,
    ).toBe('approve_one_exact_submitted_advisory_revision_after_service_validation');
  });

  it('closes issuance to the deployment-local command', () => {
    expect(INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS).toEqual(['deployment_local_command']);
    for (const rejected of INSTANCE_ADVISORY_REJECTED_ISSUANCE_CLASSIFICATIONS) {
      expect(
        parseInstanceAdvisoryAuthorityCommand(
          grantBody('advisory_submit_local', {
            issuanceClassification: rejected,
          }),
        ).ok,
      ).toBe(false);
    }
  });
});

describe('instance advisory grant lifecycle and identity', () => {
  it('is active only while revocation is absent and revoked once a time is committed', () => {
    expect(INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES).toEqual(['active', 'revoked']);
    expect(instanceAdvisoryGrantLifecycle(null)).toBe('active');
    expect(instanceAdvisoryGrantLifecycle('2026-10-14T12:00:00.000Z')).toBe('revoked');
    expect(instanceAdvisoryGrantLifecycle('')).toBe('malformed_persisted_state');
    expect(instanceAdvisoryGrantLifecycle('  ')).toBe('malformed_persisted_state');
    for (const rejected of INSTANCE_ADVISORY_REJECTED_GRANT_LIFECYCLE_STATES) {
      expect(INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES).not.toContain(rejected);
      expect(classifyInstanceAdvisoryGrantLifecycleMutation(rejected)).toBe('immutable_conflict');
    }
  });

  it('keeps organization and downstream records out of grant identity', () => {
    expect(INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS).toEqual([
      'id',
      'user_id',
      'authority',
      'issued_at',
      'revoked_at',
      'issuance_classification',
      'command_correlation_id',
    ]);
    expect(INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS).not.toContain('organization_id');
    for (const field of INSTANCE_ADVISORY_GRANT_EXCLUDED_IDENTITY_FIELDS) {
      expect(INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS).not.toContain(field);
    }
  });

  it('treats reactivation, deletion, and in-place rewrite as immutable conflicts', () => {
    expect(classifyInstanceAdvisoryGrantLifecycleMutation('insert_new_grant')).toBe(
      'insert_new_grant',
    );
    expect(classifyInstanceAdvisoryGrantLifecycleMutation('revoke_active_grant')).toBe(
      'revoke_active_grant',
    );
    expect(classifyInstanceAdvisoryGrantLifecycleMutation('reactivate_revoked_grant')).toBe(
      'immutable_conflict',
    );
    expect(classifyInstanceAdvisoryGrantLifecycleMutation('delete_grant')).toBe(
      'immutable_conflict',
    );
    expect(classifyInstanceAdvisoryGrantLifecycleMutation('rewrite_immutable_fields')).toBe(
      'immutable_conflict',
    );
  });
});

describe('instance advisory authority command', () => {
  it('closes the operation set', () => {
    expect(INSTANCE_ADVISORY_AUTHORITY_OPERATIONS).toEqual([
      'grant',
      'revoke',
      'disable_user',
      'enable_user',
    ]);
    expect(
      parseInstanceAdvisoryAuthorityCommand({ ...revokeBody(), operation: 'bootstrap' }).ok,
    ).toBe(false);
  });

  it('accepts one exact grant and the three user operations', () => {
    const grant = parseInstanceAdvisoryAuthorityCommand(grantBody('advisory_submit_local'));
    expect(grant.ok).toBe(true);
    if (grant.ok) {
      expect(grant.command).toEqual({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation: 'grant',
        targetUserId: USER_A,
        authority: 'advisory_submit_local',
        issuanceClassification: 'deployment_local_command',
        correlationId: CORRELATION,
      });
    }
    expect(parseInstanceAdvisoryAuthorityCommand(revokeBody()).ok).toBe(true);
    const revoke = parseInstanceAdvisoryAuthorityCommand(revokeBody());
    if (revoke.ok && revoke.command.operation === 'revoke') {
      expect(revoke.command.expectedGrantId).toBe(GRANT_ID);
      expect(revoke.command.expectedAuthority).toBe('advisory_submit_local');
      expect(Object.isFrozen(revoke.command)).toBe(true);
    }
    for (const operation of ['disable_user', 'enable_user'] as const) {
      expect(parseInstanceAdvisoryAuthorityCommand(userBody(operation)).ok).toBe(true);
    }
  });

  it('rejects tenant, timestamp, persistence, and callback fields', () => {
    const prohibited = [
      'organizationId',
      'membershipId',
      'role',
      'permission',
      'tenantRole',
      'tenantPermission',
      'issuedAt',
      'revokedAt',
      'grantId',
      'active',
      'auditAction',
      'password',
      'passwordHash',
      'sessionId',
      'prisma',
      'sql',
      'advisoryRevisionId',
      'approvalPurpose',
      'capabilityId',
      'provider',
      'evaluator',
      'productMatchEvidence',
      'findingId',
    ];
    for (const field of prohibited) {
      expect(INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS).toContain(field);
      expect(
        parseInstanceAdvisoryAuthorityCommand(
          grantBody('advisory_submit_local', { [field]: USER_B }),
        ).ok,
      ).toBe(false);
    }
    let invoked = 0;
    const callback = () => {
      invoked += 1;
      return undefined;
    };
    expect(
      parseInstanceAdvisoryAuthorityCommand(
        grantBody('advisory_submit_local', { transaction: callback, callback }),
      ).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...grantBody('advisory_submit_local'),
        correlationId: callback,
      }).ok,
    ).toBe(false);
    expect(invoked).toBe(0);
    expect(
      parseInstanceAdvisoryAuthorityCommand(
        revokeBody('advisory_submit_local', GRANT_ID, { grantId: GRANT_ID }),
      ).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation: 'revoke',
        targetUserId: USER_A,
        correlationId: CORRELATION,
      }).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand(
        revokeBody('advisory_submit_local', GRANT_ID, { authority: 'advisory_submit_local' }),
      ).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...revokeBody(),
        expectedGrantId: USER_HEX.toUpperCase(),
      }).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...revokeBody(),
        expectedAuthority: 'advisory_admin',
      }).ok,
    ).toBe(false);
  });

  it('requires a canonical lowercase target user id', () => {
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...grantBody('advisory_submit_local'),
        targetUserId: USER_HEX,
      }).ok,
    ).toBe(true);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...grantBody('advisory_submit_local'),
        targetUserId: USER_HEX.toUpperCase(),
      }).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...grantBody('advisory_submit_local'),
        targetUserId: ` ${USER_A}`,
      }).ok,
    ).toBe(false);
    expect(
      parseInstanceAdvisoryAuthorityCommand({
        ...grantBody('advisory_submit_local'),
        targetUserId: 'not-a-user',
      }).ok,
    ).toBe(false);
  });

  it('rejects getters, proxies, and foreign prototypes without invoking them', () => {
    let reads = 0;
    const withGetter: Record<string, unknown> = grantBody('advisory_submit_local');
    Object.defineProperty(withGetter, 'authority', {
      enumerable: true,
      get() {
        reads += 1;
        return 'advisory_submit_local';
      },
    });
    expect(parseInstanceAdvisoryAuthorityCommand(withGetter).ok).toBe(false);
    expect(reads).toBe(0);
    const proxy = new Proxy(grantBody('advisory_submit_local'), {});
    expect(parseInstanceAdvisoryAuthorityCommand(proxy).ok).toBe(false);
    const foreign = Object.create({ organizationId: USER_B }) as Record<string, unknown>;
    Object.assign(foreign, grantBody('advisory_submit_local'));
    expect(parseInstanceAdvisoryAuthorityCommand(foreign).ok).toBe(false);
  });
});

describe('instance advisory separation of duties', () => {
  it('treats the same canonical user as one principal across case, and distinct ids as distinct', () => {
    expect(canonicalInstanceAdvisoryPrincipalId(USER_HEX.toUpperCase())).toBe(USER_HEX);
    expect(compareInstanceAdvisoryPrincipals(USER_HEX, USER_HEX.toUpperCase())).toEqual({
      classification: 'self_approval_forbidden',
      userId: USER_HEX,
    });
    expect(compareInstanceAdvisoryPrincipals(USER_A, USER_B)).toEqual({
      classification: 'distinct',
      submitterUserId: USER_A,
      reviewerUserId: USER_B,
    });
    expect(compareInstanceAdvisoryPrincipals(USER_A, CORRELATION)).toEqual({
      classification: 'distinct',
      submitterUserId: USER_A,
      reviewerUserId: CORRELATION,
    });
  });

  it('does not accept email, membership, session, or a malformed id as separation', () => {
    expect(compareInstanceAdvisoryPrincipals(USER_A, 'owner@example.com')).toEqual({
      classification: 'malformed_principal',
    });
    expect(compareInstanceAdvisoryPrincipals('', USER_B)).toEqual({
      classification: 'malformed_principal',
    });
    expect(INSTANCE_ADVISORY_PRINCIPAL_EXCLUDED_FIELDS).toEqual(
      expect.arrayContaining([
        'organizationId',
        'membershipId',
        'role',
        'permission',
        'sessionId',
        'email',
        'displayName',
        'username',
        'advisoryRevisionId',
        'capabilityId',
        'correlationId',
        'instanceOperatorAttestation',
      ]),
    );
    expect(compareInstanceAdvisoryPrincipals.length).toBe(2);
    expect(INSTANCE_ADVISORY_SEPARATION_RESIDUAL).toMatchObject({
      detectableByCanonicalUserIdComparison: false,
      speculativeIdentityMatchingAuthorized: false,
      comparisonRemainsCanonicalUserId: true,
    });
  });
});

describe('instance advisory grant decisions', () => {
  it('grants once when the active user has no grant', () => {
    const decision = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local'),
      snapshot(),
    );
    expect(decision.outcome).toBe('granted');
    expect(decision.write).toEqual({
      kind: 'insert_grant',
      grantIdSource: 'database',
      issuedAtSource: 'database_clock',
    });
    expect(decision.auditEvents).toBe(1);
    expect(decision.reactivatesGrant).toBe(false);
  });

  it('replays an exact active grant without a write, including a different correlation id', () => {
    const stored = snapshot({
      activeGrant: activeGrant('advisory_submit_local'),
    });
    const first = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local', CORRELATION),
      stored,
    );
    const retry = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local', OTHER_CORRELATION),
      stored,
    );
    expectNoWrite(first, 'already_applied');
    expectNoWrite(retry, 'already_applied');
  });

  it('conflicts when another active authority is already held and does not replace it', () => {
    const decision = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_approve_for_product_evaluation'),
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expectNoWrite(decision, 'active_grant_conflict');
    expect(INSTANCE_ADVISORY_ACTIVE_GRANT_INVARIANTS).toMatchObject({
      maxActiveGrantsPerUser: 1,
      submissionAndApprovalMutuallyExclusive: true,
      enforcement: 'persistence_invariant',
      applicationCheckAloneSufficient: false,
      silentRevokeOrReplace: false,
    });
  });

  it('classifies one identical race as one grant and one already_applied reread', () => {
    const winner = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local'),
      snapshot(),
    );
    const loser = classifyInstanceAdvisoryConcurrentGrantReread(
      parsedGrant('advisory_submit_local'),
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expect(winner.outcome).toBe('granted');
    expectNoWrite(loser, 'already_applied');
    expect(INSTANCE_ADVISORY_CONCURRENT_GRANT_CONTRACT).toEqual({
      newGrants: 1,
      grantAuditEvents: 1,
      grantedResults: 1,
      alreadyAppliedResults: 1,
      unboundedRetryLoop: false,
      unexpectedUniquenessIsAutomaticReplay: false,
      unexpectedUniquenessOutcome: 'concurrency_conflict',
      rereadsAfterActiveGrantUniquenessFailure: 1,
    });
  });

  it('does not treat an unexpected uniqueness reread as replay', () => {
    const decision = classifyInstanceAdvisoryConcurrentGrantReread(
      parsedGrant('advisory_submit_local'),
      snapshot(),
    );
    expectNoWrite(decision, 'concurrency_conflict');
    const conflict = classifyInstanceAdvisoryConcurrentGrantReread(
      parsedGrant('advisory_submit_local'),
      snapshot({ activeGrant: activeGrant('advisory_approve_for_product_evaluation') }),
    );
    expectNoWrite(conflict, 'active_grant_conflict');
  });

  it('rereads one failed revocation without revoking a different grant', () => {
    const command = parsedRevoke('advisory_submit_local', GRANT_ID);
    const replay = classifyInstanceAdvisoryConcurrentRevocationReread(
      command,
      snapshot({ revokedGrants: [revokedGrant('advisory_submit_local', GRANT_ID)] }),
    );
    expectNoWrite(replay, 'already_applied');
    const stillActive = classifyInstanceAdvisoryConcurrentRevocationReread(
      command,
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expectNoWrite(stillActive, 'concurrency_conflict');
    const replacement = classifyInstanceAdvisoryConcurrentRevocationReread(
      command,
      snapshot({
        activeGrant: {
          ...activeGrant('advisory_submit_local'),
          grantId: NEW_GRANT_ID,
        },
      }),
    );
    expectNoWrite(replacement, 'expected_grant_mismatch');
  });

  it('revokes only the expected active grant and replays that grant alone', () => {
    const revoke = parsedRevoke('advisory_approve_for_product_evaluation');
    const first = classifyInstanceAdvisoryAuthorityCommand(
      revoke,
      snapshot({ activeGrant: activeGrant('advisory_approve_for_product_evaluation') }),
    );
    expect(first.outcome).toBe('revoked');
    expect(first.write).toEqual({
      kind: 'revoke_active_grant',
      revokedAtSource: 'database_clock',
      target: 'expected_active_grant',
    });
    expect(first.deletesGrant).toBe(false);
    expect(first.auditEvents).toBe(1);
    const replay = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke('advisory_approve_for_product_evaluation', GRANT_ID, OTHER_CORRELATION),
      snapshot({
        revokedGrants: [revokedGrant('advisory_approve_for_product_evaluation')],
      }),
    );
    expectNoWrite(replay, 'already_applied');
    const absent = classifyInstanceAdvisoryAuthorityCommand(revoke, snapshot());
    expectNoWrite(absent, 'grant_absent');
    expect(INSTANCE_ADVISORY_REVOCATION_REPLAY).toMatchObject({
      noGrantRowIsAlreadyApplied: false,
      noActiveGrantIsAlreadyApplied: false,
      expectedGrantIdOnCommand: true,
      expectedAuthorityOnCommand: true,
      callerMintedGrantIdOnCommand: false,
      replacementActiveGrantIsImplicitlyRevoked: false,
      correlationDefinesReplay: false,
      blindRevokeOfWhateverIsActive: false,
    });
    expect(INSTANCE_ADVISORY_REVOCATION_CONTRACT.deletesGrant).toBe(false);
    expect(INSTANCE_ADVISORY_REVOCATION_CONTRACT.revokesADifferentActiveGrant).toBe(false);
  });

  it('does not treat a replaced grant as replay and does not revoke the replacement', () => {
    const oldRevoke = parsedRevoke('advisory_submit_local', GRANT_ID);
    const replaced = snapshot({
      activeGrant: {
        ...activeGrant('advisory_approve_for_product_evaluation'),
        grantId: NEW_GRANT_ID,
      },
      revokedGrants: [revokedGrant('advisory_submit_local', GRANT_ID)],
    });
    const decision = classifyInstanceAdvisoryAuthorityCommand(oldRevoke, replaced);
    expectNoWrite(decision, 'expected_grant_mismatch');
    const sameAuthorityReplacement = classifyInstanceAdvisoryAuthorityCommand(
      oldRevoke,
      snapshot({
        activeGrant: {
          ...activeGrant('advisory_submit_local'),
          grantId: NEW_GRANT_ID,
        },
        revokedGrants: [revokedGrant('advisory_submit_local', GRANT_ID)],
      }),
    );
    expectNoWrite(sameAuthorityReplacement, 'expected_grant_mismatch');
    const wrongAuthority = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke('advisory_submit_local', NEW_GRANT_ID),
      snapshot({
        activeGrant: {
          ...activeGrant('advisory_approve_for_product_evaluation'),
          grantId: NEW_GRANT_ID,
        },
      }),
    );
    expectNoWrite(wrongAuthority, 'active_authority_mismatch');
    const otherHistory = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke('advisory_submit_local', NEW_GRANT_ID),
      snapshot({
        revokedGrants: [revokedGrant('advisory_approve_for_product_evaluation', GRANT_ID)],
      }),
    );
    expectNoWrite(otherHistory, 'expected_grant_mismatch');
    const historicalAuthority = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke('advisory_approve_for_product_evaluation', GRANT_ID),
      snapshot({
        revokedGrants: [revokedGrant('advisory_submit_local', GRANT_ID)],
      }),
    );
    expectNoWrite(historicalAuthority, 'active_authority_mismatch');
  });

  it('re-grants only by inserting a new grant after no active grant remains', () => {
    const decision = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_approve_for_product_evaluation'),
      snapshot({
        revokedGrants: [revokedGrant('advisory_submit_local')],
      }),
    );
    expect(decision.outcome).toBe('granted');
    expect(decision.write.kind).toBe('insert_grant');
    expect(decision.reactivatesGrant).toBe(false);
    expect(INSTANCE_ADVISORY_REGRANT_CONTRACT).toMatchObject({
      insertsNewGrantId: true,
      priorRevokedGrantUnchanged: true,
      inPlaceReactivation: false,
      sameAuthorityPermittedAfterRevocation: true,
      otherAuthorityPermittedAfterRevocation: true,
    });
  });

  it('disables without revoking and replays an already disabled user', () => {
    const disable = parsedUser('disable_user');
    const first = classifyInstanceAdvisoryAuthorityCommand(
      disable,
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expect(first.outcome).toBe('user_disabled');
    expect(first.write).toEqual({ kind: 'disable_user', revokesActiveGrant: false });
    expect(first.auditEvents).toBe(1);
    const replay = classifyInstanceAdvisoryAuthorityCommand(
      disable,
      snapshot({
        user: { existence: 'present', status: 'disabled' },
        activeGrant: activeGrant('advisory_submit_local'),
      }),
    );
    expectNoWrite(replay, 'already_applied');
    expect(INSTANCE_ADVISORY_DISABLEMENT_CONTRACT.automaticGrantRevocation).toBe(false);
    expect(INSTANCE_ADVISORY_DISABLEMENT_CONTRACT.activeGrantRowMayRemain).toBe(true);
    expect(
      INSTANCE_ADVISORY_DISABLEMENT_CONTRACT.reenablementRestoresAuthorityOnlyIfActiveGrantWasNotRevoked,
    ).toBe(true);
  });

  it('re-enables without granting authority and replays an already active user', () => {
    const enable = parsedUser('enable_user');
    const first = classifyInstanceAdvisoryAuthorityCommand(
      enable,
      snapshot({
        user: { existence: 'present', status: 'disabled' },
        revokedGrants: [revokedGrant('advisory_submit_local')],
      }),
    );
    expect(first.outcome).toBe('user_enabled');
    expect(first.write).toEqual({
      kind: 'enable_user',
      insertsGrant: false,
      reactivatesRevokedGrant: false,
    });
    const replay = classifyInstanceAdvisoryAuthorityCommand(enable, snapshot());
    expectNoWrite(replay, 'already_applied');
    expect(INSTANCE_ADVISORY_REENABLEMENT_CONTRACT.createsAdvisoryGrant).toBe(false);
    expect(INSTANCE_ADVISORY_REENABLEMENT_CONTRACT.isAuthorityGrant).toBe(false);
  });

  it('returns user_absent for a missing user and does not grant a disabled user who has no grant', () => {
    const missing = snapshot({ user: { existence: 'absent' } });
    expectNoWrite(
      classifyInstanceAdvisoryAuthorityCommand(parsedGrant('advisory_submit_local'), missing),
      'user_absent',
    );
    expectNoWrite(classifyInstanceAdvisoryAuthorityCommand(parsedRevoke(), missing), 'user_absent');
    const disabled = snapshot({ user: { existence: 'present', status: 'disabled' } });
    expectNoWrite(
      classifyInstanceAdvisoryAuthorityCommand(parsedGrant('advisory_submit_local'), disabled),
      'user_inactive',
    );
    expectNoWrite(
      classifyInstanceAdvisoryAuthorityCommand(
        parsedGrant('advisory_submit_local'),
        snapshot({
          user: { existence: 'present', status: 'disabled' },
          activeGrant: activeGrant('advisory_submit_local'),
        }),
      ),
      'already_applied',
    );
    expectNoWrite(
      classifyInstanceAdvisoryAuthorityCommand(
        parsedGrant('advisory_approve_for_product_evaluation'),
        snapshot({
          user: { existence: 'present', status: 'disabled' },
          activeGrant: activeGrant('advisory_submit_local'),
        }),
      ),
      'active_grant_conflict',
    );
    expect(INSTANCE_ADVISORY_USER_ABSENCE_DISCLOSURE).toMatchObject({
      commandOutcome: 'user_absent',
      usesUserNotFoundOutcome: false,
      acceptableOnDeploymentLocalCommand: true,
      noGrantRowOutcome: 'grant_absent',
      noGrantRowIsAlreadyApplied: false,
    });
  });

  it('still revokes an active grant after the user is disabled', () => {
    const decision = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke('advisory_submit_local'),
      snapshot({
        user: { existence: 'present', status: 'disabled' },
        activeGrant: activeGrant('advisory_submit_local'),
      }),
    );
    expect(decision.outcome).toBe('revoked');
    expect(decision.write.kind).toBe('revoke_active_grant');
  });

  it('fails closed on malformed persisted state and writes nothing', () => {
    const decision = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local'),
      snapshot({ malformed: true, activeGrant: activeGrant('advisory_submit_local') }),
    );
    expectNoWrite(decision, 'malformed_persisted_state');
    const foreign = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local'),
      snapshot({ activeGrant: activeGrant('advisory_submit_local', USER_B) }),
    );
    expectNoWrite(foreign, 'malformed_persisted_state');
    const illegalAuthority = classifyInstanceAdvisoryAuthorityCommand(
      parsedGrant('advisory_submit_local'),
      snapshot({
        activeGrant: {
          ...activeGrant('advisory_submit_local'),
          authority: 'owner' as InstanceAdvisoryAuthority,
        },
      }),
    );
    expectNoWrite(illegalAuthority, 'malformed_persisted_state');
    const duplicateHistory = classifyInstanceAdvisoryAuthorityCommand(
      parsedRevoke(),
      snapshot({
        revokedGrants: [
          revokedGrant('advisory_submit_local', GRANT_ID),
          revokedGrant('advisory_submit_local', GRANT_ID),
        ],
      }),
    );
    expectNoWrite(duplicateHistory, 'malformed_persisted_state');
    const forged = {
      ...parsedGrant('advisory_submit_local'),
      authority: 'owner' as InstanceAdvisoryAuthority,
    };
    expectNoWrite(classifyInstanceAdvisoryAuthorityCommand(forged, snapshot()), 'invalid_command');
  });
});

describe('instance advisory authorization read', () => {
  it('authorizes only an active user with the exact active grant', () => {
    expect(classifyInstanceAdvisoryAuthorization(facts(), readRequest())).toBe('authorized');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts(),
        readRequest('advisory_approve_for_product_evaluation'),
      ),
    ).toBe('authority_required');
    expect(classifyInstanceAdvisoryAuthorization(facts({ activeGrant: null }), readRequest())).toBe(
      'authority_required',
    );
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ user: { existence: 'absent' }, activeGrant: null }),
        readRequest(),
      ),
    ).toBe('authority_required');
  });

  it('fails closed when facts are not bound to the requested user or the status is unexpected', () => {
    expect(classifyInstanceAdvisoryAuthorization(facts({ userId: USER_B }), readRequest())).toBe(
      'malformed_persisted_state',
    );
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({
          activeGrant: {
            userId: USER_B,
            authority: 'advisory_submit_local',
            issuanceClassification: 'deployment_local_command',
          },
        }),
        readRequest(),
      ),
    ).toBe('malformed_persisted_state');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ user: { existence: 'absent' } }),
        readRequest(),
      ),
    ).toBe('malformed_persisted_state');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ user: { existence: 'present', status: 'pending' as 'active' } }),
        readRequest(),
      ),
    ).toBe('malformed_persisted_state');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({
          activeGrant: {
            userId: USER_A,
            authority: 'owner' as 'advisory_submit_local',
            issuanceClassification: 'deployment_local_command',
          },
        }),
        readRequest(),
      ),
    ).toBe('malformed_persisted_state');
  });

  it('keeps user_inactive internal and collapses it at an external boundary', () => {
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ user: { existence: 'present', status: 'disabled' } }),
        readRequest(),
      ),
    ).toBe('user_inactive');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({
          user: { existence: 'present', status: 'disabled' },
          activeGrant: {
            userId: USER_B,
            authority: 'advisory_submit_local',
            issuanceClassification: 'deployment_local_command',
          },
        }),
        readRequest(),
      ),
    ).toBe('malformed_persisted_state');
    expect(collapseInstanceAdvisoryAuthorizationForExternalBoundary('user_inactive')).toBe(
      'authority_required',
    );
    expect(INSTANCE_ADVISORY_AUTHORIZATION_EXTERNAL_COLLAPSE.user_inactive).toBe(
      'authority_required',
    );
    expect(collapseInstanceAdvisoryAuthorizationForExternalBoundary('authorized')).toBe(
      'authorized',
    );
  });

  it('fails closed when state is malformed or the database is unavailable', () => {
    expect(classifyInstanceAdvisoryAuthorization(facts({ malformed: true }), readRequest())).toBe(
      'malformed_persisted_state',
    );
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ availability: 'database_unavailable' }),
        readRequest(),
      ),
    ).toBe('database_unavailable');
    expect(
      classifyInstanceAdvisoryAuthorization(
        facts({ availability: 'internal_failure' }),
        readRequest(),
      ),
    ).toBe('internal_failure');
  });

  it('rejects organization and permission fields on the read request', () => {
    expect(
      parseInstanceAdvisoryAuthorizationReadRequest({
        schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
        userId: USER_A,
        requiredAuthority: 'advisory_submit_local',
      }).ok,
    ).toBe(true);
    for (const field of ['organizationId', 'membershipId', 'role', 'permission']) {
      expect(
        parseInstanceAdvisoryAuthorizationReadRequest({
          schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
          userId: USER_A,
          requiredAuthority: 'advisory_submit_local',
          [field]: USER_B,
        }).ok,
      ).toBe(false);
    }
  });

  it('requires the later mutation to reload authority inside the same transaction', () => {
    expect(INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS).toMatchObject({
      priorAuthorizationReadOutsideTransactionSufficient: false,
      implemented: true,
    });
    expect(
      INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS.reloadsInsideMutationTransaction,
    ).toEqual([
      'user_existence',
      'user_active_status',
      'active_advisory_grant',
      'exact_required_authority',
    ]);
  });
});

describe('instance advisory audit and nonauthority', () => {
  it('builds one system audit intent for a new grant and none for replay or rollback', () => {
    const command = parsedGrant('advisory_submit_local');
    const granted = classifyInstanceAdvisoryAuthorityCommand(command, snapshot());
    const intent = instanceAdvisoryAuditIntent({
      decision: granted,
      command,
      subjectId: NEW_GRANT_ID,
      authority: 'advisory_submit_local',
    });
    expect(intent).toMatchObject({
      actorType: 'system',
      actorUserId: null,
      organizationId: null,
      membershipId: null,
      action: 'intelligence.instance_advisory_authority_granted',
      subjectType: 'instance_advisory_authority_grant',
      subjectId: NEW_GRANT_ID,
      correlationId: CORRELATION,
      schemaVersion: 1,
      retentionCategory: 'security',
    });
    expect(intent?.payload).toEqual({
      schemaVersion: 1,
      metadata: {
        targetUserId: USER_A,
        authority: 'advisory_submit_local',
        issuanceClassification: 'deployment_local_command',
        correlationId: CORRELATION,
      },
    });
    const replay = classifyInstanceAdvisoryAuthorityCommand(
      command,
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expect(
      instanceAdvisoryAuditIntent({
        decision: replay,
        command,
        subjectId: GRANT_ID,
        authority: 'advisory_submit_local',
      }),
    ).toBeNull();
    expect(INSTANCE_ADVISORY_AUDIT_REPLAY.exactReplayWritesSecondEvent).toBe(false);
    expect(INSTANCE_ADVISORY_AUDIT_REPLAY.differentCorrelationWritesSecondEvent).toBe(false);
    expect(INSTANCE_ADVISORY_AUDIT_REPLAY.rollbackWritesEvent).toBe(false);
    expect(INSTANCE_ADVISORY_AUDIT_REPLAY.uniqueIndexIsNotProductReplay).toBe(true);
  });

  it('uses the governed action names and omits secrets from user-status intent', () => {
    expect(INSTANCE_ADVISORY_AUDIT_ACTIONS).toEqual({
      granted: 'intelligence.instance_advisory_authority_granted',
      revoked: 'intelligence.instance_advisory_authority_revoked',
      userDisabled: 'auth.user_disabled',
      userReenabled: 'auth.user_reenabled',
    });
    const command = parsedUser('disable_user');
    const decision = classifyInstanceAdvisoryAuthorityCommand(command, snapshot());
    const intent = instanceAdvisoryAuditIntent({
      decision,
      command,
      subjectId: USER_A,
      authority: null,
    });
    expect(intent?.action).toBe('auth.user_disabled');
    expect(intent?.subjectType).toBe('user');
    expect(intent?.payload.metadata).toEqual({
      targetUserId: USER_A,
      correlationId: CORRELATION,
    });
    for (const field of INSTANCE_ADVISORY_AUDIT_FORBIDDEN_PAYLOAD_FIELDS) {
      expect(intent?.payload.metadata).not.toHaveProperty(field);
    }
    expect(
      instanceAdvisoryAuditIntent({
        decision,
        command,
        subjectId: USER_A,
        authority: 'advisory_submit_local',
      }),
    ).toBeNull();
    const revoke = parsedRevoke('advisory_submit_local', GRANT_ID);
    const revoked = classifyInstanceAdvisoryAuthorityCommand(
      revoke,
      snapshot({ activeGrant: activeGrant('advisory_submit_local') }),
    );
    expect(
      instanceAdvisoryAuditIntent({
        decision: revoked,
        command: revoke,
        subjectId: GRANT_ID,
        authority: 'advisory_submit_local',
      })?.action,
    ).toBe('intelligence.instance_advisory_authority_revoked');
    expect(
      instanceAdvisoryAuditIntent({
        decision: revoked,
        command: revoke,
        subjectId: USER_A,
        authority: 'advisory_submit_local',
      }),
    ).toBeNull();
    expect(
      instanceAdvisoryAuditIntent({
        decision: revoked,
        command: revoke,
        subjectId: GRANT_ID,
        authority: 'advisory_approve_for_product_evaluation',
      }),
    ).toBeNull();
  });

  it('grants no tenant or downstream product authority', () => {
    for (const value of Object.values(INSTANCE_ADVISORY_TENANT_NONAUTHORITY)) {
      expect(value).toBe(false);
    }
    for (const value of Object.values(INSTANCE_ADVISORY_PRODUCT_NONAUTHORITY)) {
      expect(value).toBe(false);
    }
    expect(INSTANCE_ADVISORY_AUTHORITY_INVARIANTS).toMatchObject({
      persistenceImplemented: true,
      migration26Implemented: true,
      deploymentLocalCommandImplemented: true,
      grantsCanBeCreated: true,
      grantsCanBeRevoked: true,
      advisorySubmissionAvailable: false,
      advisoryApprovalAvailable: false,
      productMatchEvidenceProductionAvailable: false,
      organizationRolesGrantAdvisoryAuthority: false,
      productionComposition: 'deployment_local_command_only',
      nextSession: 'instance_advisory_authority_foundation_pull_request',
      frozenMigrationCount: 26,
      authorityFoundationComplete: true,
      genericInstanceRbac: false,
      capabilityIssuerExposed: false,
    });
    expect(INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS.implemented).toBe(true);
    expect(INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS.migrationImplemented).toBe(true);
    expect(INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS.frozenMigrationCount).toBe(26);
    expect(INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS.exposesTransactionCallback).toBe(false);
    expect(INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY).toMatchObject({
      implemented: true,
      callerSuppliedUserIdIsPrincipal: false,
      permitsExactlyOneStrictOperation: true,
      exposesGenericRepository: false,
      exposesTransactionCallback: false,
      isApprovalCapabilityIssuer: false,
      missingBoundaryOutcome: 'authority_required',
    });
  });

  it('closes the command and authorization outcome lists', () => {
    expect(INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES).toEqual([
      'granted',
      'revoked',
      'user_disabled',
      'user_enabled',
      'already_applied',
      'invalid_command',
      'user_absent',
      'grant_absent',
      'user_inactive',
      'active_grant_conflict',
      'expected_grant_mismatch',
      'active_authority_mismatch',
      'authority_required',
      'immutable_conflict',
      'malformed_persisted_state',
      'concurrency_conflict',
      'transaction_aborted',
      'database_unavailable',
      'internal_failure',
    ]);
    expect(INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES).not.toContain('user_not_found');
    expect(isInstanceAdvisoryAuthorityCommandOutcome('granted')).toBe(true);
    expect(isInstanceAdvisoryAuthorityCommandOutcome(true)).toBe(false);
    expect(INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES).toEqual([
      'authorized',
      'authority_required',
      'user_inactive',
      'malformed_persisted_state',
      'database_unavailable',
      'internal_failure',
    ]);
  });
});
