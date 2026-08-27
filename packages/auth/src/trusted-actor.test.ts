import { describe, expect, it } from 'vitest';

import {
  anonymousAuditActorFields,
  auditActorFields,
  createTrustedActor,
} from './trusted-actor.js';
import { permissionsForRole } from './permissions.js';
import {
  createMembershipRecord,
  createOrganizationRecord,
  createUserRecord,
} from './test-helper.js';

describe('TrustedActor', () => {
  it('omits Organization context when Membership is missing', () => {
    const actor = createTrustedActor({ userId: 'user-1', sessionId: 'session-1' });
    expect(actor).toMatchObject({
      userId: 'user-1',
      sessionId: 'session-1',
      organizationId: null,
      membershipId: null,
      role: null,
      permissions: [],
    });
  });

  it('loads permissions from Membership role and not from a caller-supplied role', () => {
    const user = createUserRecord({});
    const organization = createOrganizationRecord({});
    const membership = createMembershipRecord(organization, user, { role: 'member' });
    const actor = createTrustedActor({
      userId: user.id,
      sessionId: 'session-1',
      organization,
      membership,
    });
    expect(actor.role).toBe('member');
    expect(actor.organizationId).toBe(organization.id);
    expect(actor.membershipId).toBe(membership.id);
    expect(actor.permissions).toEqual(permissionsForRole('member'));
  });

  it('rejects mismatched Membership, revoked Membership, and archived Organization', () => {
    const user = createUserRecord({});
    const other = createUserRecord({ email: 'other@synthetic.patchpilot.test' });
    const organization = createOrganizationRecord({});
    const archived = createOrganizationRecord({ status: 'archived' });
    expect(
      createTrustedActor({
        userId: user.id,
        sessionId: 'session-1',
        organization,
        membership: createMembershipRecord(organization, other),
      }).organizationId,
    ).toBeNull();
    expect(
      createTrustedActor({
        userId: user.id,
        sessionId: 'session-1',
        organization,
        membership: createMembershipRecord(organization, user, { status: 'revoked' }),
      }).organizationId,
    ).toBeNull();
    expect(
      createTrustedActor({
        userId: user.id,
        sessionId: 'session-1',
        organization: archived,
        membership: createMembershipRecord(archived, user),
      }).organizationId,
    ).toBeNull();
  });

  it('follows the audit actor truth table', () => {
    expect(anonymousAuditActorFields).toEqual({ actorType: 'anonymous' });
    expect(anonymousAuditActorFields).not.toHaveProperty('actorUserId');
    expect(anonymousAuditActorFields).not.toHaveProperty('organizationId');
    expect(anonymousAuditActorFields).not.toHaveProperty('actorMembershipId');

    const instance = createTrustedActor({ userId: 'user-1', sessionId: 'session-1' });
    expect(auditActorFields(instance)).toEqual({
      actorType: 'user',
      actorUserId: 'user-1',
    });
    expect(auditActorFields(instance)).not.toHaveProperty('organizationId');
    expect(auditActorFields(instance)).not.toHaveProperty('actorMembershipId');

    const user = createUserRecord({});
    const organization = createOrganizationRecord({});
    const membership = createMembershipRecord(organization, user, { role: 'admin' });
    const tenant = createTrustedActor({
      userId: user.id,
      sessionId: 'session-1',
      organization,
      membership,
    });
    expect(auditActorFields(tenant)).toEqual({
      actorType: 'user',
      actorUserId: user.id,
      organizationId: organization.id,
      actorMembershipId: membership.id,
    });
  });
});
