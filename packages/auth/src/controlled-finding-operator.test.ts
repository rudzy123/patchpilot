/**
 * Trusted session actors against the controlled Finding application boundary.
 * The factories are loaded from the domain build because they are not package
 * barrel exports. This test does not register an HTTP route or call the issuer.
 */

import { describe, expect, it } from 'vitest';

import {
  FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
  type FindingCreationTransactionResult,
  type MembershipRole,
} from '@patchpilot/domain';

import { hasPermission, PERMISSIONS } from './permissions.js';
import {
  createMembershipRecord,
  createOrganizationRecord,
  createUserRecord,
} from './test-helper.js';
import { createTrustedActor, type TrustedActor } from './trusted-actor.js';

const FINDING_ID = 'abababab-abab-4bab-8bab-abababababab';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';
const CORRELATION = '10101010-1010-4101-8101-101010101010';

type CreationApplication = {
  execute(input: {
    readonly actor: TrustedActor;
    readonly request: unknown;
  }): Promise<{ readonly status: string; readonly findingId?: string }>;
};

type InspectionApplication = {
  execute(input: {
    readonly actor: TrustedActor;
    readonly findingId: string;
  }): Promise<{ readonly status: string }>;
};

function trusted(role: MembershipRole) {
  const user = createUserRecord({});
  const organization = createOrganizationRecord({});
  return createTrustedActor({
    userId: user.id,
    sessionId: 'session-1',
    organization,
    membership: createMembershipRecord(organization, user, { role }),
  });
}

function createdResult(): FindingCreationTransactionResult {
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status: 'created',
    findingId: FINDING_ID,
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: true,
    observationAdded: true,
    auditEventAdded: true,
    timestampChanged: false,
  };
}

async function loadApplications(): Promise<{
  createCreation: (dependencies: {
    persistence: {
      apply(input: {
        readonly trustedContext: { readonly organizationId: string };
      }): Promise<FindingCreationTransactionResult>;
    };
    createCorrelationId: () => string;
  }) => CreationApplication;
  createInspection: (dependencies: {
    inspection: {
      load(query: { readonly organizationId: string }): Promise<{ readonly status: 'not_found' }>;
    };
  }) => InspectionApplication;
}> {
  const creationSpecifier = new URL(
    '../../domain/dist/findings/controlled-operator/creation.js',
    import.meta.url,
  ).href;
  const inspectionSpecifier = new URL(
    '../../domain/dist/findings/controlled-operator/inspection.js',
    import.meta.url,
  ).href;
  const creationModule = (await import(creationSpecifier)) as {
    createControlledFindingCreationApplication: (dependencies: {
      persistence: {
        apply(input: {
          readonly trustedContext: { readonly organizationId: string };
        }): Promise<FindingCreationTransactionResult>;
      };
      createCorrelationId: () => string;
    }) => CreationApplication;
  };
  const inspectionModule = (await import(inspectionSpecifier)) as {
    createControlledFindingInspectionApplication: (dependencies: {
      inspection: {
        load(query: { readonly organizationId: string }): Promise<{ readonly status: 'not_found' }>;
      };
    }) => InspectionApplication;
  };
  return {
    createCreation: creationModule.createControlledFindingCreationApplication,
    createInspection: inspectionModule.createControlledFindingInspectionApplication,
  };
}

describe('trusted actors and controlled finding operator permissions', () => {
  it('follows the accepted role mapping through the session actor', async () => {
    expect(hasPermission('owner', PERMISSIONS.findingCreateControlled)).toBe(true);
    expect(hasPermission('admin', PERMISSIONS.findingCreateControlled)).toBe(false);
    expect(hasPermission('admin', PERMISSIONS.findingInspect)).toBe(true);
    expect(hasPermission('member', PERMISSIONS.findingTriage)).toBe(true);
    expect(hasPermission('member', PERMISSIONS.findingCreateControlled)).toBe(false);
    expect(hasPermission('viewer', PERMISSIONS.findingRead)).toBe(true);
    expect(hasPermission('viewer', PERMISSIONS.findingInspect)).toBe(false);

    const { createCreation, createInspection } = await loadApplications();
    const creationCalls: string[] = [];
    const creation = createCreation({
      persistence: {
        async apply(input) {
          creationCalls.push(input.trustedContext.organizationId);
          return createdResult();
        },
      },
      createCorrelationId: () => CORRELATION,
    });
    const inspectionCalls: string[] = [];
    const inspection = createInspection({
      inspection: {
        async load(query) {
          inspectionCalls.push(query.organizationId);
          return { status: 'not_found' };
        },
      },
    });
    const request = {
      assetId: ASSET,
      componentId: COMPONENT,
      vulnerabilityId: VULNERABILITY,
      expectedSbomIngestionId: INGESTION,
      expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    };
    const owner = trusted('owner');
    const admin = trusted('admin');
    const member = {
      ...trusted('member'),
      permissions: [PERMISSIONS.findingCreateControlled, PERMISSIONS.findingInspect],
    };
    const viewer = trusted('viewer');

    expect(await creation.execute({ actor: owner, request })).toEqual({
      status: 'created',
      findingId: FINDING_ID,
    });
    expect(creationCalls).toEqual([owner.organizationId]);
    expect(await creation.execute({ actor: admin, request })).toEqual({
      status: 'authority_required',
    });
    expect(await creation.execute({ actor: member, request })).toEqual({
      status: 'authority_required',
    });
    expect(await creation.execute({ actor: viewer, request })).toEqual({
      status: 'authority_required',
    });
    expect(creationCalls).toHaveLength(1);

    expect((await inspection.execute({ actor: admin, findingId: FINDING_ID })).status).toBe(
      'not_found',
    );
    expect((await inspection.execute({ actor: owner, findingId: FINDING_ID })).status).toBe(
      'not_found',
    );
    expect(await inspection.execute({ actor: member, findingId: FINDING_ID })).toEqual({
      status: 'authority_required',
    });
    expect(await inspection.execute({ actor: viewer, findingId: FINDING_ID })).toEqual({
      status: 'authority_required',
    });
    expect(inspectionCalls).toEqual([admin.organizationId, owner.organizationId]);

    const revokedUser = createUserRecord({});
    const revokedOrganization = createOrganizationRecord({});
    const revoked = createTrustedActor({
      userId: revokedUser.id,
      sessionId: 'session-revoked',
      organization: revokedOrganization,
      membership: createMembershipRecord(revokedOrganization, revokedUser, {
        role: 'owner',
        status: 'revoked',
      }),
    });
    const before = creationCalls.length;
    expect(await creation.execute({ actor: revoked, request })).toEqual({
      status: 'authority_required',
    });
    expect(await inspection.execute({ actor: revoked, findingId: FINDING_ID })).toEqual({
      status: 'authority_required',
    });
    expect(creationCalls).toHaveLength(before);
    expect(inspectionCalls).toEqual([admin.organizationId, owner.organizationId]);
  });
});
