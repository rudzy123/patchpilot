/**
 * Permission and application boundaries for controlled Finding operations.
 * These tests do not open a database, import the issuer, or register a route.
 */

import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '../../lifecycle.js';
import {
  FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
  type FindingCreationTransactionResult,
} from '../controlled-creation/eligibility.js';
import { FINDING_CREATION_INVARIANTS } from '../controlled-creation/policy.js';
import { openFindingInspection } from '../controlled-inspection/service.js';
import type {
  FindingInspectionEvidenceBundle,
  FindingInspectionLinkRecord,
  FindingInspectionLoadQuery,
  FindingInspectionPort,
} from '../controlled-inspection/port.js';
import {
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from '../controlled-inspection/policy.js';
import type { ControlledFindingOperatorActor } from './actor.js';
import {
  createControlledFindingCreationApplication,
  type ControlledFindingCreationPersistencePort,
} from './creation.js';
import { createControlledFindingInspectionApplication } from './inspection.js';
import {
  CONTROLLED_FINDING_OPERATOR_NEXT_REVIEW,
  CONTROLLED_FINDING_OPERATOR_PRODUCTION_REGISTRATION,
  controlledFindingOperatorPermissionsForRole,
  FINDING_CREATE_CONTROLLED_PERMISSION,
  FINDING_INSPECT_PERMISSION,
} from './permissions.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const FOREIGN_ORG = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';
const CORRELATION_A = '10101010-1010-4101-8101-101010101010';
const CORRELATION_B = '13131313-1313-4131-8131-131313131313';
const FINDING_ID = 'abababab-abab-4bab-8bab-abababababab';
const OBSERVATION_ID = '55555555-5555-4555-8555-555555555555';

const ROLES: readonly MembershipRole[] = ['viewer', 'member', 'admin', 'owner'];

function actor(
  role: MembershipRole | null,
  extras: Record<string, unknown> = {},
): ControlledFindingOperatorActor {
  return {
    userId: ACTOR,
    sessionId: 'session-1',
    organizationId: ORG,
    membershipId: MEMBERSHIP,
    role,
    ...extras,
  };
}

function request(extras: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    expectedSbomIngestionId: INGESTION,
    expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    ...extras,
  };
}

function createdResult(findingId: string): FindingCreationTransactionResult {
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status: 'created',
    findingId,
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: true,
    observationAdded: true,
    auditEventAdded: true,
    timestampChanged: false,
  };
}

function replayResult(findingId: string): FindingCreationTransactionResult {
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status: 'already_applied',
    findingId,
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: false,
    observationAdded: false,
    auditEventAdded: false,
    timestampChanged: false,
  };
}

function notFoundResult(): FindingCreationTransactionResult {
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status: 'not_found',
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: false,
    observationAdded: false,
    auditEventAdded: false,
    timestampChanged: false,
  };
}

function recordingPersistence(
  respond: (
    input: Parameters<ControlledFindingCreationPersistencePort['apply']>[0],
    index: number,
  ) => FindingCreationTransactionResult | Promise<FindingCreationTransactionResult>,
) {
  const calls: Array<Parameters<ControlledFindingCreationPersistencePort['apply']>[0]> = [];
  const persistence: ControlledFindingCreationPersistencePort = {
    async apply(input) {
      calls.push(input);
      return respond(input, calls.length - 1);
    },
  };
  return { calls, persistence };
}

describe('controlled finding operator permissions', () => {
  it('gives owner creation and inspection, admin inspection only, and neither to member or viewer', () => {
    expect(FINDING_CREATE_CONTROLLED_PERMISSION).toBe('finding:create_controlled');
    expect(FINDING_INSPECT_PERMISSION).toBe('finding:inspect');
    expect(FINDING_CREATE_CONTROLLED_PERMISSION).not.toBe('finding:triage');
    expect(FINDING_INSPECT_PERMISSION).not.toBe('finding:read');
    expect(controlledFindingOperatorPermissionsForRole('owner')).toEqual([
      FINDING_CREATE_CONTROLLED_PERMISSION,
      FINDING_INSPECT_PERMISSION,
    ]);
    expect(controlledFindingOperatorPermissionsForRole('admin')).toEqual([
      FINDING_INSPECT_PERMISSION,
    ]);
    expect(controlledFindingOperatorPermissionsForRole('member')).toEqual([]);
    expect(controlledFindingOperatorPermissionsForRole('viewer')).toEqual([]);
    for (const role of ROLES) {
      const grants = controlledFindingOperatorPermissionsForRole(role);
      expect(grants.includes(FINDING_CREATE_CONTROLLED_PERMISSION)).toBe(role === 'owner');
      expect(grants.includes(FINDING_INSPECT_PERMISSION)).toBe(
        role === 'owner' || role === 'admin',
      );
    }
  });

  it('keeps the operator application production registration absent', () => {
    expect(CONTROLLED_FINDING_OPERATOR_PRODUCTION_REGISTRATION).toBe('absent');
    expect(CONTROLLED_FINDING_OPERATOR_NEXT_REVIEW).toBe(
      'controlled_finding_operator_api_session_2',
    );
    expect(FINDING_CREATION_INVARIANTS.issuerProductionCaller).toBe(
      'controlled_finding_creation_application',
    );
    expect(FINDING_CREATION_INVARIANTS.issuerPackageExport).toBe('absent');
    expect(FINDING_CREATION_INVARIANTS.correlationIsReplayIdentity).toBe(false);
  });
});

describe('controlled finding creation application', () => {
  it('does not call the correlation source or the persistence port during construction', () => {
    let calls = 0;
    const application = createControlledFindingCreationApplication({
      persistence: {
        async apply() {
          calls += 1;
          return createdResult(FINDING_ID);
        },
      },
      createCorrelationId() {
        calls += 1;
        return CORRELATION_A;
      },
    });
    expect(calls).toBe(0);
    expect(application.execute).toEqual(expect.any(Function));
  });

  it('lets an owner reach the persistence port and returns only the Finding id', async () => {
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId: () => CORRELATION_A,
    });
    const result = await application.execute({
      actor: actor('owner', {
        permissions: ['finding:read'],
      }),
      request: request(),
    });
    expect(result).toEqual({ status: 'created', findingId: FINDING_ID });
    expect(recorded.calls).toHaveLength(1);
    const call = recorded.calls[0];
    expect(call?.trustedContext).toEqual({
      schemaVersion: 'finding_creation_trusted_context_v1',
      organizationId: ORG,
      actorId: ACTOR,
      membershipId: MEMBERSHIP,
      membershipStatus: 'active',
    });
    expect(call?.command.correlationId).toBe(CORRELATION_A);
    expect(call?.command.expectedAssetId).toBe(ASSET);
    expect(call?.command.expectedProductMatchEvidenceIds).toEqual([EVIDENCE_A, EVIDENCE_B]);
    expect(Object.keys(call?.command ?? {})).not.toContain('organizationId');
    expect(JSON.stringify(result)).not.toContain(EVIDENCE_A);
    expect(JSON.stringify(result)).not.toContain('reusableAuthority');
    expect(JSON.stringify(result)).not.toContain(MEMBERSHIP);
  });

  it('returns the Finding id for an exact replay without treating correlation as identity', async () => {
    const correlations = [CORRELATION_A, CORRELATION_B];
    let issued = 0;
    const recorded = recordingPersistence((_input, index) =>
      index === 0 ? createdResult(FINDING_ID) : replayResult(FINDING_ID),
    );
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId() {
        const correlationId = correlations[issued];
        issued += 1;
        if (correlationId === undefined) {
          throw new Error('unexpected correlation');
        }
        return correlationId;
      },
    });
    const first = await application.execute({ actor: actor('owner'), request: request() });
    const second = await application.execute({ actor: actor('owner'), request: request() });
    expect(first).toEqual({ status: 'created', findingId: FINDING_ID });
    expect(second).toEqual({ status: 'already_applied', findingId: FINDING_ID });
    expect(recorded.calls).toHaveLength(2);
    expect(recorded.calls[0]?.command.correlationId).toBe(CORRELATION_A);
    expect(recorded.calls[1]?.command.correlationId).toBe(CORRELATION_B);
    expect(recorded.calls[0]?.command.expectedProductMatchEvidenceIds).toEqual(
      recorded.calls[1]?.command.expectedProductMatchEvidenceIds,
    );
    expect(recorded.calls[0]?.command.correlationId).not.toBe(
      recorded.calls[1]?.command.correlationId,
    );
  });

  it('rejects admin, member, and viewer creation before correlation or persistence', async () => {
    for (const role of ['admin', 'member', 'viewer'] as const) {
      let correlationCalls = 0;
      const recorded = recordingPersistence(() => createdResult(FINDING_ID));
      const application = createControlledFindingCreationApplication({
        persistence: recorded.persistence,
        createCorrelationId() {
          correlationCalls += 1;
          return CORRELATION_A;
        },
      });
      const result = await application.execute({
        actor: actor(role, {
          permissions: [
            'finding:create_controlled',
            'finding:triage',
            'finding:read',
            'finding:inspect',
          ],
        }),
        request: request({ organizationId: FOREIGN_ORG, role: 'owner' }),
      });
      expect(result, role).toEqual({ status: 'authority_required' });
      expect(correlationCalls, role).toBe(0);
      expect(recorded.calls, role).toEqual([]);
      expect(JSON.stringify(result)).not.toContain(FINDING_ID);
    }
  });

  it('rejects membership without the creation permission and a null organization', async () => {
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId: () => CORRELATION_A,
    });
    const member = await application.execute({ actor: actor('member'), request: request() });
    const unscoped = await application.execute({
      actor: actor('owner', { organizationId: null, membershipId: null }),
      request: request(),
    });
    expect(member).toEqual({ status: 'authority_required' });
    expect(unscoped).toEqual({ status: 'authority_required' });
    expect(recorded.calls).toEqual([]);
  });

  it('rejects a request organization and keeps the trusted organization', async () => {
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    let correlationCalls = 0;
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId() {
        correlationCalls += 1;
        return CORRELATION_A;
      },
    });
    const injected = await application.execute({
      actor: actor('owner'),
      request: request({ organizationId: FOREIGN_ORG }),
    });
    expect(injected).toEqual({ status: 'invalid_command' });
    expect(correlationCalls).toBe(0);
    expect(recorded.calls).toEqual([]);
    const accepted = await application.execute({ actor: actor('owner'), request: request() });
    expect(accepted).toEqual({ status: 'created', findingId: FINDING_ID });
    expect(recorded.calls[0]?.trustedContext.organizationId).toBe(ORG);
    expect(recorded.calls[0]?.trustedContext.organizationId).not.toBe(FOREIGN_ORG);
  });

  it('rejects ambient role claims and prohibited creation fields before issuance', async () => {
    let correlationCalls = 0;
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId() {
        correlationCalls += 1;
        return CORRELATION_A;
      },
    });
    const ambient = await application.execute({
      actor: actor('owner'),
      request: request({ role: 'owner', permissions: ['finding:create_controlled'] }),
    });
    const prohibited = await application.execute({
      actor: actor('owner'),
      request: request({ risk: 'high', priority: 1 }),
    });
    expect(ambient).toEqual({ status: 'authority_rejected' });
    expect(prohibited).toEqual({ status: 'invalid_command' });
    expect(correlationCalls).toBe(0);
    expect(recorded.calls).toEqual([]);
  });

  it('omits the Finding id and authority details from failure results', async () => {
    const recorded = recordingPersistence(async () => {
      return {
        ...notFoundResult(),
        findingId: FINDING_ID,
        reason: 'membership_inactive',
        authorization: { reusableAuthority: false },
        sql: 'select 1',
      } as unknown as FindingCreationTransactionResult;
    });
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId: () => CORRELATION_A,
    });
    const result = await application.execute({ actor: actor('owner'), request: request() });
    expect(result).toEqual({ status: 'not_found' });
    expect(result).not.toHaveProperty('findingId');
    expect(JSON.stringify(result)).not.toContain(FINDING_ID);
    expect(JSON.stringify(result)).not.toContain(EVIDENCE_A);
    expect(JSON.stringify(result)).not.toContain('membership_inactive');
    expect(JSON.stringify(result)).not.toContain('select 1');
  });

  it('rejects an explicit inactive membership before issuance or persistence', async () => {
    for (const membershipStatus of ['revoked', 'inactive', null, 'Active'] as const) {
      let correlationCalls = 0;
      const recorded = recordingPersistence(() => createdResult(FINDING_ID));
      const application = createControlledFindingCreationApplication({
        persistence: recorded.persistence,
        createCorrelationId() {
          correlationCalls += 1;
          return CORRELATION_A;
        },
      });
      const result = await application.execute({
        actor: actor('owner', { membershipStatus, permissions: ['finding:create_controlled'] }),
        request: request(),
      });
      expect(result, String(membershipStatus)).toEqual({ status: 'authority_required' });
      expect(correlationCalls, String(membershipStatus)).toBe(0);
      expect(recorded.calls, String(membershipStatus)).toEqual([]);
      expect(JSON.stringify(result)).not.toContain(FINDING_ID);
      expect(JSON.stringify(result)).not.toContain('revoked');
      expect(JSON.stringify(result)).not.toContain(MEMBERSHIP);
    }
  });

  it('rejects caller-selected membership, correlation, and idempotency fields before issuance', async () => {
    let correlationCalls = 0;
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    const application = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId() {
        correlationCalls += 1;
        return CORRELATION_A;
      },
    });
    const cases = [
      request({ membershipId: MEMBERSHIP }),
      request({ correlationId: CORRELATION_B }),
      request({ idempotencyKey: 'same-key' }),
      request({ administrator: true }),
      request({ expectedProductMatchEvidenceIds: [EVIDENCE_B, EVIDENCE_A] }),
      request({ expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_A] }),
      request({ expectedProductMatchEvidenceIds: [] }),
    ];
    for (const body of cases) {
      const result = await application.execute({ actor: actor('owner'), request: body });
      expect(result.status === 'invalid_command' || result.status === 'authority_rejected').toBe(
        true,
      );
      expect(result).not.toHaveProperty('findingId');
    }
    expect(correlationCalls).toBe(0);
    expect(recorded.calls).toEqual([]);
  });

  it('does not promote a partial or contradictory persistence result to created or replay', async () => {
    const partial = recordingPersistence(
      () =>
        ({
          status: 'already_applied',
          findingId: FINDING_ID,
        }) as unknown as FindingCreationTransactionResult,
    );
    const contradictory = recordingPersistence(
      () =>
        ({
          ...replayResult(FINDING_ID),
          writesPerformed: true,
          authorization: { reusableAuthority: false },
        }) as unknown as FindingCreationTransactionResult,
    );
    const unique = recordingPersistence(
      () =>
        ({
          status: '23505',
          findingId: FINDING_ID,
          code: 'P2002',
        }) as unknown as FindingCreationTransactionResult,
    );
    const applications = [partial, contradictory, unique].map((recorded) =>
      createControlledFindingCreationApplication({
        persistence: recorded.persistence,
        createCorrelationId: () => CORRELATION_A,
      }),
    );
    for (const application of applications) {
      const result = await application.execute({ actor: actor('owner'), request: request() });
      expect(result).toEqual({ status: 'internal_failure' });
      expect(JSON.stringify(result)).not.toContain(FINDING_ID);
      expect(JSON.stringify(result)).not.toContain('reusableAuthority');
      expect(JSON.stringify(result)).not.toContain('P2002');
    }
  });

  it('fails closed when a success result has no Finding id or the port throws', async () => {
    const missing = recordingPersistence(
      () =>
        ({
          ...createdResult(FINDING_ID),
          findingId: 'not-a-finding',
        }) as FindingCreationTransactionResult,
    );
    const thrown = recordingPersistence(() => {
      throw new Error('database constraint finding_pkey');
    });
    const missingApplication = createControlledFindingCreationApplication({
      persistence: missing.persistence,
      createCorrelationId: () => CORRELATION_A,
    });
    const thrownApplication = createControlledFindingCreationApplication({
      persistence: thrown.persistence,
      createCorrelationId: () => CORRELATION_B,
    });
    expect(await missingApplication.execute({ actor: actor('owner'), request: request() })).toEqual(
      { status: 'internal_failure' },
    );
    expect(await thrownApplication.execute({ actor: actor('owner'), request: request() })).toEqual({
      status: 'internal_failure',
    });
    expect(thrown.calls).toHaveLength(1);
  });
});

describe('controlled finding inspection application', () => {
  it('does not load a Finding during construction', () => {
    let calls = 0;
    const application = createControlledFindingInspectionApplication({
      inspection: {
        async load() {
          calls += 1;
          return { status: 'not_found' };
        },
      },
    });
    expect(calls).toBe(0);
    expect(application.execute).toEqual(expect.any(Function));
  });

  it('lets an admin inspect through the safe service and returns that result', async () => {
    const loads: FindingInspectionLoadQuery[] = [];
    const inspection: FindingInspectionPort = {
      async load(query) {
        loads.push(query);
        return { status: 'ready', bundle: bundle(['1.2.0']) };
      },
    };
    const application = createControlledFindingInspectionApplication({ inspection });
    const result = await application.execute({
      actor: actor('admin', { permissions: ['finding:read'] }),
      findingId: FINDING_ID,
    });
    const direct = await openFindingInspection({
      async load() {
        return { status: 'ready', bundle: bundle(['1.2.0']) };
      },
    }).inspect({
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: ORG,
      },
      findingId: FINDING_ID,
    });
    expect(loads).toEqual([{ organizationId: ORG, findingId: FINDING_ID }]);
    expect(result).toEqual(direct);
    expect(result).toMatchObject({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'found',
    });
    expect(JSON.stringify(result)).not.toContain(ACTOR);
    expect(JSON.stringify(result)).not.toContain(MEMBERSHIP);
    expect(JSON.stringify(result)).not.toContain('reusableAuthority');
  });

  it('uses the actor organization and ignores a caller-supplied organization', async () => {
    const loads: FindingInspectionLoadQuery[] = [];
    const application = createControlledFindingInspectionApplication({
      inspection: {
        async load(query) {
          loads.push(query);
          return { status: 'not_found' };
        },
      },
    });
    const input = {
      actor: actor('owner'),
      findingId: FINDING_ID,
      organizationId: FOREIGN_ORG,
    };
    const result = await application.execute(input);
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(loads).toEqual([{ organizationId: ORG, findingId: FINDING_ID }]);
  });

  it('rejects inactive membership, forged actors, and administrator labels before a load', async () => {
    const loads: FindingInspectionLoadQuery[] = [];
    const application = createControlledFindingInspectionApplication({
      inspection: {
        async load(query) {
          loads.push(query);
          return { status: 'not_found', findingId: FINDING_ID } as unknown as {
            status: 'not_found';
          };
        },
      },
    });
    const revoked = await application.execute({
      actor: actor('admin', { membershipStatus: 'revoked', administrator: true }),
      findingId: FINDING_ID,
    });
    const proxy = new Proxy(actor('owner'), {});
    const forged = await application.execute({
      actor: proxy as unknown as ControlledFindingOperatorActor,
      findingId: FINDING_ID,
    });
    class StructuralActor {}
    const structural = Object.assign(new StructuralActor(), actor('owner'));
    const plain = await application.execute({
      actor: structural as unknown as ControlledFindingOperatorActor,
      findingId: FINDING_ID,
    });
    const labeled = await application.execute({
      actor: actor('member', {
        administrator: true,
        isAdmin: true,
        permissions: ['finding:read', 'finding:triage', 'organization:manage', 'asset:manage'],
      }),
      findingId: FINDING_ID,
    });
    expect(revoked).toEqual({ status: 'authority_required' });
    expect(forged).toEqual({ status: 'authority_required' });
    expect(plain).toEqual({ status: 'authority_required' });
    expect(labeled).toEqual({ status: 'authority_required' });
    expect(loads).toEqual([]);
    for (const result of [revoked, forged, plain, labeled]) {
      expect(JSON.stringify(result)).not.toContain(FINDING_ID);
      expect(result).not.toHaveProperty('findingId');
    }
  });

  it('drops a Finding id attached to an inspection load failure', async () => {
    const application = createControlledFindingInspectionApplication({
      inspection: {
        async load() {
          return { status: 'not_found', findingId: FINDING_ID } as unknown as {
            status: 'not_found';
          };
        },
      },
    });
    const result = await application.execute({
      actor: actor('admin'),
      findingId: FINDING_ID,
    });
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(result).not.toHaveProperty('findingId');
    expect(JSON.stringify(result)).not.toContain(FINDING_ID);
  });

  it('rejects member and viewer inspection before the service, including finding:read', async () => {
    for (const role of ['member', 'viewer'] as const) {
      const loads: FindingInspectionLoadQuery[] = [];
      const application = createControlledFindingInspectionApplication({
        inspection: {
          async load(query) {
            loads.push(query);
            return { status: 'not_found' };
          },
        },
      });
      const result = await application.execute({
        actor: actor(role, {
          permissions: [
            'finding:read',
            'finding:inspect',
            'finding:triage',
            'finding:create_controlled',
          ],
        }),
        findingId: { findingId: FINDING_ID, organizationId: FOREIGN_ORG },
      });
      expect(result, role).toEqual({ status: 'authority_required' });
      expect(loads, role).toEqual([]);
      expect(result).not.toHaveProperty('findingId');
      expect(result).not.toHaveProperty('projection');
    }
  });

  it('does not grant inspection from creation permission alone or creation from inspection', async () => {
    const loads: FindingInspectionLoadQuery[] = [];
    const inspection = createControlledFindingInspectionApplication({
      inspection: {
        async load(query) {
          loads.push(query);
          return { status: 'not_found' };
        },
      },
    });
    const recorded = recordingPersistence(() => createdResult(FINDING_ID));
    let correlationCalls = 0;
    const creation = createControlledFindingCreationApplication({
      persistence: recorded.persistence,
      createCorrelationId() {
        correlationCalls += 1;
        return CORRELATION_A;
      },
    });
    const adminInspection = await inspection.execute({
      actor: actor('admin'),
      findingId: FINDING_ID,
    });
    const adminCreation = await creation.execute({ actor: actor('admin'), request: request() });
    expect(adminInspection).toMatchObject({ status: 'not_found' });
    expect(loads).toEqual([{ organizationId: ORG, findingId: FINDING_ID }]);
    expect(adminCreation).toEqual({ status: 'authority_required' });
    expect(correlationCalls).toBe(0);
    expect(recorded.calls).toEqual([]);
  });
});

function link(index: number, version: string): FindingInspectionLinkRecord {
  const suffix = index.toString(16).padStart(12, '0');
  return {
    evidenceId: `77777777-7777-4777-8777-${suffix}`,
    findingObservationId: OBSERVATION_ID,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: INGESTION,
    componentOccurrenceId: `88888888-8888-4888-8888-${suffix}`,
    linkOutcome: 'affected',
    evidencePresent: true,
    evidenceTargetAligned: true,
    evidenceOutcome: 'affected',
    productOrigin: 'maintainer_reviewed_advisory',
    evaluatorId: 'osv_first_ecosystem_affected_version_evaluator_v1',
    evaluatorVersion: 'session_14_batch_2_in_memory',
    matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
    matchingPolicyVersion: 'osv_first_ecosystem_matching_architecture_v1',
    productEvidencePolicyId: 'product_match_evaluation_policy_v1',
    productEvidencePolicyVersion: 1,
    evidenceSchemaVersion: 'product_match_evaluation_evidence_v1',
    findingCreation: 'unavailable',
    suppressionAuthority: false,
    rawObservedVersion: version,
    occurrencePresent: true,
    occurrenceVersion: version,
    occurrenceVersionKnown: true,
    occurrenceAssetId: ASSET,
    occurrenceComponentId: COMPONENT,
    occurrenceIngestionId: INGESTION,
    revisionPresent: true,
    withdrawal: 'not_withdrawn',
    quarantine: 'not_quarantined',
    hasSuccessor: false,
    approvalPresent: true,
    approvalPurpose: 'approve_maintainer_reviewed_advisory_for_product_evaluation',
    approvalRevisionMatches: true,
    approvalVulnerabilityMatches: true,
    bindingPresent: true,
    bindingReviewed: true,
    normalizationVersion: '2',
    ingestionState: 'completed',
    ingestionPresent: true,
    explanationCodes: ['affected_within_introduced_fixed_range'],
  };
}

function bundle(versions: readonly string[]): FindingInspectionEvidenceBundle {
  const links = versions.map((version, index) => link(index + 1, version));
  return {
    findingId: FINDING_ID,
    state: 'open',
    createdAt: '2026-10-06T16:00:00.000Z',
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    componentOccurrenceId: null,
    resolvedAt: null,
    reopenedAt: null,
    assignedMembershipId: null,
    assignedTeamId: null,
    dueAt: null,
    currentRiskCalculationId: null,
    version: 1,
    assetPresent: true,
    assetDisplayName: 'asset <untrusted>',
    assetCurrentIngestionId: INGESTION,
    componentPresent: true,
    componentEcosystem: 'npm',
    componentNamespace: null,
    componentName: 'widget <untrusted>',
    vulnerabilityPresent: true,
    vulnerabilityPublicId: 'REVIEWED-NPM-1',
    remediationTaskCount: 0,
    riskAcceptanceCount: 0,
    riskCalculationCount: 0,
    genericEvidenceCount: 0,
    creationIngestionOccurrenceCount: links.length,
    otherOccurrenceCount: 0,
    observations: [
      {
        id: OBSERVATION_ID,
        sbomIngestionId: INGESTION,
        occurrenceId: null,
        result: 'present',
        method: 'controlled_finding_creation',
        transitionClassification: 'initial_creation',
        creationPurpose: 'create_finding_from_product_match_evidence',
        creationPolicyId: 'finding_creation_policy_v1',
        creationPolicyVersion: 1,
        affectedEvidenceCount: links.length,
        replayAgrees: true,
        evidenceRecordAgrees: true,
      },
    ],
    links,
  };
}
