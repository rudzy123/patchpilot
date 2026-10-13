/**
 * Latest-observation application service.
 * These tests do not open a database, compose a route, or write a Finding.
 */

import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '../../lifecycle.js';
import { FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS } from '../controlled-inspection/latest-observation-selection.js';
import type { ControlledFindingOperatorActor } from '../controlled-operator/actor.js';
import { INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION } from './command.js';
import {
  CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS,
  type ControlledFindingLatestObservationReadDiagnostic,
  type ControlledFindingLatestObservationReadOutcome,
  type ControlledFindingLatestObservationReadPort,
  type ControlledFindingLatestObservationReadQuery,
} from './port.js';
import { createControlledFindingLatestObservationApplication } from './service.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const OTHER_ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FOREIGN_ORG = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const FOREIGN_FINDING = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const EVIDENCE = '77777777-7777-4777-8777-777777777777';
const OCCURRENCE = '88888888-8888-4888-8888-888888888888';
const SUPPORT = '99999999-9999-4999-8999-999999999999';
const OBSERVED = '2026-10-09T16:00:00.000001Z';
const SECRET = 'postgres://user:secret@database.internal/patchpilot';

const SUBSTITUTE_PERMISSIONS = [
  'finding:create_controlled',
  'finding:discover_controlled',
  'finding:triage',
  'finding:read',
  'asset:read',
  'asset:manage',
] as const;

type ReadCall = ControlledFindingLatestObservationReadQuery;

function actor(
  role: MembershipRole | null,
  extras: Record<string, unknown> = {},
  organizationId: string | null = ORG,
): ControlledFindingOperatorActor {
  return {
    userId: ACTOR,
    sessionId: 'session-1',
    organizationId,
    membershipId: MEMBERSHIP,
    role,
    ...extras,
  };
}

function command(findingId: unknown = FINDING, extras: Record<string, unknown> = {}) {
  return {
    schemaVersion: INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
    findingId,
    ...extras,
  };
}

function occurrenceEvidence(
  counts: Partial<{
    affected: number;
    unaffected: number;
    unknown: number;
    unknownVersion: number;
    versions: readonly string[];
  }> = {},
) {
  return {
    kind: 'occurrence_support' as const,
    affectedSupportCount: counts.affected ?? 1,
    unaffectedSupportCount: counts.unaffected ?? 0,
    unknownSupportCount: counts.unknown ?? 0,
    unknownVersionSupportCount: counts.unknownVersion ?? 0,
    knownVersions: counts.versions ?? ['1.2.0'],
  };
}

function projection(input: {
  readonly observationSource: 'creation' | 'latest_repeated';
  readonly aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent';
  readonly mappedResult: 'present' | 'absent' | 'inconclusive';
  readonly evidence: Record<string, unknown>;
  readonly findingId?: string;
}) {
  return {
    schemaVersion: 'finding_latest_observation_projection_v1' as const,
    findingId: input.findingId ?? FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    observationSource: input.observationSource,
    observedAt: OBSERVED,
    aggregate: input.aggregate,
    mappedResult: input.mappedResult,
    evidence: input.evidence,
  };
}

function creationProjection() {
  return projection({
    observationSource: 'creation',
    aggregate: 'affected',
    mappedResult: 'present',
    evidence: occurrenceEvidence(),
  });
}

function repeatedProjection(
  aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent',
  mappedResult: 'present' | 'absent' | 'inconclusive',
  evidence: Record<string, unknown>,
) {
  return projection({
    observationSource: 'latest_repeated',
    aggregate,
    mappedResult,
    evidence,
  });
}

function outcome(
  diagnostic: ControlledFindingLatestObservationReadDiagnostic,
  safe: unknown,
): ControlledFindingLatestObservationReadOutcome {
  return { safe, diagnostic } as ControlledFindingLatestObservationReadOutcome;
}

function foundSafe(body: ReturnType<typeof projection>) {
  return {
    schemaVersion: 'finding_latest_observation_external_result_v1' as const,
    status: 'found' as const,
    projection: body,
  };
}

function terminalSafe(status: 'not_found' | 'unavailable') {
  return {
    schemaVersion: 'finding_latest_observation_external_result_v1' as const,
    status,
  };
}

function portReturning(result: ControlledFindingLatestObservationReadOutcome | (() => never)): {
  readonly port: ControlledFindingLatestObservationReadPort;
  readonly calls: ReadCall[];
} {
  const calls: ReadCall[] = [];
  return {
    calls,
    port: {
      async read(query) {
        calls.push(query);
        if (typeof result === 'function') {
          return result();
        }
        return result;
      },
    },
  };
}

function applicationFor(
  result: ControlledFindingLatestObservationReadOutcome | (() => never) = outcome(
    'not_found',
    terminalSafe('not_found'),
  ),
) {
  const recorded = portReturning(result);
  return {
    ...recorded,
    application: createControlledFindingLatestObservationApplication({ read: recorded.port }),
  };
}

describe('controlled finding latest-observation application', () => {
  it('does not read during construction or import', () => {
    let calls = 0;
    const application = createControlledFindingLatestObservationApplication({
      read: {
        async read() {
          calls += 1;
          return outcome('not_found', terminalSafe('not_found'));
        },
      },
    });
    expect(calls).toBe(0);
    expect(application.execute).toEqual(expect.any(Function));
  });

  it.each(['owner', 'admin'] as const)(
    'lets a %s with finding:inspect read through the actor organization',
    async (role) => {
      const recorded = applicationFor(outcome('found', foundSafe(creationProjection())));
      const result = await recorded.application.execute({
        actor: actor(role, { permissions: ['finding:read'] }),
        command: command(),
      });
      expect(recorded.calls).toEqual([{ organizationId: ORG, findingId: FINDING }]);
      expect(result).toMatchObject({
        schemaVersion: 'finding_latest_observation_external_result_v1',
        status: 'found',
        projection: { observationSource: 'creation', aggregate: 'affected' },
      });
    },
  );

  it('uses a second actor organization without retrying under another organization', async () => {
    const recorded = applicationFor(outcome('not_found', terminalSafe('not_found')));
    await recorded.application.execute({
      actor: actor('admin', {}, OTHER_ORG),
      command: command(),
    });
    expect(recorded.calls).toEqual([{ organizationId: OTHER_ORG, findingId: FINDING }]);
  });

  it.each(['member', 'viewer'] as const)('rejects a %s before the read port', async (role) => {
    const recorded = applicationFor();
    const result = await recorded.application.execute({
      actor: actor(role, { permissions: ['finding:inspect', ...SUBSTITUTE_PERMISSIONS] }),
      command: command(),
    });
    expect(result).toEqual({ status: 'authority_required' });
    expect(recorded.calls).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(FINDING);
  });

  it.each(SUBSTITUTE_PERMISSIONS)('rejects %s alone before the read port', async (permission) => {
    const recorded = applicationFor();
    const result = await recorded.application.execute({
      actor: actor('member', { permissions: [permission], administrator: true }),
      command: command(),
    });
    expect(result).toEqual({ status: 'authority_required' });
    expect(recorded.calls).toEqual([]);
  });

  it('rejects an unauthenticated actor, a missing organization, and an inactive membership', async () => {
    const recorded = applicationFor();
    const unauthenticated = await recorded.application.execute({
      actor: { ...actor('owner'), userId: '', sessionId: '' },
      command: command(),
    });
    const missingOrganization = await recorded.application.execute({
      actor: actor('owner', {}, null),
      command: command(),
    });
    const inactive = await recorded.application.execute({
      actor: actor('admin', { membershipStatus: 'revoked' }),
      command: command(),
    });
    const membershipOnly = await recorded.application.execute({
      actor: actor(null),
      command: command(),
    });
    for (const result of [unauthenticated, missingOrganization, inactive, membershipOnly]) {
      expect(result).toEqual({ status: 'authority_required' });
      expect(JSON.stringify(result)).not.toContain(FINDING);
      expect(JSON.stringify(result)).not.toContain(ORG);
    }
    expect(recorded.calls).toEqual([]);
  });

  it('rejects caller-supplied roles and permissions as grants', async () => {
    const recorded = applicationFor();
    const labeled = await recorded.application.execute({
      actor: actor('viewer', {
        claimedRole: 'owner',
        permissions: ['finding:inspect'],
        administrator: true,
      }),
      command: command(),
    });
    const commanded = await recorded.application.execute({
      actor: actor('owner'),
      command: command(FINDING, { role: 'owner', permissions: ['finding:inspect'] }),
    });
    expect(labeled).toEqual({ status: 'authority_required' });
    expect(commanded).toEqual({ status: 'authority_required' });
    expect(recorded.calls).toEqual([]);
  });

  it('rejects organization injection on the request and on the command', async () => {
    const recorded = applicationFor();
    const request = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
      organizationId: FOREIGN_ORG,
    });
    const injected = await recorded.application.execute({
      actor: actor('admin'),
      command: command(FINDING, { organizationId: FOREIGN_ORG }),
    });
    expect(request).toEqual({ status: 'authority_required' });
    expect(injected).toEqual({ status: 'authority_required' });
    expect(recorded.calls).toEqual([]);
    expect(JSON.stringify(request)).not.toContain(FOREIGN_ORG);
    expect(JSON.stringify(injected)).not.toContain(FOREIGN_ORG);
  });

  it('rejects a malformed Finding ID before the read port', async () => {
    const recorded = applicationFor();
    const malformed = [
      'not-a-uuid',
      FINDING.toUpperCase(),
      '',
      { findingId: FINDING, organizationId: FOREIGN_ORG },
      null,
    ];
    for (const findingId of malformed) {
      const result = await recorded.application.execute({
        actor: actor('owner'),
        command: command(findingId),
      });
      expect(result).toMatchObject({ status: 'unavailable' });
      expect(JSON.stringify(result)).not.toContain(FINDING);
      expect(JSON.stringify(result)).not.toContain(FOREIGN_ORG);
    }
    expect(recorded.calls).toEqual([]);
  });

  it('rejects unexpected command selectors before the read port', async () => {
    const recorded = applicationFor();
    const result = await recorded.application.execute({
      actor: actor('admin'),
      command: command(FINDING, {
        observationId: EVIDENCE,
        source: 'latest_repeated',
        aggregate: 'affected',
        historyLimit: 20,
      }),
    });
    expect(result).toMatchObject({ status: 'unavailable' });
    expect(recorded.calls).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(EVIDENCE);
  });

  it('returns one not_found result for an absent Finding and a foreign Finding', async () => {
    const absent = applicationFor(outcome('not_found', terminalSafe('not_found')));
    const foreign = applicationFor(outcome('not_found', terminalSafe('not_found')));
    const absentResult = await absent.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    const foreignResult = await foreign.application.execute({
      actor: actor('owner'),
      command: command(FOREIGN_FINDING),
    });
    expect(absentResult).toEqual(foreignResult);
    expect(absentResult).toEqual({
      schemaVersion: 'finding_latest_observation_external_result_v1',
      status: 'not_found',
    });
    expect(JSON.stringify(absentResult)).not.toContain(FINDING);
    expect(JSON.stringify(foreignResult)).not.toContain(FOREIGN_FINDING);
    expect(absent.calls).toEqual([{ organizationId: ORG, findingId: FINDING }]);
    expect(foreign.calls).toEqual([{ organizationId: ORG, findingId: FOREIGN_FINDING }]);
  });

  it('preserves creation fallback without repeated-observation language', async () => {
    const recorded = applicationFor(outcome('found', foundSafe(creationProjection())));
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toMatchObject({
      status: 'found',
      projection: {
        observationSource: 'creation',
        aggregate: 'affected',
        mappedResult: 'present',
        evidence: { kind: 'occurrence_support', knownVersions: ['1.2.0'] },
      },
    });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain('latest_repeated');
    expect(encoded).not.toContain('stale');
    expect(encoded).not.toContain('missing');
    expect(encoded).not.toContain('failed');
    expect(encoded).not.toContain('resolved');
    expect(encoded).not.toContain('reopened');
    if (result.status === 'found') {
      expect(Object.keys(result.projection).sort()).toEqual(
        [...FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS].sort(),
      );
    }
  });

  it.each([
    ['affected', 'present', occurrenceEvidence({ affected: 2, versions: ['1.2.0', '1.3.0'] })],
    [
      'unaffected',
      'absent',
      occurrenceEvidence({ affected: 0, unaffected: 2, versions: ['2.0.0'] }),
    ],
    [
      'unknown',
      'inconclusive',
      occurrenceEvidence({ affected: 0, unknown: 1, versions: ['0.0.0'] }),
    ],
  ] as const)('preserves a legal %s repeated observation', async (aggregate, mapped, evidence) => {
    const recorded = applicationFor(
      outcome('found', foundSafe(repeatedProjection(aggregate, mapped, evidence))),
    );
    const result = await recorded.application.execute({
      actor: actor('admin'),
      command: command(),
    });
    expect(result).toMatchObject({
      status: 'found',
      projection: {
        observationSource: 'latest_repeated',
        aggregate,
        mappedResult: mapped,
        evidence,
      },
    });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain('resolved');
    expect(encoded).not.toContain('remediat');
    expect(encoded).not.toContain('verified');
    expect(encoded).not.toContain('reopen');
    expect(encoded).not.toContain('recurrence');
    expect(encoded).not.toContain('priority');
    expect(encoded).not.toContain(EVIDENCE);
    expect(encoded).not.toContain(OCCURRENCE);
    expect(encoded).not.toContain(SUPPORT);
  });

  it('preserves component absence without remediation language', async () => {
    const evidence = {
      kind: 'component_absence',
      graphCompleteness: 'no_dependencies',
      componentCount: 3,
      dependencyEdgeCount: 0,
    };
    const recorded = applicationFor(
      outcome('found', foundSafe(repeatedProjection('component_absent', 'absent', evidence))),
    );
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toMatchObject({
      status: 'found',
      projection: {
        observationSource: 'latest_repeated',
        aggregate: 'component_absent',
        mappedResult: 'absent',
        evidence,
      },
    });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain('remediat');
    expect(encoded).not.toContain('resolved');
    expect(encoded).not.toContain('verified');
    expect(encoded).not.toContain('closed');
    expect(encoded).not.toContain('fingerprint');
  });

  it.each(
    CONTROLLED_FINDING_LATEST_OBSERVATION_READ_DIAGNOSTICS.filter(
      (diagnostic) => diagnostic !== 'found' && diagnostic !== 'not_found',
    ),
  )('maps %s to unavailable without the diagnostic', async (diagnostic) => {
    const recorded = applicationFor(outcome(diagnostic, terminalSafe('unavailable')));
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toEqual({
      schemaVersion: 'finding_latest_observation_external_result_v1',
      status: 'unavailable',
    });
    expect(JSON.stringify(result)).not.toContain(diagnostic);
    expect(JSON.stringify(result)).not.toContain(FINDING);
    expect(result).not.toHaveProperty('diagnostic');
  });

  it('does not convert hostile or unavailable persistence into not_found or creation', async () => {
    const cases = [
      outcome('malformed_persisted_state', terminalSafe('not_found')),
      outcome('database_unavailable', terminalSafe('not_found')),
      outcome('evidence_unavailable', foundSafe(creationProjection())),
      outcome('integrity_failure', {
        ...terminalSafe('unavailable'),
        diagnostic: 'integrity_failure',
        detail: SECRET,
      } as unknown as ReturnType<typeof terminalSafe>),
      outcome('internal_failure', terminalSafe('unavailable')),
    ];
    for (const body of cases) {
      const recorded = applicationFor(body);
      const result = await recorded.application.execute({
        actor: actor('admin'),
        command: command(),
      });
      expect(result).toMatchObject({ status: 'unavailable' });
      expect(result).not.toMatchObject({ status: 'not_found' });
      expect(result).not.toMatchObject({ status: 'found' });
      const encoded = JSON.stringify(result);
      expect(encoded).not.toContain('creation');
      expect(encoded).not.toContain(SECRET);
      expect(encoded).not.toContain('integrity_failure');
      expect(encoded).not.toContain('malformed_persisted_state');
      expect(encoded).not.toContain('database_unavailable');
    }
  });

  it('drops support identifiers, history, and recurrence from a found payload', async () => {
    const dirty = {
      ...creationProjection(),
      observations: [{ id: SUPPORT }],
      recurrence: 'continuous',
      evidence: {
        ...occurrenceEvidence(),
        evidenceId: EVIDENCE,
        occurrenceId: OCCURRENCE,
        supportLinkId: SUPPORT,
        replayFingerprint: 'ab'.repeat(32),
      },
    };
    const recorded = applicationFor(
      outcome('found', foundSafe(dirty as unknown as ReturnType<typeof creationProjection>)),
    );
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toMatchObject({ status: 'unavailable' });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain(EVIDENCE);
    expect(encoded).not.toContain(OCCURRENCE);
    expect(encoded).not.toContain(SUPPORT);
    expect(encoded).not.toContain('replay');
    expect(encoded).not.toContain('recurrence');
    expect(encoded).not.toContain('observations');
  });

  it('hides a contradictory Finding identity and adapter exceptions', async () => {
    const foreign = applicationFor(
      outcome(
        'found',
        foundSafe(
          projection({
            observationSource: 'creation',
            aggregate: 'affected',
            mappedResult: 'present',
            evidence: occurrenceEvidence(),
            findingId: FOREIGN_FINDING,
          }),
        ),
      ),
    );
    const thrown = applicationFor(() => {
      throw new Error(`${SECRET} finding ${FINDING} SQLSTATE 23505`);
    });
    const foreignResult = await foreign.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    const thrownResult = await thrown.application.execute({
      actor: actor('admin'),
      command: command(),
    });
    expect(foreignResult).toMatchObject({ status: 'unavailable' });
    expect(thrownResult).toMatchObject({ status: 'unavailable' });
    expect(JSON.stringify(foreignResult)).not.toContain(FOREIGN_FINDING);
    expect(JSON.stringify(thrownResult)).not.toContain(SECRET);
    expect(JSON.stringify(thrownResult)).not.toContain(FINDING);
    expect(JSON.stringify(thrownResult)).not.toContain('SQLSTATE');
    expect(thrown.calls).toHaveLength(1);
  });

  it('does not invoke a write, audit, or repeated-observation method on the port', async () => {
    const writes = { insert: 0, update: 0, delete: 0, audit: 0, observe: 0 };
    const calls: ReadCall[] = [];
    const read = Object.assign(
      {
        async read(query: ReadCall) {
          calls.push(query);
          return outcome('not_found', terminalSafe('not_found'));
        },
      },
      {
        insert() {
          writes.insert += 1;
        },
        update() {
          writes.update += 1;
        },
        delete() {
          writes.delete += 1;
        },
        audit() {
          writes.audit += 1;
        },
        recordFindingRepeatedObservation() {
          writes.observe += 1;
        },
      },
    );
    const application = createControlledFindingLatestObservationApplication({
      read: read as unknown as ControlledFindingLatestObservationReadPort,
    });
    const result = await application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toMatchObject({ status: 'not_found' });
    expect(calls).toHaveLength(1);
    expect(writes).toEqual({ insert: 0, update: 0, delete: 0, audit: 0, observe: 0 });
  });

  it('rejects forged actors that the trusted-actor contract rejects', async () => {
    const recorded = applicationFor();
    const valid = actor('owner');
    const proxy = new Proxy(valid, {});
    const getter = actor('owner');
    let getterReads = 0;
    Object.defineProperty(getter, 'role', {
      enumerable: true,
      get() {
        getterReads += 1;
        return 'owner';
      },
    });
    const statusGetter = actor('owner', { membershipStatus: 'active' });
    Object.defineProperty(statusGetter, 'membershipStatus', {
      enumerable: true,
      get() {
        getterReads += 1;
        return 'active';
      },
    });
    const bare: Record<string, unknown> = Object.assign(Object.create(null), valid);
    const cases = [
      proxy,
      getter,
      statusGetter,
      bare,
      [],
      null,
      undefined,
      {},
      { ...valid, userId: '' },
      { ...valid, sessionId: '' },
      { ...valid, organizationId: 'not-an-organization' },
      { ...valid, membershipId: null },
      { ...valid, role: 'maintainer' },
      { ...valid, role: 'owner', membershipStatus: 'inactive' },
      { ...valid, role: 'admin', membershipStatus: null },
      { ...valid, role: 'owner', membershipStatus: 'Active' },
      { ...valid, role: 'owner', membershipStatus: 'suspended' },
    ];
    for (const candidate of cases) {
      const result = await recorded.application.execute({
        actor: candidate,
        command: command(),
      });
      expect(result).toEqual({ status: 'authority_required' });
      expect(JSON.stringify(result)).not.toContain(FINDING);
      expect(JSON.stringify(result)).not.toContain(ORG);
      expect(JSON.stringify(result)).not.toContain(MEMBERSHIP);
    }
    expect(getterReads).toBe(0);
    expect(recorded.calls).toEqual([]);
  });

  it('keeps a disagreeing membership organization off the read port', async () => {
    const recorded = applicationFor(outcome('not_found', terminalSafe('not_found')));
    const result = await recorded.application.execute({
      actor: actor('owner', {
        membershipOrganizationId: FOREIGN_ORG,
        membership: { organizationId: FOREIGN_ORG, status: 'active' },
      }),
      command: command(),
    });
    expect(result).toMatchObject({ status: 'not_found' });
    expect(recorded.calls).toEqual([{ organizationId: ORG, findingId: FINDING }]);
    expect(JSON.stringify(result)).not.toContain(FOREIGN_ORG);
    expect(JSON.stringify(recorded.calls)).not.toContain(FOREIGN_ORG);
  });

  it('rejects stale presentation context and caller-selected authority before the read port', async () => {
    const recorded = applicationFor();
    const cases = [
      {
        actor: actor('viewer'),
        command: command(),
        permissions: ['finding:inspect'],
        role: 'owner',
        organizationId: FOREIGN_ORG,
      },
      {
        actor: actor('member'),
        command: command(),
        presentation: {
          organizationId: FOREIGN_ORG,
          role: 'owner',
          permissions: ['finding:inspect'],
          membershipStatus: 'active',
        },
      },
      {
        actor: { role: 'owner', permissions: ['finding:inspect'], organizationId: ORG },
        command: command(),
      },
    ];
    for (const input of cases) {
      const result = await recorded.application.execute(input);
      expect(result).toEqual({ status: 'authority_required' });
      expect(JSON.stringify(result)).not.toContain(FOREIGN_ORG);
      expect(JSON.stringify(result)).not.toContain(FINDING);
    }
    expect(recorded.calls).toEqual([]);
  });

  it('rejects every non-Finding command field before the read port', async () => {
    const recorded = applicationFor();
    let callbackReads = 0;
    const authorityFields = [
      { membershipId: MEMBERSHIP },
      { organizationId: FOREIGN_ORG },
      { role: 'owner' },
      { permissions: ['finding:inspect'] },
    ];
    const rejectedFields = [
      { observationId: EVIDENCE },
      { ingestionId: EVIDENCE },
      { sbomIngestionId: EVIDENCE },
      { aggregate: 'affected' },
      { observationSource: 'latest_repeated' },
      { source: 'creation' },
      { fallback: 'creation' },
      { historyLimit: 10 },
      { sort: 'observedAt' },
      { evidenceId: EVIDENCE },
      { supportLinkId: SUPPORT },
      { state: 'resolved' },
      { resolvedAt: OBSERVED },
      { reopenedAt: OBSERVED },
      { prisma: { select: { id: true } } },
      { sql: `select * from finding where organization_id = '${FOREIGN_ORG}'` },
      { selector: 'order by observed_at desc' },
      {
        transaction: () => {
          callbackReads += 1;
          return FOREIGN_ORG;
        },
      },
    ];
    for (const extras of authorityFields) {
      const result = await recorded.application.execute({
        actor: actor('owner'),
        command: command(FINDING, extras),
      });
      expect(result).toEqual({ status: 'authority_required' });
      expect(JSON.stringify(result)).not.toContain(FOREIGN_ORG);
      expect(JSON.stringify(result)).not.toContain(EVIDENCE);
    }
    for (const extras of rejectedFields) {
      const result = await recorded.application.execute({
        actor: actor('admin'),
        command: command(FINDING, extras),
      });
      expect(result).toMatchObject({ status: 'unavailable' });
      const encoded = JSON.stringify(result);
      expect(encoded).not.toContain(FOREIGN_ORG);
      expect(encoded).not.toContain(EVIDENCE);
      expect(encoded).not.toContain(SUPPORT);
      expect(encoded).not.toContain('select *');
      expect(encoded).not.toContain('resolved');
    }
    const missingFinding = await recorded.application.execute({
      actor: actor('owner'),
      command: {
        schemaVersion: INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
      },
    });
    const wrongSchema = await recorded.application.execute({
      actor: actor('owner'),
      command: command(FINDING, {
        schemaVersion: 'inspect_controlled_finding_latest_observation_v2',
      }),
    });
    const nilFinding = await recorded.application.execute({
      actor: actor('owner'),
      command: command('00000000-0000-0000-0000-000000000000'),
    });
    expect(missingFinding).toMatchObject({ status: 'unavailable' });
    expect(wrongSchema).toMatchObject({ status: 'unavailable' });
    expect(nilFinding).toMatchObject({ status: 'unavailable' });
    expect(callbackReads).toBe(0);
    expect(recorded.calls).toEqual([]);
  });

  it('does not invoke a Finding getter while rejecting a command', async () => {
    const recorded = applicationFor();
    let reads = 0;
    const commandBody = {
      schemaVersion: INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
      get findingId() {
        reads += 1;
        return FINDING;
      },
    };
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: commandBody,
    });
    expect(result).toMatchObject({ status: 'unavailable' });
    expect(reads).toBe(0);
    expect(recorded.calls).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(FINDING);
  });

  it('keeps unknown distinct from unaffected and creation distinct from a repeated observation', async () => {
    const unknown = applicationFor(
      outcome(
        'found',
        foundSafe(
          repeatedProjection(
            'unknown',
            'inconclusive',
            occurrenceEvidence({ affected: 0, unknown: 1, versions: ['0.0.0'] }),
          ),
        ),
      ),
    );
    const contradicted = applicationFor(
      outcome(
        'found',
        foundSafe(
          repeatedProjection(
            'unknown',
            'absent',
            occurrenceEvidence({ affected: 0, unknown: 1, versions: ['0.0.0'] }),
          ),
        ),
      ),
    );
    const creationAbsence = applicationFor(
      outcome(
        'found',
        foundSafe(
          projection({
            observationSource: 'creation',
            aggregate: 'component_absent',
            mappedResult: 'absent',
            evidence: {
              kind: 'component_absence',
              graphCompleteness: 'no_dependencies',
              componentCount: 1,
              dependencyEdgeCount: 0,
            },
          }),
        ),
      ),
    );
    const mixedCreation = applicationFor(
      outcome(
        'found',
        foundSafe(
          projection({
            observationSource: 'creation',
            aggregate: 'affected',
            mappedResult: 'present',
            evidence: occurrenceEvidence({ affected: 1, unaffected: 1 }),
          }),
        ),
      ),
    );
    const unknownResult = await unknown.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    const contradictedResult = await contradicted.application.execute({
      actor: actor('admin'),
      command: command(),
    });
    const absenceResult = await creationAbsence.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    const mixedResult = await mixedCreation.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(unknownResult).toMatchObject({
      status: 'found',
      projection: {
        observationSource: 'latest_repeated',
        aggregate: 'unknown',
        mappedResult: 'inconclusive',
      },
    });
    if (unknownResult.status === 'found') {
      expect(unknownResult.projection.aggregate).not.toBe('unaffected');
    }
    expect(contradictedResult).toMatchObject({ status: 'unavailable' });
    expect(absenceResult).toMatchObject({ status: 'unavailable' });
    expect(mixedResult).toMatchObject({ status: 'unavailable' });
    for (const result of [contradictedResult, absenceResult, mixedResult]) {
      expect(result).not.toMatchObject({ status: 'found' });
      expect(JSON.stringify(result)).not.toContain('component_absence');
      expect(JSON.stringify(result)).not.toContain('latest_repeated');
    }
  });

  it('turns an internal exception into unavailable rather than authority_required', async () => {
    const recorded = applicationFor(() => {
      throw new Error(`authority_required ${SECRET} ${FOREIGN_ORG} ${FINDING}`);
    });
    const result = await recorded.application.execute({
      actor: actor('owner'),
      command: command(),
    });
    expect(result).toEqual({
      schemaVersion: 'finding_latest_observation_external_result_v1',
      status: 'unavailable',
    });
    expect(result).not.toEqual({ status: 'authority_required' });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain(SECRET);
    expect(encoded).not.toContain(FOREIGN_ORG);
    expect(encoded).not.toContain(FINDING);
    expect(encoded).not.toContain('authority_required');
    expect(recorded.calls).toHaveLength(1);
  });
});
