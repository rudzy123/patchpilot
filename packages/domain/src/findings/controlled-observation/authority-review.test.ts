import { inspect } from 'node:util';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../../index.js';
import {
  deriveComponentAbsenceClassification,
  deriveRepeatedObservationAggregate,
} from './aggregate.js';
import {
  classifyFindingRepeatedObservationAuthorizationReuse,
  issueFindingRepeatedObservationAuthorization,
  openFindingRepeatedObservationCommand,
  presentFindingRepeatedObservationAuthorization,
  type FindingRepeatedObservationAuthorizationHandle,
} from './authorization.js';
import {
  classifyInspectionCompatibility,
  classifyInspectionObservationShape,
} from './inspection-compatibility.js';
import * as persistence from './persistence.js';
import {
  FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_FINDING_MUTATION,
  FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_INVARIANTS,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS,
  FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS,
  FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
  mapRepeatedObservationAggregate,
} from './policy.js';
import { parseFindingRepeatedObservationSupport } from './support.js';
import { classifyFindingRepeatedObservationReplay } from './replay.js';
import { parseTrustedFindingRepeatedObservationContext } from './trusted-context.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const FINDING = '19191919-1919-4191-8191-191919191919';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';
const UNKNOWN_A = '20202020-2020-4202-8202-202020202020';
const UNKNOWN_B = '21212121-2121-4121-8121-212121212121';
const CORRELATION = '10101010-1010-4101-8101-101010101010';
const OTHER_CORRELATION = '13131313-1313-4131-8131-131313131313';
const FOREIGN_ORG = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OTHER_ACTOR = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const OTHER_MEMBERSHIP = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const OTHER_ASSET = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const OTHER_COMPONENT = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const OTHER_VULNERABILITY = '12121212-1212-4121-8121-121212121212';
const OTHER_FINDING = '16161616-1616-4161-8161-161616161616';
const OTHER_INGESTION = '14141414-1414-4141-8141-141414141414';
const OCCURRENCE_A = '30303030-3030-4303-8303-303030303030';
const OCCURRENCE_B = '31313131-3131-4313-8313-313131313131';
const SENTINEL = 'review-sentinel-not-authority';
const UUID_TEXT = /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i;

type ClosedResult = {
  readonly status: string;
  readonly effects: typeof FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS;
};

function context(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: ORG,
    actorId: ACTOR,
    membershipId: MEMBERSHIP,
    membershipStatus: 'active',
    ...overrides,
  };
}

function evidenceSupport(
  evidenceIds: readonly string[] = [EVIDENCE_A, EVIDENCE_B],
  unknownVersionOccurrenceIds: readonly string[] = [],
): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
    kind: 'evidence_set',
    productMatchEvidenceIds: evidenceIds,
    unknownVersionOccurrenceIds,
  };
}

function absenceSupport(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
    kind: 'component_absence',
    sbomIngestionId: INGESTION,
    graphCompleteness: 'complete',
    componentCount: 4,
    occurrenceCardinality: 4,
    dependencyEdgeCount: 3,
    expectedFindingComponentOccurrenceCount: 0,
    normalizationVersion: 2,
    ...overrides,
  };
}

function issueBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext: context(),
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    findingId: FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: INGESTION,
    support: evidenceSupport(),
    correlationId: CORRELATION,
    ...overrides,
  };
}

function commandBody(
  authorization: unknown,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    expectedFindingId: FINDING,
    expectedAssetId: ASSET,
    expectedComponentId: COMPONENT,
    expectedVulnerabilityId: VULNERABILITY,
    expectedSbomIngestionId: INGESTION,
    support: evidenceSupport(),
    correlationId: CORRELATION,
    authorization,
    ...overrides,
  };
}

function authorize(
  overrides: Record<string, unknown> = {},
): FindingRepeatedObservationAuthorizationHandle {
  const issued = issueFindingRepeatedObservationAuthorization(issueBody(overrides));
  expect(issued.status).toBe('authorized');
  if (issued.status !== 'authorized') {
    throw new Error('authorization was not issued');
  }
  return issued.authorization;
}

function expectClosed(result: ClosedResult): void {
  expect(result.status).not.toBe('authorized');
  expect(result.status).not.toBe('observed');
  expect(result.status).not.toBe('already_applied');
  expect(result.effects).toEqual(FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS);
  expect(result).not.toHaveProperty('stack');
  expect(result).not.toHaveProperty('sql');
  expect(result).not.toHaveProperty('prisma');
  expect(result).not.toHaveProperty('authorization');
  const serialized = JSON.stringify(result);
  expect(serialized).not.toContain(SENTINEL);
  expect(serialized).not.toContain('SELECT ');
  expect(serialized.toLowerCase()).not.toContain('prisma');
  expect(serialized).not.toMatch(UUID_TEXT);
}

function supportId(index: number): string {
  return `88888888-8888-4888-8888-${index.toString(16).padStart(12, '0')}`;
}

function unknownId(index: number): string {
  return `20202020-2020-4202-8202-${index.toString(16).padStart(12, '0')}`;
}

function known(
  occurrenceId: string,
  outcome: 'affected' | 'unaffected' | 'unknown',
): Record<string, unknown> {
  return {
    occurrenceId,
    versionKnown: true,
    directness: 'direct',
    evidenceStatus: 'one_current',
    outcome,
  };
}

function occurrenceSet(occurrences: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION,
    occurrences,
  };
}

function absenceFacts(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION,
    ingestionStatus: 'completed',
    latestSuccessful: true,
    strictlyLater: true,
    normalizationVersion: 2,
    graphCompleteness: 'complete',
    componentCount: 4,
    liveOccurrenceCardinality: 4,
    dependencyEdgeCount: 3,
    liveDependencyEdgeCardinality: 3,
    findingComponentOccurrenceCount: 0,
    ...overrides,
  };
}

function replay(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION,
    observationPresent: true,
    naturalIdentityAgrees: true,
    purposeAgrees: true,
    policyAgrees: true,
    aggregateAgrees: true,
    mappedResultAgrees: true,
    supportFingerprintAgrees: true,
    evidenceLinkSetAgrees: true,
    unknownVersionProofSetAgrees: true,
    absenceProofAgrees: true,
    ingestionAgrees: true,
    findingTargetAgrees: true,
    replayFingerprintAgrees: true,
    persistedStateWellFormed: true,
    uniquenessViolation: false,
    semanticComparisonComplete: true,
    ...overrides,
  };
}

describe('repeated observation authority forgery', () => {
  it('rejects plain, serialized, cloned, spread, assigned, prototype, proxy, and asserted objects', () => {
    const handle = authorize();
    const attacks: unknown[] = [
      {
        purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
        policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
        findingId: FINDING,
        organizationId: ORG,
      },
      JSON.parse(JSON.stringify(handle)),
      structuredClone(handle),
      { ...handle },
      Object.assign(Object.create(null) as object, handle),
      Object.create(handle),
      Object.create(Object.getPrototypeOf(handle)),
      Object.freeze({ purpose: FINDING_REPEATED_OBSERVATION_PURPOSE, findingId: FINDING }),
      Object.seal({ purpose: FINDING_REPEATED_OBSERVATION_PURPOSE, findingId: FINDING }),
      {} as FindingRepeatedObservationAuthorizationHandle,
    ];
    for (const attack of attacks) {
      expectClosed(openFindingRepeatedObservationCommand(commandBody(attack)));
    }

    const symbolCopy = Object.create(null) as object;
    for (const key of [
      ...Object.getOwnPropertyNames(handle),
      ...Object.getOwnPropertySymbols(handle),
    ]) {
      const descriptor = Object.getOwnPropertyDescriptor(handle, key);
      if (descriptor !== undefined) {
        Object.defineProperty(symbolCopy, key, descriptor);
      }
    }
    expectClosed(openFindingRepeatedObservationCommand(commandBody(symbolCopy)));

    let proxyReads = 0;
    const forwarding = new Proxy(handle, {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    expectClosed(openFindingRepeatedObservationCommand(commandBody(forwarding)));
    expect(proxyReads).toBe(0);

    const revocable = Proxy.revocable(handle, {});
    revocable.revoke();
    expectClosed(openFindingRepeatedObservationCommand(commandBody(revocable.proxy)));
    expect(JSON.stringify(handle)).not.toMatch(UUID_TEXT);
    expect(inspect(handle)).not.toMatch(UUID_TEXT);
    expect(String(handle)).not.toMatch(UUID_TEXT);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.plainObjectIsAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.proxyIsAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.typeAssertionIsAuthority).toBe(false);
  });

  it('rejects a forged command that copies a valid handle', () => {
    const handle = authorize();
    const command = openFindingRepeatedObservationCommand(commandBody(handle));
    expect(command.status).toBe('authorized');
    if (command.status !== 'authorized') {
      return;
    }
    const forged = Object.assign(Object.create(null) as object, command.command);
    const authorization = Object.getOwnPropertyDescriptor(command.command, 'authorization');
    if (authorization !== undefined) {
      Object.defineProperty(forged, 'authorization', authorization);
    }
    expectClosed(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context(),
        command: forged,
      }),
    );
    const cloned: unknown = structuredClone(command.command);
    expect(cloned).not.toHaveProperty('authorization');
    expectClosed(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context(),
        command: cloned,
      }),
    );
    expect(JSON.stringify(command)).not.toMatch(UUID_TEXT);
    expect(JSON.stringify(command)).not.toContain(EVIDENCE_A);
  });

  it('keeps caller role, permission, and membership from minting authority', () => {
    expectClosed(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ role: 'owner', permission: SENTINEL }),
      ),
    );
    expectClosed(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ permissions: ['finding:create_controlled'] }),
      ),
    );
    const parsed = parseTrustedFindingRepeatedObservationContext(context());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) {
      return;
    }
    expectClosed(openFindingRepeatedObservationCommand(commandBody(parsed.context)));
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.membershipAloneIsAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.permissionIsAuthority).toBe(false);
  });
});

describe('repeated observation binding and substitution', () => {
  it('rejects every substituted target, ingestion, support set, purpose, and policy', () => {
    const handle = authorize();
    const substitutions: Record<string, unknown>[] = [
      { expectedFindingId: OTHER_FINDING },
      { expectedAssetId: OTHER_ASSET },
      { expectedComponentId: OTHER_COMPONENT },
      { expectedVulnerabilityId: OTHER_VULNERABILITY },
      { expectedSbomIngestionId: OTHER_INGESTION },
      { correlationId: OTHER_CORRELATION },
      { purpose: 'observe_finding' },
      { policyId: 'other_policy' },
      { policyVersion: 2 },
      { support: evidenceSupport([EVIDENCE_A]) },
      { support: evidenceSupport([EVIDENCE_A, EVIDENCE_B], [UNKNOWN_A]) },
      { support: absenceSupport() },
    ];
    for (const substitution of substitutions) {
      expectClosed(openFindingRepeatedObservationCommand(commandBody(handle, substitution)));
    }
    const command = openFindingRepeatedObservationCommand(commandBody(handle));
    expect(command.status).toBe('authorized');
    if (command.status !== 'authorized') {
      return;
    }
    for (const trusted of [
      context({ organizationId: FOREIGN_ORG }),
      context({ actorId: OTHER_ACTOR }),
      context({ membershipId: OTHER_MEMBERSHIP }),
    ]) {
      const presented = presentFindingRepeatedObservationAuthorization({
        trustedContext: trusted,
        command: command.command,
      });
      expectClosed(presented);
      expect(JSON.stringify(presented)).not.toContain(FOREIGN_ORG);
      expect(JSON.stringify(presented)).not.toContain(ORG);
    }
    expectClosed(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { trustedContext: context({ organizationId: FOREIGN_ORG }) }),
      ),
    );
    expectClosed(
      openFindingRepeatedObservationCommand(commandBody({ findingId: FINDING, assetId: ASSET })),
    );
  });

  it('binds correlation to issuance without making correlation the replay identity', () => {
    const first = authorize();
    const second = authorize({ correlationId: OTHER_CORRELATION });
    expect(
      classifyFindingRepeatedObservationAuthorizationReuse({ left: first, right: second }).status,
    ).toBe('authorized');
    const reuse = classifyFindingRepeatedObservationAuthorizationReuse({
      left: first,
      right: second,
    });
    expect(reuse.status).toBe('authorized');
    if (reuse.status === 'authorized') {
      expect(reuse.classification).toBe('distinct_authorization');
      expect(reuse.authorityCreated).toBe(false);
    }
    expectClosed(
      openFindingRepeatedObservationCommand(
        commandBody(first, { correlationId: OTHER_CORRELATION }),
      ),
    );
    const opened = openFindingRepeatedObservationCommand(
      commandBody(second, { correlationId: OTHER_CORRELATION }),
    );
    expect(opened.status).toBe('authorized');
    const applied = classifyFindingRepeatedObservationReplay(replay());
    expect(applied.classification).toBe('already_applied');
    expect(applied.correlationRedefinesReplay).toBe(false);
    expect(applied.observationInserts).toBe(0);
    expect(FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS).toContain('correlationId');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.correlationIsReplayIdentity).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.correlationIsAuthorizationBinding).toBe(true);
  });
});

describe('repeated observation support canonicalization', () => {
  it('rejects hostile, noncanonical, duplicate, and contradictory support sets', () => {
    expectClosed(
      issueFindingRepeatedObservationAuthorization(issueBody({ support: evidenceSupport([], []) })),
    );
    const canonicalWithLetters = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([canonicalWithLetters.toUpperCase()]) }),
      ).reason,
    ).toBe('evidence_set_malformed');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([` ${EVIDENCE_A}`]) }),
      ).reason,
    ).toBe('evidence_set_malformed');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A.replaceAll('-', '')]) }),
      ).reason,
    ).toBe('evidence_set_malformed');

    const sparse = [EVIDENCE_A, EVIDENCE_B];
    delete sparse[0];
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ support: evidenceSupport(sparse) }))
        .reason,
    ).toBe('evidence_set_hostile');

    let getterReads = 0;
    const getterIds: string[] = [];
    Object.defineProperty(getterIds, '0', {
      enumerable: true,
      get() {
        getterReads += 1;
        return EVIDENCE_A;
      },
    });
    Object.defineProperty(getterIds, 'length', { value: 1, writable: false });
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport(getterIds) }),
      ).reason,
    ).toBe('evidence_set_hostile');
    expect(getterReads).toBe(0);

    const customPrototype = [EVIDENCE_A];
    Object.setPrototypeOf(customPrototype, Object.create(Array.prototype));
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport(customPrototype) }),
      ).reason,
    ).toBe('evidence_set_hostile');

    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A, EVIDENCE_B], [EVIDENCE_A]) }),
      ).reason,
    ).toBe('evidence_set_duplicate');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: {
            ...evidenceSupport(),
            supportCount: 1,
            fingerprint: SENTINEL,
          },
        }),
      ).reason,
    ).toBe('command_rejected');
  });

  it('accepts exactly sixteen combined facts and rejects seventeen', () => {
    const eightEvidence = Array.from({ length: 8 }, (_, index) => supportId(index + 1));
    const eightUnknown = Array.from({ length: 8 }, (_, index) => unknownId(index + 1));
    expect(eightEvidence.length + eightUnknown.length).toBe(
      FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
    );
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport(eightEvidence, eightUnknown) }),
      ).status,
    ).toBe('authorized');

    const sixteenEvidence = Array.from({ length: 16 }, (_, index) => supportId(index + 1));
    const oversized = issueFindingRepeatedObservationAuthorization(
      issueBody({ support: evidenceSupport(sixteenEvidence, [unknownId(1)]) }),
    );
    expect(oversized.status).toBe('evidence_set_oversized');
    expect(oversized.effects.persistenceWrites).toBe(0);
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.classification).toBe(
      'versioned_policy_limit',
    );
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.countsUnknownVersionOccurrenceProofs).toBe(
      true,
    );
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.schemaMaximum).toBe(false);
  });

  it('keeps unknown-version proofs distinct from evidence and from absence', () => {
    const parsed = parseFindingRepeatedObservationSupport(
      evidenceSupport([], [UNKNOWN_A, UNKNOWN_B]),
      INGESTION,
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.support.kind !== 'evidence_set') {
      return;
    }
    expect(parsed.support.productMatchEvidenceIds).toEqual([]);
    expect(parsed.support.unknownVersionOccurrenceIds).toEqual([UNKNOWN_A, UNKNOWN_B]);
    expect(parsed.support.supportCount).toBe(2);
    expect(parsed.support.kind).not.toBe('component_absence');
    const ids = [UNKNOWN_A, UNKNOWN_B];
    const issued = issueFindingRepeatedObservationAuthorization(
      issueBody({ support: evidenceSupport([], ids) }),
    );
    expect(issued.status).toBe('authorized');
    ids.push(EVIDENCE_A);
    ids[0] = EVIDENCE_B;
    const opened = openFindingRepeatedObservationCommand(
      commandBody(issued.status === 'authorized' ? issued.authorization : authorize(), {
        support: evidenceSupport([], [UNKNOWN_A, UNKNOWN_B]),
      }),
    );
    expect(opened.status).toBe('authorized');
    if (opened.status === 'authorized' && opened.command.supportKind === 'evidence_set') {
      expect(opened.command.expectedUnknownVersionOccurrenceIds).toEqual([UNKNOWN_A, UNKNOWN_B]);
      expect(opened.command.expectedProductMatchEvidenceIds).toEqual([]);
    }
  });

  it('rejects unconstrained absence facts and ignores caller absence assertions', () => {
    let conversions = 0;
    const graph = {
      toString() {
        conversions += 1;
        return 'complete';
      },
      valueOf() {
        conversions += 1;
        return 'complete';
      },
    };
    const coerced = issueFindingRepeatedObservationAuthorization(
      issueBody({ support: absenceSupport({ graphCompleteness: graph }) }),
    );
    expect(coerced.reason).toBe('absence_graph_rejected');
    expect(conversions).toBe(0);
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ graphCompleteness: Symbol('complete') }) }),
      ).reason,
    ).toBe('absence_graph_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ graphCompleteness: 'empty' }) }),
      ).reason,
    ).toBe('absence_graph_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ graphCompleteness: 'partial' }) }),
      ).reason,
    ).toBe('absence_graph_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ componentCount: -1, occurrenceCardinality: -1 }) }),
      ).reason,
    ).toBe('absence_count_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ componentCount: 4, occurrenceCardinality: 3 }) }),
      ).reason,
    ).toBe('absence_count_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ dependencyEdgeCount: 0 }) }),
      ).reason,
    ).toBe('absence_graph_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: absenceSupport({
            graphCompleteness: 'no_dependencies',
            componentCount: 2,
            occurrenceCardinality: 2,
            dependencyEdgeCount: 2,
          }),
        }),
      ).reason,
    ).toBe('absence_graph_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: absenceSupport({
            graphCompleteness: 'no_dependencies',
            componentCount: 2,
            occurrenceCardinality: 2,
            dependencyEdgeCount: -0,
          }),
        }),
      ).reason,
    ).toBe('absence_count_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: absenceSupport({
            graphCompleteness: 'no_dependencies',
            componentCount: 2,
            occurrenceCardinality: 2,
            dependencyEdgeCount: 0,
          }),
        }),
      ).status,
    ).toBe('authorized');

    const mutable = absenceSupport();
    const issued = issueFindingRepeatedObservationAuthorization(issueBody({ support: mutable }));
    expect(issued.status).toBe('authorized');
    mutable['componentCount'] = 99;
    mutable['graphCompleteness'] = 'empty';
    mutable['sbomIngestionId'] = OTHER_INGESTION;
    if (issued.status !== 'authorized') {
      return;
    }
    const opened = openFindingRepeatedObservationCommand(
      commandBody(issued.authorization, { support: absenceSupport() }),
    );
    expect(opened.status).toBe('authorized');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.callerSelectsAbsenceAuthority).toBe(false);
  });

  it('does not let post-issuance command mutation change the sealed target', () => {
    const handle = authorize();
    const opened = openFindingRepeatedObservationCommand(commandBody(handle));
    expect(opened.status).toBe('authorized');
    if (opened.status !== 'authorized' || opened.command.supportKind !== 'evidence_set') {
      return;
    }
    expect(() => {
      (opened.command as { expectedFindingId: string }).expectedFindingId = OTHER_FINDING;
    }).toThrow(TypeError);
    const presented = presentFindingRepeatedObservationAuthorization({
      trustedContext: context(),
      command: opened.command,
    });
    expect(presented.status).toBe('authorized');
    if (presented.status === 'authorized') {
      expect(presented).not.toHaveProperty('authorization');
      expect(presented.effects).toEqual(FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS);
      expect(JSON.stringify(presented)).not.toMatch(UUID_TEXT);
    }
  });
});

describe('repeated observation aggregate, command, and replay contracts', () => {
  it('derives governed aggregates and leaves every Finding open', () => {
    const affectedAndUnknownVersion = deriveRepeatedObservationAggregate(
      occurrenceSet([
        known(OCCURRENCE_A, 'affected'),
        { occurrenceId: OCCURRENCE_B, versionKnown: false, directness: 'transitive' },
      ]),
    );
    expect(affectedAndUnknownVersion.status).toBe('derived');
    if (affectedAndUnknownVersion.status === 'derived') {
      expect(affectedAndUnknownVersion.aggregate).toBe('affected');
      expect(affectedAndUnknownVersion.mappedResult).toBe('present');
      expect(affectedAndUnknownVersion.findingState).toBe('open');
      expect(affectedAndUnknownVersion.persisted).toBe(false);
    }

    const unaffectedAndUnknownVersion = deriveRepeatedObservationAggregate(
      occurrenceSet([
        known(OCCURRENCE_A, 'unaffected'),
        { occurrenceId: OCCURRENCE_B, versionKnown: false, directness: 'unspecified' },
      ]),
    );
    expect(unaffectedAndUnknownVersion.status).toBe('derived');
    if (unaffectedAndUnknownVersion.status === 'derived') {
      expect(unaffectedAndUnknownVersion.aggregate).toBe('unknown');
      expect(unaffectedAndUnknownVersion.mappedResult).toBe('inconclusive');
    }

    const allUnknown = deriveRepeatedObservationAggregate(
      occurrenceSet([known(OCCURRENCE_A, 'unknown'), known(OCCURRENCE_B, 'unknown')]),
    );
    expect(allUnknown.status).toBe('derived');
    if (allUnknown.status === 'derived') {
      expect(allUnknown.aggregate).toBe('unknown');
    }

    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([
          known(OCCURRENCE_A, 'affected'),
          {
            occurrenceId: OCCURRENCE_B,
            versionKnown: true,
            directness: 'direct',
            evidenceStatus: 'missing',
          },
        ]),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([
          {
            occurrenceId: OCCURRENCE_A,
            versionKnown: true,
            directness: 'direct',
            evidenceStatus: 'missing',
          },
          { occurrenceId: OCCURRENCE_B, versionKnown: false, directness: 'direct' },
        ]),
      ).status,
    ).toBe('evidence_unavailable');
    const empty = deriveRepeatedObservationAggregate(occurrenceSet([]));
    expect(empty.status).toBe('evidence_unavailable');
    expect(empty.aggregate).toBeNull();
    expect(
      deriveRepeatedObservationAggregate(
        occurrenceSet([
          {
            occurrenceId: OCCURRENCE_A,
            versionKnown: true,
            directness: null,
            evidenceStatus: 'one_current',
            outcome: 'affected',
          },
        ]),
      ).status,
    ).toBe('invalid_command');
    expect(
      deriveRepeatedObservationAggregate({
        ...occurrenceSet([known(OCCURRENCE_A, 'unaffected')]),
        mappedResult: 'absent',
      }).status,
    ).toBe('invalid_command');

    expect(mapRepeatedObservationAggregate('unaffected')).toBe('absent');
    expect(mapRepeatedObservationAggregate('component_absent')).toBe('absent');
    expect(mapRepeatedObservationAggregate('unaffected')).toBe(
      mapRepeatedObservationAggregate('component_absent'),
    );

    const absent = deriveComponentAbsenceClassification(absenceFacts());
    expect(absent.status).toBe('component_absent');
    if (absent.status === 'component_absent') {
      expect(absent.findingState).toBe('open');
      expect(absent.meansClosed).toBe(false);
      expect(absent.meansRemediated).toBe(false);
    }
    expect(
      deriveComponentAbsenceClassification(
        absenceFacts({
          graphCompleteness: 'no_dependencies',
          componentCount: 2,
          liveOccurrenceCardinality: 2,
          dependencyEdgeCount: -0,
          liveDependencyEdgeCardinality: -0,
        }),
      ).status,
    ).toBe('invalid_command');
    expect(
      deriveComponentAbsenceClassification(
        absenceFacts({ componentCount: 4, liveOccurrenceCardinality: 3 }),
      ).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification(absenceFacts({ graphCompleteness: 'partial' })).status,
    ).toBe('evidence_unavailable');
    expect(
      deriveComponentAbsenceClassification({
        ...absenceFacts(),
        callerAssertsAbsent: true,
      }).status,
    ).toBe('invalid_command');
  });

  it('rejects caller-selected command authority and mutation fields', () => {
    const handle = authorize();
    for (const field of FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS) {
      expectClosed(issueFindingRepeatedObservationAuthorization(issueBody({ [field]: SENTINEL })));
      expectClosed(
        openFindingRepeatedObservationCommand(commandBody(handle, { [field]: SENTINEL })),
      );
    }
    let callbacks = 0;
    expectClosed(
      openFindingRepeatedObservationCommand(
        commandBody(handle, {
          transaction: () => {
            callbacks += 1;
          },
          prisma: { client: SENTINEL },
          operatorNote: SENTINEL,
        }),
      ),
    );
    expect(callbacks).toBe(0);
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.directMutationAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.stateAfterEveryAggregate).toBe('open');
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.permittedSummaryFields).toEqual([
      'last_observed_at',
      'updated_at',
    ]);
    for (const power of Object.values(FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS)) {
      expect(power).toBe('unavailable');
    }
  });

  it('classifies semantic disagreement as conflict and refuses to repair malformed state', () => {
    const flags = [
      'purposeAgrees',
      'policyAgrees',
      'aggregateAgrees',
      'mappedResultAgrees',
      'supportFingerprintAgrees',
      'evidenceLinkSetAgrees',
      'unknownVersionProofSetAgrees',
      'absenceProofAgrees',
      'ingestionAgrees',
      'findingTargetAgrees',
      'replayFingerprintAgrees',
    ] as const;
    for (const flag of flags) {
      const conflict = classifyFindingRepeatedObservationReplay(replay({ [flag]: false }));
      expect(conflict.classification).toBe('immutable_conflict');
      expect(conflict.repairAuthorized).toBe(false);
      expect(conflict.writes).toBe(false);
      expect(conflict.correlationRedefinesReplay).toBe(false);
    }
    const fingerprintOnly = classifyFindingRepeatedObservationReplay(
      replay({ supportFingerprintAgrees: true, evidenceLinkSetAgrees: false }),
    );
    expect(fingerprintOnly.classification).toBe('immutable_conflict');
    const malformed = classifyFindingRepeatedObservationReplay(
      replay({ persistedStateWellFormed: false }),
    );
    expect(malformed.classification).toBe('malformed_persisted_state');
    expect(malformed.repairAuthorized).toBe(false);
    expect(malformed.outcome).not.toBe('already_applied');
    expect(
      classifyFindingRepeatedObservationReplay(
        replay({ uniquenessViolation: true, semanticComparisonComplete: false }),
      ).classification,
    ).toBe('uniqueness_not_replay');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ correlationAgrees: false })).classification,
    ).toBe('comparison_rejected');
    expect(
      classifyFindingRepeatedObservationReplay(replay({ observationPresent: 'true' }))
        .classification,
    ).toBe('comparison_rejected');
    expect(
      FINDING_REPEATED_OBSERVATION_INVARIANTS.fingerprintEqualityReplacesSemanticValidation,
    ).toBe(false);
  });
});

describe('repeated observation public surface and inspection boundary', () => {
  it('does not export the issuer, a writer, or a generic Finding mutator', () => {
    expect(domainPublic).not.toHaveProperty('issueFindingRepeatedObservationAuthorization');
    expect(domainPublic).not.toHaveProperty('parseFindingRepeatedObservationSupport');
    expect(domainPublic).not.toHaveProperty('repeatedObservationSupportsMatch');
    expect(domainPublic).not.toHaveProperty('observeFinding');
    expect(domainPublic).not.toHaveProperty('updateFinding');
    expect(Object.keys(persistence).sort()).toEqual([
      'FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY',
      'FINDING_REPEATED_OBSERVATION_PORT_EXCLUSIONS',
      'repeatedObservationTenantDisclosure',
    ]);
    expect(persistence.FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.implemented).toBe(true);
    expect(persistence.FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.canWriteObservation).toBe(
      true,
    );
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.issuerPackageExport).toBe('absent');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.internalIssuerTrustBoundary).toBe(
      'same_package_relative_import',
    );
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.authorityReview).toBe(
      'controlled_finding_repeated_observation_session_1r',
    );
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.nextSession).toBe(
      'controlled_finding_repeated_observation_session_2r',
    );
    const disclosure = persistence.repeatedObservationTenantDisclosure();
    expect(disclosure.foreignResourceRevealed).toBe(false);
    expect(disclosure.existsInOtherOrganization).toBe(false);
  });

  it('does not treat an arbitrary or later observation as the creation observation', () => {
    const later = {
      method: 'controlled_finding_repeated_observation',
      result: 'present',
      occurrenceId: null,
      transitionClassification: 'evidence_observation',
      creationPurpose: null,
      creationPolicyId: null,
      creationPolicyVersion: null,
      observationPurpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
      observationPolicyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
      observationPolicyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
      aggregate: 'affected',
    };
    expect(
      classifyInspectionCompatibility({
        schemaVersion: FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION,
        creationObservation: later,
        laterObservations: [],
      }).status,
    ).toBe('malformed_persisted_state');
    expect(classifyInspectionObservationShape({ method: 'controlled_finding_creation' }).role).toBe(
      'malformed_persisted_state',
    );
    expect(
      classifyInspectionObservationShape({
        ...later,
        method: 'controlled_finding_creation',
        creationPurpose: 'create_controlled_finding',
      }).role,
    ).toBe('malformed_persisted_state');
  });
});
