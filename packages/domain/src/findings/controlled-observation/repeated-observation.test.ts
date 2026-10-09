import { describe, expect, it } from 'vitest';

import {
  classifyFindingRepeatedObservationAuthorizationReuse,
  issueFindingRepeatedObservationAuthorization,
  openFindingRepeatedObservationCommand,
  presentFindingRepeatedObservationAuthorization,
  type FindingRepeatedObservationAuthorizationHandle,
  type SealedFindingRepeatedObservationCommand,
} from './authorization.js';
import {
  FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY,
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT,
  FINDING_REPEATED_OBSERVATION_AGGREGATES,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_FINDING_MUTATION,
  FINDING_REPEATED_OBSERVATION_INVARIANTS,
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_NATURAL_IDENTITY_FIELDS,
  FINDING_REPEATED_OBSERVATION_NON_AGGREGATE_FAILURES,
  FINDING_REPEATED_OBSERVATION_NON_FINDING_IDENTITY_FIELDS,
  FINDING_REPEATED_OBSERVATION_OUTCOMES,
  FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_REJECTED_GENERIC_PURPOSES,
  FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS,
  FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS,
  FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS,
  FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS,
  mapRepeatedObservationAggregate,
} from './policy.js';
import { parseFindingRepeatedObservationSupport } from './support.js';

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
const EVIDENCE_C = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const UNKNOWN_A = '20202020-2020-4202-8202-202020202020';
const UNKNOWN_B = '21212121-2121-4121-8121-212121212121';
const CORRELATION = '10101010-1010-4101-8101-101010101010';
const FOREIGN_ORG = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OTHER_ACTOR = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const OTHER_MEMBERSHIP = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const OTHER_ASSET = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const OTHER_COMPONENT = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const OTHER_VULNERABILITY = '12121212-1212-4121-8121-121212121212';
const OTHER_FINDING = '16161616-1616-4161-8161-161616161616';
const OTHER_INGESTION = '14141414-1414-4141-8141-141414141414';
const OTHER_CORRELATION = '13131313-1313-4131-8131-131313131313';

const UUID_TEXT = /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/;

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

function sealCommand(
  authorization: FindingRepeatedObservationAuthorizationHandle = authorize(),
  overrides: Record<string, unknown> = {},
): SealedFindingRepeatedObservationCommand {
  const opened = openFindingRepeatedObservationCommand(commandBody(authorization, overrides));
  expect(opened.status).toBe('authorized');
  if (opened.status !== 'authorized') {
    throw new Error('command was not sealed');
  }
  return opened.command;
}

function supportId(index: number): string {
  return `88888888-8888-4888-8888-${index.toString(16).padStart(12, '0')}`;
}

function unknownId(index: number): string {
  return `20202020-2020-4202-8202-${index.toString(16).padStart(12, '0')}`;
}

describe('repeated observation purpose and policy', () => {
  it('keeps one exact purpose and one versioned policy', () => {
    expect(FINDING_REPEATED_OBSERVATION_PURPOSE).toBe('record_finding_repeated_observation');
    expect(FINDING_REPEATED_OBSERVATION_POLICY_ID).toBe('finding_observation_policy_v1');
    expect(FINDING_REPEATED_OBSERVATION_POLICY_VERSION).toBe(1);
    expect(FINDING_REPEATED_OBSERVATION_REJECTED_GENERIC_PURPOSES).not.toContain(
      FINDING_REPEATED_OBSERVATION_PURPOSE,
    );
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ purpose: 'observe_finding' }))
        .status,
    ).toBe('authority_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ policyId: 'generic_finding_policy' }),
      ).status,
    ).toBe('authority_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ policyVersion: 2 })).status,
    ).toBe('authority_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ policyVersion: '1' })).status,
    ).toBe('authority_rejected');
  });
});

describe('repeated observation authorization', () => {
  it('issues and presents one exact purpose-specific authorization', () => {
    const issued = issueFindingRepeatedObservationAuthorization(issueBody());
    expect(issued.status).toBe('authorized');
    if (issued.status !== 'authorized') {
      return;
    }
    expect(issued.authorityCreated).toBe(true);
    expect(issued.authorityRenewed).toBe(false);
    expect(issued.durableAuthority).toBe(false);
    expect(issued.observationWrite).toBe('not_performed');
    expect(issued.findingMutation).toBe('not_performed');
    expect(issued.persistence).toBe('not_performed');
    expect(issued.effects).toEqual(FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS);
    expect(issued).not.toHaveProperty('success');
    expect(issued).not.toHaveProperty('organizationId');

    const command = sealCommand(issued.authorization);
    const presented = presentFindingRepeatedObservationAuthorization({
      trustedContext: context(),
      command,
    });
    expect(presented.status).toBe('authorized');
    if (presented.status !== 'authorized') {
      return;
    }
    expect(presented.continuation).toBe('persisted_fact_validation');
    expect(presented.authorizationReuse).toBe('repeatable');
    expect(presented.authorizationConsumed).toBe(false);
    expect(presented.authorizationExpires).toBe(false);
    expect(presented.effects.findingObservationWrites).toBe(0);
    expect(presented.effects.findingTimestampUpdates).toBe(0);
    expect(presented.effects.findingObservedAuditWrites).toBe(0);
    const again = presentFindingRepeatedObservationAuthorization({
      trustedContext: context(),
      command,
    });
    expect(again.status).toBe('authorized');
  });

  it('rejects missing, forged, plain, JSON, cloned, spread, and prototype authority', () => {
    expect(openFindingRepeatedObservationCommand(commandBody(null)).status).toBe(
      'authority_required',
    );
    expect(openFindingRepeatedObservationCommand(commandBody(undefined)).status).toBe(
      'authority_required',
    );

    const plain = openFindingRepeatedObservationCommand(
      commandBody({
        purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
        organizationId: ORG,
        findingId: FINDING,
      }),
    );
    expect(plain.status).toBe('authority_rejected');

    const handle = authorize();
    const jsonHandle: unknown = JSON.parse(JSON.stringify(handle));
    expect(openFindingRepeatedObservationCommand(commandBody(jsonHandle)).status).toBe(
      'authority_rejected',
    );
    expect(openFindingRepeatedObservationCommand(commandBody(structuredClone(handle))).status).toBe(
      'authority_rejected',
    );
    expect(openFindingRepeatedObservationCommand(commandBody({ ...handle })).status).toBe(
      'authority_rejected',
    );
    const copied = Object.assign(Object.create(null) as object, handle);
    expect(openFindingRepeatedObservationCommand(commandBody(copied)).status).toBe(
      'authority_rejected',
    );
    expect(openFindingRepeatedObservationCommand(commandBody(Object.create(handle))).status).toBe(
      'authority_rejected',
    );
    const asserted = {} as FindingRepeatedObservationAuthorizationHandle;
    expect(openFindingRepeatedObservationCommand(commandBody(asserted)).status).toBe(
      'authority_rejected',
    );

    const command = sealCommand(handle);
    expect(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context(),
        command: structuredClone(command),
      }).status,
    ).toBe('authority_rejected');
    expect(JSON.stringify(handle)).not.toMatch(UUID_TEXT);
    expect(JSON.stringify(command)).toBe(
      JSON.stringify({ classification: 'redacted', reusableAuthority: false }),
    );
    expect(
      Object.getOwnPropertyNames(command).some((name) =>
        name.toLowerCase().includes('fingerprint'),
      ),
    ).toBe(false);
  });

  it('rejects proxy authority where the runtime can represent it', () => {
    const handle = authorize();
    let traps = 0;
    const proxy = new Proxy(issueBody(), {
      ownKeys() {
        traps += 1;
        return ['schemaVersion'];
      },
      get() {
        traps += 1;
        return undefined;
      },
    });
    const proxied = issueFindingRepeatedObservationAuthorization(proxy);
    expect(proxied.status).not.toBe('authorized');
    expect(proxied.authorityCreated).toBe(false);
    expect(traps).toBe(0);
    expect(openFindingRepeatedObservationCommand(commandBody(new Proxy(handle, {}))).status).toBe(
      'authority_rejected',
    );
    const command = sealCommand(handle);
    expect(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context(),
        command: new Proxy(command, {}),
      }).status,
    ).toBe('authority_rejected');
    let evidenceTraps = 0;
    const evidence = new Proxy([EVIDENCE_A], {
      ownKeys() {
        evidenceTraps += 1;
        return ['0', 'length'];
      },
      get() {
        evidenceTraps += 1;
        return EVIDENCE_A;
      },
    });
    const hostile = parseFindingRepeatedObservationSupport(
      evidenceSupport(evidence as unknown as readonly string[]),
      INGESTION,
    );
    expect(hostile.ok).toBe(false);
    if (!hostile.ok) {
      expect(hostile.reason).toBe('evidence_set_hostile');
    }
    expect(evidenceTraps).toBe(0);
  });

  it('rejects the wrong organization, actor, membership, finding, and target', () => {
    const command = sealCommand();
    const wrongOrganization = presentFindingRepeatedObservationAuthorization({
      trustedContext: context({ organizationId: FOREIGN_ORG }),
      command,
    });
    expect(wrongOrganization.status).toBe('authority_rejected');
    if (wrongOrganization.status === 'authority_rejected') {
      expect(wrongOrganization.reason).toBe('organization_mismatch');
    }
    expect(JSON.stringify(wrongOrganization)).not.toContain(FOREIGN_ORG);
    expect(JSON.stringify(wrongOrganization)).not.toContain(ORG);

    expect(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context({ actorId: OTHER_ACTOR }),
        command,
      }).reason,
    ).toBe('actor_mismatch');
    expect(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context({ membershipId: OTHER_MEMBERSHIP }),
        command,
      }).reason,
    ).toBe('membership_mismatch');

    const handle = authorize();
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { expectedFindingId: OTHER_FINDING }),
      ).reason,
    ).toBe('finding_mismatch');
    expect(
      openFindingRepeatedObservationCommand(commandBody(handle, { expectedAssetId: OTHER_ASSET }))
        .reason,
    ).toBe('asset_mismatch');
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { expectedComponentId: OTHER_COMPONENT }),
      ).reason,
    ).toBe('component_mismatch');
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { expectedVulnerabilityId: OTHER_VULNERABILITY }),
      ).reason,
    ).toBe('vulnerability_mismatch');
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { expectedSbomIngestionId: OTHER_INGESTION }),
      ).reason,
    ).toBe('ingestion_mismatch');
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(handle, { correlationId: OTHER_CORRELATION }),
      ).reason,
    ).toBe('correlation_mismatch');
    expect(
      openFindingRepeatedObservationCommand(commandBody(handle, { purpose: 'observe_finding' }))
        .reason,
    ).toBe('purpose_mismatch');
    expect(
      openFindingRepeatedObservationCommand(commandBody(handle, { policyId: 'other_policy' }))
        .reason,
    ).toBe('policy_mismatch');
  });

  it('rejects changed evidence, unknown-version, and absence bindings', () => {
    const handle = authorize();
    const changedEvidence = openFindingRepeatedObservationCommand(
      commandBody(handle, { support: evidenceSupport([EVIDENCE_A, EVIDENCE_C]) }),
    );
    expect(changedEvidence.status).toBe('evidence_set_mismatch');
    if (changedEvidence.status === 'evidence_set_mismatch') {
      expect(changedEvidence.reason).toBe('evidence_set_mismatch');
    }
    const changedUnknown = openFindingRepeatedObservationCommand(
      commandBody(handle, { support: evidenceSupport([EVIDENCE_A, EVIDENCE_B], [UNKNOWN_A]) }),
    );
    expect(changedUnknown.reason).toBe('unknown_version_set_mismatch');

    const absenceHandle = authorize({ support: absenceSupport() });
    const changedAbsence = openFindingRepeatedObservationCommand(
      commandBody(absenceHandle, {
        support: absenceSupport({ componentCount: 5, occurrenceCardinality: 5 }),
      }),
    );
    expect(changedAbsence.status).toBe('evidence_set_mismatch');
    if (changedAbsence.status === 'evidence_set_mismatch') {
      expect(changedAbsence.reason).toBe('absence_proof_mismatch');
    }
    expect(
      openFindingRepeatedObservationCommand(
        commandBody(absenceHandle, { support: evidenceSupport() }),
      ).reason,
    ).toBe('absence_proof_mismatch');
  });

  it('keeps caller mutation from retargeting a sealed authorization', () => {
    const ids = [EVIDENCE_A, EVIDENCE_B];
    const trusted = context();
    const body = issueBody({ trustedContext: trusted, support: evidenceSupport(ids) });
    const issued = issueFindingRepeatedObservationAuthorization(body);
    expect(issued.status).toBe('authorized');
    if (issued.status !== 'authorized') {
      return;
    }
    ids[0] = EVIDENCE_C;
    ids.push(EVIDENCE_C);
    trusted['organizationId'] = FOREIGN_ORG;
    body['findingId'] = OTHER_FINDING;
    body['correlationId'] = OTHER_CORRELATION;

    const command = sealCommand(issued.authorization);
    expect(command.supportKind).toBe('evidence_set');
    if (command.supportKind !== 'evidence_set') {
      return;
    }
    expect(command.expectedProductMatchEvidenceIds).toEqual([EVIDENCE_A, EVIDENCE_B]);
    expect(Object.isFrozen(command.expectedProductMatchEvidenceIds)).toBe(true);
    expect(() => {
      (command.expectedProductMatchEvidenceIds as string[]).push(EVIDENCE_C);
    }).toThrow(TypeError);
    expect(
      presentFindingRepeatedObservationAuthorization({
        trustedContext: context(),
        command,
      }).status,
    ).toBe('authorized');
  });

  it('classifies exact handle reuse without minting a second authority', () => {
    const handle = authorize();
    const same = classifyFindingRepeatedObservationAuthorizationReuse({
      left: handle,
      right: handle,
    });
    expect(same.status).toBe('authorized');
    if (same.status === 'authorized') {
      expect(same.classification).toBe('exact_reuse');
      expect(same.authorityCreated).toBe(false);
    }
    const other = authorize();
    const distinct = classifyFindingRepeatedObservationAuthorizationReuse({
      left: handle,
      right: other,
    });
    expect(distinct.status).toBe('authorized');
    if (distinct.status === 'authorized') {
      expect(distinct.classification).toBe('distinct_authorization');
    }
  });

  it('rejects ambient role, permission, and inactive membership claims', () => {
    expect(issueFindingRepeatedObservationAuthorization(issueBody({ role: 'owner' })).status).toBe(
      'authority_rejected',
    );
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ permission: 'finding:create_controlled' }),
      ).status,
    ).toBe('authority_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ canInspectFinding: true })).status,
    ).toBe('authority_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ trustedContext: context({ membershipStatus: 'revoked' }) }),
      ).reason,
    ).toBe('membership_inactive');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.membershipAloneIsAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.roleIsAuthority).toBe(false);
  });
});

describe('repeated observation support canonicalization', () => {
  it('rejects an empty evidence set and mixed support variants', () => {
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ support: evidenceSupport([], []) }))
        .reason,
    ).toBe('evidence_set_empty');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: {
            ...evidenceSupport(),
            graphCompleteness: 'complete',
            componentCount: 1,
          },
        }),
      ).reason,
    ).toBe('support_mutually_exclusive');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: {
            ...absenceSupport(),
            productMatchEvidenceIds: [EVIDENCE_A],
          },
        }),
      ).reason,
    ).toBe('support_mutually_exclusive');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: {
            ...absenceSupport(),
            unknownVersionOccurrenceIds: [UNKNOWN_A],
          },
        }),
      ).reason,
    ).toBe('support_mutually_exclusive');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ aggregate: 'affected' })).reason,
    ).toBe('caller_selected_aggregate');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ observationResult: 'present' }))
        .reason,
    ).toBe('caller_selected_result');
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ absenceAuthority: true })).status,
    ).toBe('invalid_command');
  });

  it('rejects unsorted, duplicate, and malformed identifiers', () => {
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_B, EVIDENCE_A]) }),
      ).reason,
    ).toBe('evidence_set_unsorted');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A, EVIDENCE_A]) }),
      ).reason,
    ).toBe('evidence_set_duplicate');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport(['not-a-uuid']) }),
      ).reason,
    ).toBe('evidence_set_malformed');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A], [UNKNOWN_B, UNKNOWN_A]) }),
      ).reason,
    ).toBe('unknown_version_unsorted');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A], [UNKNOWN_A, UNKNOWN_A]) }),
      ).reason,
    ).toBe('unknown_version_duplicate');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: evidenceSupport([EVIDENCE_A], ['not-a-uuid']) }),
      ).reason,
    ).toBe('unknown_version_malformed');
  });

  it('rejects a combined support set above the versioned policy limit', () => {
    const evidenceIds = Array.from({ length: 10 }, (_, index) => supportId(index + 1));
    const unknownIds = Array.from({ length: 7 }, (_, index) => unknownId(index + 1));
    const oversized = issueFindingRepeatedObservationAuthorization(
      issueBody({ support: evidenceSupport(evidenceIds, unknownIds) }),
    );
    expect(oversized.status).toBe('evidence_set_oversized');
    expect(oversized.effects.persistenceWrites).toBe(0);

    const exact = Array.from(
      { length: FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS },
      (_, index) => supportId(index + 1),
    );
    expect(
      issueFindingRepeatedObservationAuthorization(issueBody({ support: evidenceSupport(exact) }))
        .status,
    ).toBe('authorized');
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.findingIdentity).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.observationIdentity).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.permanentDomainMaximum).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT.schemaMaximum).toBe(false);
  });

  it('fingerprints canonical support deterministically without treating equality as authority', () => {
    const left = parseFindingRepeatedObservationSupport(evidenceSupport(), INGESTION);
    const right = parseFindingRepeatedObservationSupport(
      evidenceSupport([EVIDENCE_A, EVIDENCE_B], []),
      INGESTION,
    );
    expect(left.ok).toBe(true);
    expect(right.ok).toBe(true);
    if (
      !left.ok ||
      !right.ok ||
      left.support.kind !== 'evidence_set' ||
      right.support.kind !== 'evidence_set'
    ) {
      return;
    }
    expect(left.support.fingerprint).toBe(right.support.fingerprint);
    expect(left.support.supportCount).toBe(2);
    expect(Object.isFrozen(left.support.productMatchEvidenceIds)).toBe(true);
    const unknownOnly = parseFindingRepeatedObservationSupport(
      evidenceSupport([], [UNKNOWN_A]),
      INGESTION,
    );
    expect(unknownOnly.ok).toBe(true);
    if (unknownOnly.ok && unknownOnly.support.kind === 'evidence_set') {
      expect(unknownOnly.support.fingerprint).not.toBe(left.support.fingerprint);
    }
    expect(
      FINDING_REPEATED_OBSERVATION_INVARIANTS.fingerprintEqualityReplacesSemanticValidation,
    ).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.supportFingerprintIsAuthority).toBe(false);
  });

  it('binds a constrained absence proof without caller absence authority', () => {
    const parsed = parseFindingRepeatedObservationSupport(absenceSupport(), INGESTION);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.support.kind !== 'component_absence') {
      return;
    }
    expect(parsed.support.callerEstablishesAbsence).toBe(false);
    expect(parsed.support.expectedFindingComponentOccurrenceCount).toBe(0);
    expect(parsed.support.normalizationVersion).toBe(2);
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
        issueBody({ support: absenceSupport({ normalizationVersion: 1 }) }),
      ).status,
    ).toBe('unsupported_normalization_version');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({
          support: absenceSupport({ componentCount: 0, occurrenceCardinality: 0 }),
        }),
      ).reason,
    ).toBe('absence_count_rejected');
    expect(
      issueFindingRepeatedObservationAuthorization(
        issueBody({ support: absenceSupport({ expectedFindingComponentOccurrenceCount: 2 }) }),
      ).reason,
    ).toBe('absence_count_rejected');
    expect(FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY.meansRemediated).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY.meansClosed).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY.missingEvidenceIsAbsence).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY.unknownVersionIsAbsence).toBe(false);
  });
});

describe('repeated observation nonauthority', () => {
  it('keeps identity, replay, mutation, and withheld powers closed', () => {
    expect(FINDING_REPEATED_OBSERVATION_NATURAL_IDENTITY_FIELDS).toEqual([
      'organizationId',
      'findingId',
      'sbomIngestionId',
    ]);
    expect(FINDING_REPEATED_OBSERVATION_NON_FINDING_IDENTITY_FIELDS).toEqual(
      expect.arrayContaining([
        'sbomIngestionId',
        'componentOccurrenceId',
        'componentVersion',
        'productMatchEvidenceId',
        'observationResult',
        'aggregate',
        'policyVersion',
        'evidenceFingerprint',
        'actorId',
        'correlationId',
      ]),
    );
    expect(FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS).toContain('aggregate');
    expect(FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS).toContain('replayFingerprint');
    expect(FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS).toContain('correlationId');
    expect(FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS).not.toContain('correlationId');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.correlationIsReplayIdentity).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.correlationIsAuthorizationBinding).toBe(true);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.ingestionIsObservationNaturalIdentity).toBe(
      true,
    );
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.ingestionIsFindingIdentity).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.directMutationAuthority).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.permittedSummaryFields).toEqual([
      'last_observed_at',
      'updated_at',
    ]);
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.deniedFields).toEqual(
      expect.arrayContaining([
        'state',
        'version',
        'first_observed_at',
        'component_occurrence_id',
        'resolved_at',
        'reopened_at',
        'created_at',
      ]),
    );
    expect(FINDING_REPEATED_OBSERVATION_FINDING_MUTATION.stateAfterEveryAggregate).toBe('open');
    expect(FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS.findingCreation).toBe('unavailable');
    expect(FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS.findingClosure).toBe('unavailable');
    expect(FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS.automaticObservation).toBe('unavailable');
    expect(FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS.evaluatorExecution).toBe('unavailable');
    expect(FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.implemented).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.canWriteObservation).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.canUpdateFindingTimestamp).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.canWriteFindingObservedAudit).toBe(
      false,
    );
    expect(FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY.frozenMigrationCount).toBe(24);
    expect(FINDING_REPEATED_OBSERVATION_OUTCOMES).not.toContain('authorized');
    expect(FINDING_REPEATED_OBSERVATION_AGGREGATES).not.toContain('absent');
    expect(mapRepeatedObservationAggregate('affected')).toBe('present');
    expect(mapRepeatedObservationAggregate('unaffected')).toBe('absent');
    expect(mapRepeatedObservationAggregate('unknown')).toBe('inconclusive');
    expect(mapRepeatedObservationAggregate('component_absent')).toBe('absent');
    expect(FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT.unaffected).toBe(
      FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT.component_absent,
    );
    expect(FINDING_REPEATED_OBSERVATION_NON_AGGREGATE_FAILURES).toContain('evidence_unavailable');
    expect(FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS).toContain('organizationId');
    expect(FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS).toContain('lastObservedAt');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.storedAbsentAloneIsProductAggregate).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.unaffectedEqualsComponentAbsent).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.genericSuccessBoolean).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.observationCanBeWritten).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.persistenceImplemented).toBe(false);
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.sliceComplete).toBe(false);
  });
});
