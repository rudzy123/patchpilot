import { describe, expect, it } from 'vitest';

import {
  classifyFindingCreationAuthorizationReuse,
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
  presentFindingCreationAuthorization,
  type FindingCreationAuthorizationHandle,
  type SealedFindingCreationCommand,
} from './authorization.js';
import { parseFindingCreationEvidenceSet } from './evidence-set.js';
import {
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_EVIDENCE_REQUIREMENTS,
  FINDING_CREATION_EXCEPTION_ID,
  FINDING_CREATION_GENERIC_PURPOSES,
  FINDING_CREATION_INVARIANTS,
  FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
  FINDING_CREATION_NON_IDENTITY_FIELDS,
  FINDING_CREATION_NORMALIZATION_VERSION,
  FINDING_CREATION_OUTCOMES,
  FINDING_CREATION_PERSISTENCE_BOUNDARY,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PROHIBITED_COMMAND_FIELDS,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_CREATION_TARGET_FIELDS,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_CREATION_WITHHELD_POWERS,
  FINDING_CREATION_ZERO_EFFECTS,
} from './policy.js';
import { classifyFindingCreationReplay } from './replay.js';
import {
  FINDING_CREATION_COMPLETE_SET_RULES,
  FINDING_CREATION_EVIDENCE_ELIGIBILITY_IMPLEMENTED,
} from './eligibility.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';
const EVIDENCE_C = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CORRELATION = '10101010-1010-4101-8101-101010101010';
const FOREIGN_ORG = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OTHER_ACTOR = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const OTHER_MEMBERSHIP = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const OTHER_ASSET = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const OTHER_COMPONENT = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const OTHER_VULNERABILITY = '12121212-1212-4121-8121-121212121212';
const OTHER_INGESTION = '14141414-1414-4141-8141-141414141414';
const OTHER_CORRELATION = '13131313-1313-4131-8131-131313131313';

const UUID_TEXT = /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/;

function context(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: ORG,
    actorId: ACTOR,
    membershipId: MEMBERSHIP,
    membershipStatus: 'active',
    ...overrides,
  };
}

function issueBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext: context(),
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: INGESTION,
    productMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    correlationId: CORRELATION,
    ...overrides,
  };
}

function commandBody(
  authorization: unknown,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: ASSET,
    expectedComponentId: COMPONENT,
    expectedVulnerabilityId: VULNERABILITY,
    expectedSbomIngestionId: INGESTION,
    expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    correlationId: CORRELATION,
    authorization,
    ...overrides,
  };
}

function authorize(overrides: Record<string, unknown> = {}): FindingCreationAuthorizationHandle {
  const issued = issueFindingCreationAuthorization(issueBody(overrides));
  expect(issued.status).toBe('authorized');
  if (issued.status !== 'authorized') {
    throw new Error('authorization was not issued');
  }
  return issued.authorization;
}

function sealCommand(
  authorization: FindingCreationAuthorizationHandle = authorize(),
  overrides: Record<string, unknown> = {},
): SealedFindingCreationCommand {
  const opened = openFindingCreationCommand(commandBody(authorization, overrides));
  expect(opened.status).toBe('authorized');
  if (opened.status !== 'authorized') {
    throw new Error('command was not sealed');
  }
  return opened.command;
}

function evidenceId(index: number): string {
  return `88888888-8888-4888-8888-${index.toString(16).padStart(12, '0')}`;
}

describe('controlled finding creation authorization', () => {
  it('issues and presents one exact purpose-specific authorization', () => {
    const issued = issueFindingCreationAuthorization(issueBody());
    expect(issued.status).toBe('authorized');
    if (issued.status !== 'authorized') {
      return;
    }
    expect(issued.authorityCreated).toBe(true);
    expect(issued.authorityRenewed).toBe(false);
    expect(issued.findingCreation).toBe('not_performed');
    expect(issued.persistence).toBe('not_performed');
    expect(issued.effects).toEqual(FINDING_CREATION_ZERO_EFFECTS);
    expect(issued).not.toHaveProperty('findingId');
    expect(issued).not.toHaveProperty('organizationId');

    const command = sealCommand(issued.authorization);
    const presented = presentFindingCreationAuthorization({
      trustedContext: context(),
      command,
    });
    expect(presented.status).toBe('authorized');
    if (presented.status !== 'authorized') {
      return;
    }
    expect(presented.continuation).toBe('evidence_validation');
    expect(presented.authorityCreated).toBe(false);
    expect(presented.authorityRenewed).toBe(false);
    expect(presented.authorizationReuse).toBe('repeatable');
    expect(presented.effects.findingWrites).toBe(0);
    expect(presented.effects.findingObservationWrites).toBe(0);
    expect(presented.effects.evaluatorCalls).toBe(0);
    expect(presented.effects.productMatchEvidenceWrites).toBe(0);
  });

  it('rejects missing, forged, plain, JSON, cloned, and prototype authority', () => {
    const missing = openFindingCreationCommand(commandBody(null));
    expect(missing.status).toBe('authority_required');

    const plain = openFindingCreationCommand(
      commandBody({
        purpose: FINDING_CREATION_PURPOSE,
        organizationId: ORG,
      }),
    );
    expect(plain.status).toBe('authority_rejected');
    if (plain.status === 'authority_rejected') {
      expect(plain.reason).toBe('authorization_unrecognized');
    }

    const handle = authorize();
    const jsonHandle: unknown = JSON.parse(JSON.stringify(handle));
    expect(openFindingCreationCommand(commandBody(jsonHandle)).status).toBe('authority_rejected');
    expect(openFindingCreationCommand(commandBody(structuredClone(handle))).status).toBe(
      'authority_rejected',
    );

    const copied = Object.assign(Object.create(null) as object, handle);
    expect(openFindingCreationCommand(commandBody(copied)).status).toBe('authority_rejected');
    expect(openFindingCreationCommand(commandBody(Object.create(handle))).status).toBe(
      'authority_rejected',
    );

    const asserted = {} as FindingCreationAuthorizationHandle;
    expect(openFindingCreationCommand(commandBody(asserted)).status).toBe('authority_rejected');

    const command = sealCommand(handle);
    const clonedCommand: unknown = structuredClone(command);
    expect(
      presentFindingCreationAuthorization({
        trustedContext: context(),
        command: clonedCommand,
      }).status,
    ).toBe('authority_rejected');
    expect(JSON.stringify(handle)).not.toMatch(UUID_TEXT);
    expect(JSON.stringify(command)).not.toMatch(UUID_TEXT);
  });

  it('rejects the wrong organization, actor, membership, and target bindings', () => {
    const command = sealCommand();
    const wrongOrganization = presentFindingCreationAuthorization({
      trustedContext: context({ organizationId: FOREIGN_ORG }),
      command,
    });
    expect(wrongOrganization.status).toBe('target_mismatch');
    if (wrongOrganization.status === 'target_mismatch') {
      expect(wrongOrganization.reason).toBe('organization_mismatch');
    }
    expect(JSON.stringify(wrongOrganization)).not.toContain(FOREIGN_ORG);
    expect(JSON.stringify(wrongOrganization)).not.toContain(ORG);

    const wrongActor = presentFindingCreationAuthorization({
      trustedContext: context({ actorId: OTHER_ACTOR }),
      command,
    });
    expect(wrongActor.status).toBe('authority_rejected');
    if (wrongActor.status === 'authority_rejected') {
      expect(wrongActor.reason).toBe('actor_mismatch');
    }

    const wrongMembership = presentFindingCreationAuthorization({
      trustedContext: context({ membershipId: OTHER_MEMBERSHIP }),
      command,
    });
    expect(wrongMembership.status).toBe('authority_rejected');
    if (wrongMembership.status === 'authority_rejected') {
      expect(wrongMembership.reason).toBe('membership_mismatch');
    }

    const handle = authorize();
    expect(
      openFindingCreationCommand(commandBody(handle, { expectedAssetId: OTHER_ASSET })).status,
    ).toBe('target_mismatch');
    expect(
      openFindingCreationCommand(commandBody(handle, { expectedComponentId: OTHER_COMPONENT }))
        .status,
    ).toBe('target_mismatch');
    expect(
      openFindingCreationCommand(
        commandBody(handle, { expectedVulnerabilityId: OTHER_VULNERABILITY }),
      ).status,
    ).toBe('target_mismatch');
    const wrongIngestion = openFindingCreationCommand(
      commandBody(handle, { expectedSbomIngestionId: OTHER_INGESTION }),
    );
    expect(wrongIngestion.status).toBe('evidence_set_mismatch');
    if (wrongIngestion.status === 'evidence_set_mismatch') {
      expect(wrongIngestion.reason).toBe('ingestion_mismatch');
    }
  });

  it('rejects the wrong purpose, policy, and correlation identity', () => {
    expect(issueFindingCreationAuthorization(issueBody({ purpose: 'create_finding' })).status).toBe(
      'authority_rejected',
    );
    expect(
      issueFindingCreationAuthorization(issueBody({ policyId: 'generic_finding_policy' })).status,
    ).toBe('authority_rejected');
    expect(issueFindingCreationAuthorization(issueBody({ policyVersion: 2 })).status).toBe(
      'authority_rejected',
    );
    const handle = authorize();
    const wrongCorrelation = openFindingCreationCommand(
      commandBody(handle, { correlationId: OTHER_CORRELATION }),
    );
    expect(wrongCorrelation.status).toBe('authority_rejected');
    if (wrongCorrelation.status === 'authority_rejected') {
      expect(wrongCorrelation.reason).toBe('correlation_mismatch');
    }
  });

  it('rejects empty, duplicate, unsorted, malformed, oversized, and hostile evidence sets', () => {
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: [] })).status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(
        issueBody({ productMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_A] }),
      ).status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(
        issueBody({ productMatchEvidenceIds: [EVIDENCE_B, EVIDENCE_A] }),
      ).status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: ['not-a-uuid'] }))
        .status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(
        issueBody({ productMatchEvidenceIds: [EVIDENCE_C.toUpperCase()] }),
      ).status,
    ).toBe('invalid_command');

    const oversized = Array.from(
      { length: FINDING_CREATION_MAX_EVIDENCE_SET_SIZE + 1 },
      (_, index) => evidenceId(index),
    );
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: oversized })).status,
    ).toBe('invalid_command');

    const hostile = [EVIDENCE_A];
    Object.defineProperty(hostile, '0', {
      configurable: true,
      enumerable: true,
      get() {
        return EVIDENCE_B;
      },
    });
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: hostile })).status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(
        issueBody({ productMatchEvidenceIds: new Proxy([EVIDENCE_A], {}) }),
      ).status,
    ).toBe('invalid_command');
    const extra = [EVIDENCE_A];
    Object.defineProperty(extra, 'note', { value: 'hostile', enumerable: true });
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: extra })).status,
    ).toBe('invalid_command');
    expect(
      issueFindingCreationAuthorization(
        issueBody({ productMatchEvidenceIds: { 0: EVIDENCE_A, length: 1 } }),
      ).status,
    ).toBe('invalid_command');
  });

  it('keeps the authorized evidence set stable after the caller mutates the input', () => {
    const ids = [EVIDENCE_A, EVIDENCE_B];
    const handle = authorize({ productMatchEvidenceIds: ids });
    const command = sealCommand(handle);
    ids[1] = EVIDENCE_C;
    const changed = openFindingCreationCommand(
      commandBody(handle, { expectedProductMatchEvidenceIds: ids }),
    );
    expect(changed.status).toBe('evidence_set_mismatch');
    expect(presentFindingCreationAuthorization({ trustedContext: context(), command }).status).toBe(
      'authorized',
    );
    expect(() => {
      const stored = command.expectedProductMatchEvidenceIds as string[];
      stored[0] = EVIDENCE_C;
    }).toThrow(TypeError);
  });

  it('binds several affected evidence rows to one versionless component', () => {
    const handle = authorize({ productMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B, EVIDENCE_C] });
    const command = sealCommand(handle, {
      expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B, EVIDENCE_C],
    });
    expect(command.expectedComponentId).toBe(COMPONENT);
    expect(command.expectedProductMatchEvidenceIds).toEqual([EVIDENCE_A, EVIDENCE_B, EVIDENCE_C]);
    expect(command).not.toHaveProperty('componentOccurrenceId');
    expect(command).not.toHaveProperty('occurrenceId');
    expect(presentFindingCreationAuthorization({ trustedContext: context(), command }).status).toBe(
      'authorized',
    );
    expect(FINDING_CREATION_COMPLETE_SET_RULES.unaffectedOccurrenceVetoesAffected).toBe(false);
    expect(FINDING_CREATION_COMPLETE_SET_RULES.severalAffectedOccurrencesShareOneFinding).toBe(
      true,
    );
  });

  it('classifies exact authorization reuse without minting another authorization', () => {
    const handle = authorize();
    const command = sealCommand(handle);
    const first = presentFindingCreationAuthorization({ trustedContext: context(), command });
    const second = presentFindingCreationAuthorization({ trustedContext: context(), command });
    expect(first.status).toBe('authorized');
    expect(second.status).toBe('authorized');
    if (second.status === 'authorized') {
      expect(second.authorityCreated).toBe(false);
      expect(second.authorityRenewed).toBe(false);
    }
    const reuse = classifyFindingCreationAuthorizationReuse({ left: handle, right: handle });
    expect(reuse.status).toBe('authorized');
    if (reuse.status === 'authorized') {
      expect(reuse.classification).toBe('exact_reuse');
      expect(reuse.authorityCreated).toBe(false);
      expect(reuse.authorityRenewed).toBe(false);
    }
    const other = authorize();
    const distinct = classifyFindingCreationAuthorizationReuse({ left: handle, right: other });
    expect(distinct.status).toBe('authorized');
    if (distinct.status === 'authorized') {
      expect(distinct.classification).toBe('distinct_authorization');
      expect(distinct.authorityCreated).toBe(false);
    }
  });

  it('does not treat membership, role, or a trusted context as Finding authority', () => {
    expect(
      presentFindingCreationAuthorization({
        trustedContext: context(),
        command: context(),
      }).status,
    ).toBe('authority_rejected');
    expect(issueFindingCreationAuthorization(issueBody({ role: 'owner' })).status).toBe(
      'authority_rejected',
    );
    expect(
      issueFindingCreationAuthorization({
        ...issueBody(),
        trustedContext: context({ role: 'admin' }),
      }).status,
    ).toBe('authority_rejected');
    expect(
      issueFindingCreationAuthorization({
        ...issueBody(),
        trustedContext: context({ membershipStatus: 'revoked' }),
      }).status,
    ).toBe('authority_rejected');
    expect(issueFindingCreationAuthorization(issueBody({ organizationId: ORG })).status).toBe(
      'invalid_command',
    );
  });

  it('rejects caller-selected Finding fields', () => {
    const handle = authorize();
    for (const field of FINDING_CREATION_PROHIBITED_COMMAND_FIELDS) {
      const rejected = openFindingCreationCommand(commandBody(handle, { [field]: 'selected' }));
      expect(rejected.status, field).toBe('invalid_command');
    }
  });

  it('keeps failure explanations tenant-indistinguishable', () => {
    const failure = presentFindingCreationAuthorization({
      trustedContext: context({ organizationId: FOREIGN_ORG }),
      command: sealCommand(),
    });
    expect(failure.tenantDisclosure).toBe('indistinguishable');
    expect(failure.explanation).not.toMatch(UUID_TEXT);
    expect(JSON.stringify(failure)).not.toContain('existsInOtherOrganization');
    expect(FINDING_CREATION_OUTCOMES).toContain('not_found');
    expect(FINDING_CREATION_OUTCOMES).not.toContain('foreign_found');
  });
});

describe('controlled finding creation contracts', () => {
  it('closes purpose, policy, target, and non-identity fields', () => {
    expect(FINDING_CREATION_EXCEPTION_ID).toBe(
      'controlled_maintainer_reviewed_finding_creation_v1',
    );
    expect(FINDING_CREATION_PURPOSE).toBe('create_finding_from_product_match_evidence');
    expect(FINDING_CREATION_POLICY_ID).toBe('finding_creation_policy_v1');
    expect(FINDING_CREATION_POLICY_VERSION).toBe(1);
    expect(FINDING_CREATION_GENERIC_PURPOSES).not.toContain(FINDING_CREATION_PURPOSE);
    expect(FINDING_CREATION_TARGET_FIELDS).toEqual([
      'organizationId',
      'assetId',
      'componentId',
      'vulnerabilityId',
    ]);
    for (const field of FINDING_CREATION_NON_IDENTITY_FIELDS) {
      expect(FINDING_CREATION_TARGET_FIELDS).not.toContain(field);
    }
    expect(FINDING_CREATION_MAX_EVIDENCE_SET_SIZE).toBe(16);
    expect(FINDING_CREATION_NORMALIZATION_VERSION).toBe(2);
  });

  it('canonicalizes the evidence-set fingerprint without treating it as authority', () => {
    const first = parseFindingCreationEvidenceSet([EVIDENCE_A, EVIDENCE_B]);
    const second = parseFindingCreationEvidenceSet([EVIDENCE_A, EVIDENCE_B]);
    const changed = parseFindingCreationEvidenceSet([EVIDENCE_A, EVIDENCE_C]);
    const unsorted = parseFindingCreationEvidenceSet([EVIDENCE_B, EVIDENCE_A]);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(changed.ok).toBe(true);
    expect(unsorted.ok).toBe(false);
    if (!first.ok || !second.ok || !changed.ok) {
      return;
    }
    expect(first.evidenceSet.fingerprint).toBe(second.evidenceSet.fingerprint);
    expect(first.evidenceSet.fingerprint).not.toBe(changed.evidenceSet.fingerprint);
    expect(first.evidenceSet.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(FINDING_CREATION_INVARIANTS.fingerprintEqualityReplacesSemanticValidation).toBe(false);
    expect(FINDING_CREATION_INVARIANTS.evidenceSetFingerprintIsAuthority).toBe(false);
  });

  it('classifies exact replay separately from another ingestion or a natural-key collision', () => {
    const agreement = {
      schemaVersion: FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
      findingPresent: true,
      creationObservationPresent: true,
      evidenceLinksComplete: true,
      naturalIdentityAgrees: true,
      purposeAgrees: true,
      policyAgrees: true,
      evidenceFingerprintAgrees: true,
      ingestionAgrees: true,
      linkSetAgrees: true,
      persistedStateWellFormed: true,
    };
    const exact = classifyFindingCreationReplay(agreement);
    expect(exact.classification).toBe('already_applied');
    expect(exact.writes).toBe(false);
    expect(exact.timestampChanged).toBe(false);
    expect(exact.observationAdded).toBe(false);
    expect(exact.auditEventAdded).toBe(false);
    expect(exact.authorityCreated).toBe(false);

    const conflict = classifyFindingCreationReplay({
      ...agreement,
      evidenceFingerprintAgrees: false,
      linkSetAgrees: false,
    });
    expect(conflict.classification).toBe('immutable_conflict');
    expect(conflict.writes).toBe(false);

    const otherIngestion = classifyFindingCreationReplay({
      ...agreement,
      ingestionAgrees: false,
    });
    expect(otherIngestion.classification).toBe('finding_already_exists');
    expect(otherIngestion.outcome).not.toBe('already_applied');

    const collision = classifyFindingCreationReplay({
      ...agreement,
      creationObservationPresent: false,
      evidenceLinksComplete: false,
      evidenceFingerprintAgrees: true,
      linkSetAgrees: true,
    });
    expect(collision.classification).toBe('finding_already_exists');

    const absent = classifyFindingCreationReplay({
      ...agreement,
      findingPresent: false,
      creationObservationPresent: false,
      evidenceLinksComplete: false,
    });
    expect(absent.classification).toBe('not_persisted');
    expect(absent.outcome).not.toBe('created');
    expect(absent.writes).toBe(false);

    const rejected = classifyFindingCreationReplay({ schemaVersion: 'other' });
    expect(rejected.classification).toBe('comparison_rejected');
    expect(rejected.outcome).toBe('invalid_command');
    expect(rejected.writes).toBe(false);
  });

  it('withholds evaluator, evidence-write, persistence, and lifecycle authority', () => {
    expect(FINDING_CREATION_WITHHELD_POWERS.evaluatorExecution).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.productMatchEvidenceCreation).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.providerContact).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.findingStateTransitions).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.riskCalculation).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.priority).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.assignment).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.suppression).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.remediation).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.verification).toBe('unavailable');
    expect(FINDING_CREATION_WITHHELD_POWERS.aiAuthority).toBe('unavailable');
    expect(FINDING_CREATION_EVIDENCE_ELIGIBILITY_IMPLEMENTED).toBe(false);
    expect(FINDING_CREATION_PERSISTENCE_BOUNDARY.implemented).toBe(false);
    expect(FINDING_CREATION_PERSISTENCE_BOUNDARY.evidenceLinkMigrationImplemented).toBe(false);
    expect(FINDING_CREATION_PERSISTENCE_BOUNDARY.productionComposition).toBe('absent');
    expect(FINDING_CREATION_PERSISTENCE_BOUNDARY.durableCreationAuthorityTable).toBe(false);
    expect(FINDING_CREATION_INVARIANTS.findingCanBeCreated).toBe(false);
    expect(FINDING_CREATION_EVIDENCE_REQUIREMENTS).toContain('outcome_affected');
    expect(FINDING_CREATION_EVIDENCE_REQUIREMENTS).toContain('non_synthetic');
    expect(FINDING_CREATION_EVIDENCE_REQUIREMENTS).toContain(
      'normalization_version_2_completed_graph',
    );
    expect(FINDING_CREATION_COMPLETE_SET_RULES.subsetFailsClosed).toBe(true);
    expect(FINDING_CREATION_COMPLETE_SET_RULES.supersetFailsClosed).toBe(true);
  });
});
