import { inspect } from 'node:util';

import { describe, expect, it } from 'vitest';

import {
  classifyFindingCreationAuthorizationReuse,
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
  presentFindingCreationAuthorization,
  type FindingCreationAuthorizationHandle,
  type SealedFindingCreationCommand,
} from './authorization.js';
import { evidenceSetsMatch, parseFindingCreationEvidenceSet } from './evidence-set.js';
import {
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_EVIDENCE_SET_LIMIT,
  FINDING_CREATION_INVARIANTS,
  FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_CREATION_ZERO_EFFECTS,
} from './policy.js';
import { classifyFindingCreationReplay } from './replay.js';

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

function replayAgreement(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
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
    ...overrides,
  };
}

describe('controlled finding authority adversarial review', () => {
  it('rejects proxy, spread, descriptor-copy, and revoked-proxy forgeries', () => {
    const handle = authorize();
    const command = sealCommand(handle);
    let proxyTraps = 0;
    const proxy = new Proxy(issueBody(), {
      ownKeys() {
        proxyTraps += 1;
        return ['schemaVersion'];
      },
      get() {
        proxyTraps += 1;
        return undefined;
      },
    });
    const proxiedIssue = issueFindingCreationAuthorization(proxy);
    expect(proxiedIssue.status).not.toBe('authorized');
    expect(proxiedIssue.authorityCreated).toBe(false);
    expect(proxiedIssue.effects).toEqual(FINDING_CREATION_ZERO_EFFECTS);
    expect(proxyTraps).toBe(0);

    const { proxy: revoked, revoke } = Proxy.revocable(issueBody(), {});
    revoke();
    const revokedIssue = issueFindingCreationAuthorization(revoked);
    expect(revokedIssue.status).toBe('invalid_command');
    expect(revokedIssue.authorityCreated).toBe(false);

    const handleProxy = new Proxy(handle, {});
    expect(openFindingCreationCommand(commandBody(handleProxy)).status).toBe('authority_rejected');
    expect(openFindingCreationCommand(commandBody({ ...handle })).status).toBe(
      'authority_rejected',
    );

    const copied = Object.create(null) as object;
    Object.defineProperties(copied, Object.getOwnPropertyDescriptors(command));
    expect(
      presentFindingCreationAuthorization({ trustedContext: context(), command: copied }).status,
    ).toBe('authority_rejected');
    expect(presentFindingCreationAuthorization({ trustedContext: context(), command }).status).toBe(
      'authorized',
    );

    const extracted = Object.getOwnPropertyDescriptor(command, 'authorization')?.value;
    expect(
      openFindingCreationCommand(commandBody(extracted, { expectedAssetId: OTHER_ASSET })).status,
    ).toBe('target_mismatch');
  });

  it('does not invoke evidence-set traps and rejects a revoked evidence proxy', () => {
    let traps = 0;
    const evidence = new Proxy([EVIDENCE_A], {
      ownKeys() {
        traps += 1;
        return ['0', 'length'];
      },
      get() {
        traps += 1;
        return EVIDENCE_A;
      },
    });
    const parsed = parseFindingCreationEvidenceSet(evidence);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.reason).toBe('evidence_set_hostile');
    }
    expect(traps).toBe(0);

    const { proxy, revoke } = Proxy.revocable([EVIDENCE_A], {});
    revoke();
    const revoked = parseFindingCreationEvidenceSet(proxy);
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) {
      expect(revoked.reason).toBe('evidence_set_hostile');
    }
  });

  it('keeps caller mutation from retargeting a sealed authorization', () => {
    const ids = [EVIDENCE_A, EVIDENCE_B];
    const trusted = context();
    const body = issueBody({
      trustedContext: trusted,
      productMatchEvidenceIds: ids,
    });
    const issued = issueFindingCreationAuthorization(body);
    expect(issued.status).toBe('authorized');
    if (issued.status !== 'authorized') {
      return;
    }
    ids[0] = EVIDENCE_C;
    ids.push(EVIDENCE_C);
    trusted['organizationId'] = FOREIGN_ORG;
    trusted['actorId'] = OTHER_ACTOR;
    body['assetId'] = OTHER_ASSET;
    body['correlationId'] = OTHER_CORRELATION;
    body['sbomIngestionId'] = OTHER_INGESTION;

    const command = sealCommand(issued.authorization);
    expect(
      presentFindingCreationAuthorization({
        trustedContext: context(),
        command,
      }).status,
    ).toBe('authorized');
    expect(
      presentFindingCreationAuthorization({
        trustedContext: context({ organizationId: FOREIGN_ORG }),
        command,
      }).status,
    ).toBe('target_mismatch');
    expect(
      openFindingCreationCommand(
        commandBody(issued.authorization, { expectedAssetId: OTHER_ASSET }),
      ).status,
    ).toBe('target_mismatch');
    expect(String(issued.authorization)).not.toMatch(UUID_TEXT);
    expect(inspect(issued.authorization)).not.toMatch(UUID_TEXT);
    expect(String(command)).not.toMatch(UUID_TEXT);
    expect(inspect(command, { showHidden: true })).not.toMatch(UUID_TEXT);
    expect(JSON.stringify(command)).not.toMatch(UUID_TEXT);
  });

  it('rejects subset, superset, and over-limit evidence without using fingerprint equality', () => {
    const handle = authorize();
    const subset = openFindingCreationCommand(
      commandBody(handle, { expectedProductMatchEvidenceIds: [EVIDENCE_A] }),
    );
    expect(subset.status).toBe('evidence_set_mismatch');
    const superset = openFindingCreationCommand(
      commandBody(handle, {
        expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B, EVIDENCE_C],
      }),
    );
    expect(superset.status).toBe('evidence_set_mismatch');

    const exact = Array.from({ length: FINDING_CREATION_MAX_EVIDENCE_SET_SIZE }, (_, index) =>
      evidenceId(index),
    );
    const oversized = [...exact, evidenceId(FINDING_CREATION_MAX_EVIDENCE_SET_SIZE)];
    const accepted = parseFindingCreationEvidenceSet(exact);
    const rejected = parseFindingCreationEvidenceSet(oversized);
    expect(accepted.ok).toBe(true);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) {
      expect(rejected.reason).toBe('evidence_set_oversized');
    }
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: oversized })).reason,
    ).toBe('evidence_set_oversized');

    expect(FINDING_CREATION_EVIDENCE_SET_LIMIT).toMatchObject({
      policyId: FINDING_CREATION_POLICY_ID,
      policyVersion: 1,
      maxSize: 16,
      classification: 'implementation_policy_limit',
      findingProductIdentity: false,
      permanentDomainMaximum: false,
      schemaConstraint: false,
      firstSliceSufficient: true,
    });

    expect(accepted.ok).toBe(true);
    if (!accepted.ok) {
      return;
    }
    expect(
      issueFindingCreationAuthorization(issueBody({ productMatchEvidenceIds: exact })).status,
    ).toBe('authorized');
    const tampered = {
      ids: exact.map((id, index) => (index === exact.length - 1 ? evidenceId(200) : id)),
      fingerprint: accepted.evidenceSet.fingerprint,
    };
    expect(tampered.fingerprint).toBe(accepted.evidenceSet.fingerprint);
    expect(evidenceSetsMatch(accepted.evidenceSet, tampered)).toBe(false);
    expect(
      openFindingCreationCommand(commandBody(handle, { authorization: accepted.evidenceSet }))
        .status,
    ).not.toBe('authorized');
    expect(FINDING_CREATION_INVARIANTS.fingerprintEqualityReplacesSemanticValidation).toBe(false);
    expect(FINDING_CREATION_INVARIANTS.correlationIsReplayIdentity).toBe(false);
    expect(FINDING_CREATION_INVARIANTS.correlationIsAuthorizationBinding).toBe(true);
  });

  it('treats command fields as conflict checks and ignores ambient authority', () => {
    const handle = authorize();
    const command = sealCommand(handle);
    const spread = {
      ...command,
      authorization: { purpose: FINDING_CREATION_PURPOSE, organizationId: ORG },
    };
    expect(openFindingCreationCommand(spread).status).toBe('authority_rejected');
    expect(
      presentFindingCreationAuthorization({ trustedContext: context(), command: spread }).status,
    ).toBe('authority_rejected');
    expect(openFindingCreationCommand(commandBody(handle, { policyVersion: '1' })).status).toBe(
      'authority_rejected',
    );
    for (const claim of ['administrator', 'permissions', 'isAdmin', 'canCreateFinding'] as const) {
      expect(issueFindingCreationAuthorization(issueBody({ [claim]: true })).status).toBe(
        'authority_rejected',
      );
    }
    expect(
      issueFindingCreationAuthorization(
        issueBody({ trustedContext: context({ membershipStatus: 'Active' }) }),
      ).status,
    ).not.toBe('authorized');
    expect(
      presentFindingCreationAuthorization({
        trustedContext: context({ membershipId: OTHER_MEMBERSHIP }),
        command: sealCommand(handle),
      }).status,
    ).toBe('authority_rejected');
    let getterReads = 0;
    const hostile = issueBody();
    Object.defineProperty(hostile, 'assetId', {
      enumerable: true,
      get() {
        getterReads += 1;
        return ASSET;
      },
    });
    expect(issueFindingCreationAuthorization(hostile).status).toBe('invalid_command');
    expect(getterReads).toBe(0);
  });

  it('classifies replay without using correlation as product identity', () => {
    const exact = classifyFindingCreationReplay(replayAgreement());
    expect(exact.classification).toBe('already_applied');
    expect(exact.writes).toBe(false);
    expect(exact.authorityCreated).toBe(false);

    const correlated = classifyFindingCreationReplay(
      replayAgreement({ correlationId: OTHER_CORRELATION }),
    );
    expect(correlated.classification).toBe('comparison_rejected');
    expect(correlated.outcome).toBe('invalid_command');
    expect(exact.classification).toBe('already_applied');

    const otherIngestion = classifyFindingCreationReplay(
      replayAgreement({ ingestionAgrees: false }),
    );
    expect(otherIngestion.classification).toBe('finding_already_exists');
    expect(otherIngestion.outcome).not.toBe('created');
    expect(otherIngestion.writes).toBe(false);
    expect(otherIngestion.observationAdded).toBe(false);

    const conflict = classifyFindingCreationReplay(
      replayAgreement({ evidenceFingerprintAgrees: false, linkSetAgrees: false }),
    );
    expect(conflict.classification).toBe('immutable_conflict');
    expect(conflict.writes).toBe(false);

    const malformedInput = classifyFindingCreationReplay(
      replayAgreement({ findingPresent: 'yes' }),
    );
    expect(malformedInput.classification).toBe('comparison_rejected');
    expect(malformedInput.outcome).toBe('invalid_command');

    const corruptAbsence = classifyFindingCreationReplay(
      replayAgreement({
        findingPresent: false,
        creationObservationPresent: false,
        evidenceLinksComplete: false,
        persistedStateWellFormed: false,
      }),
    );
    expect(corruptAbsence.classification).toBe('malformed_persisted_state');
    expect(corruptAbsence.writes).toBe(false);

    const orphan = classifyFindingCreationReplay(
      replayAgreement({ findingPresent: false, creationObservationPresent: true }),
    );
    expect(orphan.classification).toBe('malformed_persisted_state');

    const split = classifyFindingCreationReplay(
      replayAgreement({ evidenceFingerprintAgrees: true, linkSetAgrees: false }),
    );
    expect(split.classification).toBe('malformed_persisted_state');

    const absent = classifyFindingCreationReplay(
      replayAgreement({
        findingPresent: false,
        creationObservationPresent: false,
        evidenceLinksComplete: false,
      }),
    );
    expect(absent.classification).toBe('not_persisted');
    expect(absent.outcome).not.toBe('created');

    const { proxy, revoke } = Proxy.revocable(replayAgreement(), {});
    revoke();
    expect(classifyFindingCreationReplay(proxy).classification).toBe('comparison_rejected');
  });

  it('keeps authorization failures free of foreign and home resource identifiers', () => {
    const command = sealCommand();
    const foreign = presentFindingCreationAuthorization({
      trustedContext: context({ organizationId: FOREIGN_ORG }),
      command,
    });
    const absent = presentFindingCreationAuthorization({
      trustedContext: context(),
      command: { ...command, authorization: {} },
    });
    const unrecognized = openFindingCreationCommand(commandBody({}));
    for (const failure of [foreign, absent, unrecognized]) {
      expect(failure.tenantDisclosure).toBe('indistinguishable');
      expect(failure.authorityCreated).toBe(false);
      expect(failure.findingCreation).toBe('not_performed');
      expect(failure.persistence).toBe('not_performed');
      const encoded = JSON.stringify(failure);
      expect(encoded).not.toMatch(UUID_TEXT);
      expect(encoded).not.toContain(ORG);
      expect(encoded).not.toContain(FOREIGN_ORG);
      expect(encoded).not.toContain('existsInOtherOrganization');
      expect(encoded).not.toContain('foreign_found');
    }
    expect(foreign.status).not.toBe('authorized');
    expect(absent.status).toBe('authority_rejected');
    const reuse = classifyFindingCreationAuthorizationReuse({ left: command, right: command });
    expect(reuse.status).toBe('authority_rejected');
    expect(reuse.authorityCreated).toBe(false);
  });
});
