/**
 * Discovery page, permission, cursor, and acknowledgement contracts.
 * These tests do not open a database or call the creation issuer.
 */

import { describe, expect, it } from 'vitest';

import { parseFindingCreationEvidenceSet } from '../controlled-creation/evidence-set.js';
import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
} from '../controlled-creation/policy.js';
import { encodeFindingDiscoveryCursor, decodeFindingDiscoveryCursor } from './cursor.js';
import { assembleFindingDiscoveryPage, type FindingDiscoveryCandidate } from './page.js';
import {
  FINDING_DISCOVER_CONTROLLED_PERMISSION,
  controlledFindingDiscoveryPermissionsForRole,
} from './permissions.js';
import type {
  FindingDiscoveryLineageFact,
  FindingDiscoveryPairFact,
  FindingDiscoveryRead,
} from './port.js';
import { createControlledFindingDiscoveryApplication } from './service.js';

const ORG = '22222222-2222-4222-8222-222222222222';
const USER = '11111111-1111-4111-8111-111111111111';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT_A = '55555555-5555-4555-8555-555555555551';
const COMPONENT_B = '55555555-5555-4555-8555-555555555552';
const COMPONENT_C = '55555555-5555-4555-8555-555555555553';
const VULN_A = '66666666-6666-4666-8666-666666666661';
const VULN_B = '66666666-6666-4666-8666-666666666662';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const OTHER_INGESTION = '77777777-7777-4777-8777-777777777778';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888881';
const EVIDENCE_B = '88888888-8888-4888-8888-888888888882';
const EVIDENCE_C = '99999999-9999-4999-8999-999999999991';
const FINDING = 'abababab-abab-4bab-8bab-abababababab';

function actor(role: 'owner' | 'admin' | 'member' | 'viewer') {
  return {
    userId: USER,
    sessionId: 'session-1',
    organizationId: ORG,
    membershipId: MEMBERSHIP,
    role,
    permissions: ['finding:read', 'finding:triage', 'finding:inspect', 'finding:create_controlled'],
  };
}

function pair(
  componentId: string,
  vulnerabilityId: string,
  evidence: ReadonlyArray<{ id: string; version: string | null }>,
  extras?: Partial<FindingDiscoveryPairFact>,
): FindingDiscoveryPairFact {
  return {
    componentId,
    vulnerabilityId,
    vulnerabilityPublicId: 'REVIEWED-EXAMPLE',
    qualifyingCount: evidence.length,
    qualifying: evidence.map((row) => ({
      id: row.id,
      occurrenceId: row.id,
      version: row.version,
    })),
    otherOccurrenceCount: 0,
    lineage: null,
    ...extras,
  };
}

function ready(
  pairs: readonly FindingDiscoveryPairFact[],
  continues = false,
  ingestionId: string | null = INGESTION,
): Extract<FindingDiscoveryRead, { status: 'ready' }> {
  return { status: 'ready', ingestionId, pairs, pairSpaceContinues: continues };
}

function lineage(
  evidenceIds: readonly string[],
  ingestionId = INGESTION,
  patch?: Partial<FindingDiscoveryLineageFact>,
): FindingDiscoveryLineageFact {
  const parsed = parseFindingCreationEvidenceSet([...evidenceIds]);
  if (!parsed.ok) {
    throw new Error('lineage evidence');
  }
  return {
    findingId: FINDING,
    state: 'open',
    componentOccurrenceId: null,
    resolvedAt: null,
    reopenedAt: null,
    assignedMembershipId: null,
    assignedTeamId: null,
    dueAt: null,
    currentRiskCalculationId: null,
    version: 1,
    observationCount: 1,
    observation: {
      method: 'controlled_finding_creation',
      result: 'present',
      occurrenceId: null,
      transitionClassification: 'initial_creation',
      creationPurpose: FINDING_CREATION_PURPOSE,
      creationPolicyId: FINDING_CREATION_POLICY_ID,
      creationPolicyVersion: FINDING_CREATION_POLICY_VERSION,
      replayFingerprint: parsed.evidenceSet.fingerprint,
      affectedEvidenceCount: evidenceIds.length,
      sbomIngestionId: ingestionId,
    },
    linkEvidenceIds: [...evidenceIds],
    ...patch,
  };
}

describe('controlled finding discovery permission', () => {
  it('grants discovery to owner and admin only', () => {
    expect(FINDING_DISCOVER_CONTROLLED_PERMISSION).toBe('finding:discover_controlled');
    expect(controlledFindingDiscoveryPermissionsForRole('owner')).toEqual([
      'finding:discover_controlled',
    ]);
    expect(controlledFindingDiscoveryPermissionsForRole('admin')).toEqual([
      'finding:discover_controlled',
    ]);
    expect(controlledFindingDiscoveryPermissionsForRole('member')).toEqual([]);
    expect(controlledFindingDiscoveryPermissionsForRole('viewer')).toEqual([]);
  });

  it('does not read storage for member, viewer, or substitute permissions', async () => {
    let reads = 0;
    const application = createControlledFindingDiscoveryApplication({
      discovery: {
        async read() {
          reads += 1;
          return ready([]);
        },
      },
    });
    for (const role of ['member', 'viewer'] as const) {
      const result = await application.execute({
        actor: actor(role),
        assetId: ASSET,
        limit: 10,
        cursor: null,
      });
      expect(result).toEqual({ status: 'authority_required' });
    }
    expect(reads).toBe(0);
  });
});

describe('controlled finding discovery page', () => {
  it('returns one sorted acknowledgement for several affected versions', () => {
    const assembled = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready([
        pair(
          COMPONENT_A,
          VULN_A,
          [
            { id: EVIDENCE_B, version: '1.2.0' },
            { id: EVIDENCE_A, version: '1.1.0' },
          ],
          { otherOccurrenceCount: 1 },
        ),
        pair(COMPONENT_B, VULN_A, []),
      ]),
    });
    expect(assembled.status).toBe('page');
    if (assembled.status !== 'page') {
      return;
    }
    expect(assembled.page.candidates).toHaveLength(1);
    expect(assembled.page.oversizedCandidateCount).toBe(0);
    expect(assembled.page.nextCursor).toBeNull();
    const candidate = assembled.page.candidates[0];
    expect(candidate?.classification).toBe('eligible_for_creation');
    if (candidate?.classification !== 'eligible_for_creation') {
      return;
    }
    expect(candidate.acknowledgement.expectedProductMatchEvidenceIds).toEqual([
      EVIDENCE_A,
      EVIDENCE_B,
    ]);
    expect(candidate.affectedOccurrenceCount).toBe(2);
    expect(candidate.affectedVersions.values).toEqual(['1.1.0', '1.2.0']);
    expect(candidate.otherOccurrenceCount).toBe(1);
    expect(candidate.explanationCodes).toEqual([
      'several_affected_occurrences',
      'other_occurrences_present',
    ]);
    expect(JSON.stringify(candidate)).not.toContain(FINDING);
    expect('findingId' in candidate).toBe(false);
  });

  it('classifies exact replay and a changed lineage without an acknowledgement or Finding id', () => {
    const exact = pair(COMPONENT_A, VULN_A, [{ id: EVIDENCE_A, version: '1.1.0' }], {
      lineage: lineage([EVIDENCE_A]),
    });
    const changed = pair(COMPONENT_B, VULN_A, [{ id: EVIDENCE_C, version: '1.4.0' }], {
      lineage: lineage([EVIDENCE_A], OTHER_INGESTION),
    });
    const assembled = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready([exact, changed]),
    });
    expect(assembled.status).toBe('page');
    if (assembled.status !== 'page') {
      return;
    }
    const [first, second] = assembled.page.candidates;
    expect(first?.classification).toBe('exact_replay_available');
    expect(second?.classification).toBe('existing_finding');
    if (
      first?.classification !== 'exact_replay_available' ||
      second?.classification !== 'existing_finding'
    ) {
      return;
    }
    expect(first.acknowledgement.expectedProductMatchEvidenceIds).toEqual([EVIDENCE_A]);
    expect('acknowledgement' in second).toBe(false);
    expect(second.lifecycleUpdate).toBe('unavailable');
    expect(second.explanationCodes).toContain('lifecycle_update_unavailable');
    expect(JSON.stringify(assembled.page)).not.toContain(FINDING);
  });

  it('fails the whole page when examined lineage is malformed', () => {
    const assembled = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready([
        pair(COMPONENT_A, VULN_A, [{ id: EVIDENCE_A, version: '1.1.0' }]),
        pair(COMPONENT_B, VULN_A, [{ id: EVIDENCE_C, version: '1.2.0' }], {
          lineage: lineage([EVIDENCE_C], INGESTION, { version: 2 }),
        }),
      ]),
    });
    expect(assembled).toEqual({ status: 'malformed_persisted_state' });
  });

  it('omits an oversized set without its identities', () => {
    const assembled = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready([
        {
          componentId: COMPONENT_A,
          vulnerabilityId: VULN_A,
          vulnerabilityPublicId: null,
          qualifyingCount: 17,
          qualifying: [],
          otherOccurrenceCount: 0,
          lineage: null,
        },
      ]),
    });
    expect(assembled.status).toBe('page');
    if (assembled.status !== 'page') {
      return;
    }
    expect(assembled.page.candidates).toEqual([]);
    expect(assembled.page.oversizedCandidateCount).toBe(1);
    expect(JSON.stringify(assembled.page)).not.toContain(COMPONENT_A);
    expect(JSON.stringify(assembled.page)).not.toContain(VULN_A);
  });

  it('pages in component and vulnerability order without duplicates', () => {
    const pairs = [
      pair(COMPONENT_A, VULN_A, [{ id: EVIDENCE_A, version: '1.0.1' }]),
      pair(COMPONENT_A, VULN_B, [{ id: EVIDENCE_B, version: '1.0.2' }]),
      pair(COMPONENT_C, VULN_A, [{ id: EVIDENCE_C, version: '1.0.3' }]),
    ];
    const first = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 1,
      read: ready(pairs, false),
    });
    expect(first.status).toBe('page');
    if (first.status !== 'page' || first.page.nextCursor === null) {
      throw new Error('cursor');
    }
    expect(first.page.candidates.map((candidate) => candidate.componentId)).toEqual([COMPONENT_A]);
    const decoded = decodeFindingDiscoveryCursor(first.page.nextCursor);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) {
      return;
    }
    expect(decoded.cursor).toEqual({
      ingestionId: INGESTION,
      componentId: COMPONENT_A,
      vulnerabilityId: VULN_A,
    });
    const rest = pairs.filter(
      (candidate) =>
        candidate.componentId > decoded.cursor.componentId ||
        (candidate.componentId === decoded.cursor.componentId &&
          candidate.vulnerabilityId > decoded.cursor.vulnerabilityId),
    );
    const second = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready(rest),
    });
    expect(second.status).toBe('page');
    if (second.status !== 'page') {
      return;
    }
    const ids = [...first.page.candidates.map(identity), ...second.page.candidates.map(identity)];
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual([
      `${COMPONENT_A}:${VULN_A}`,
      `${COMPONENT_A}:${VULN_B}`,
      `${COMPONENT_C}:${VULN_A}`,
    ]);
  });

  it('counts a version that fails the display rule as truncated and keeps the occurrence', () => {
    const assembled = assembleFindingDiscoveryPage({
      assetId: ASSET,
      limit: 10,
      read: ready([pair(COMPONENT_A, VULN_A, [{ id: EVIDENCE_A, version: '1.1.0\u0000' }])]),
    });
    expect(assembled.status).toBe('page');
    if (assembled.status !== 'page') {
      return;
    }
    const candidate = assembled.page.candidates[0];
    expect(candidate?.affectedOccurrenceCount).toBe(1);
    expect(candidate?.affectedVersions).toEqual({
      values: [],
      truncated: true,
      omittedDistinctCount: 1,
      distinctCount: 1,
    });
  });
});

describe('controlled finding discovery cursor', () => {
  it('rejects an empty, unknown, or oversized cursor before a read', async () => {
    let reads = 0;
    const application = createControlledFindingDiscoveryApplication({
      discovery: {
        async read() {
          reads += 1;
          return ready([]);
        },
      },
    });
    const empty = await application.execute({
      actor: actor('owner'),
      assetId: ASSET,
      limit: 10,
      cursor: '',
    });
    const huge = await application.execute({
      actor: actor('admin'),
      assetId: ASSET,
      limit: 10,
      cursor: 'a'.repeat(4097),
    });
    expect(empty.status).toBe('invalid_request');
    expect(huge.status).toBe('invalid_request');
    expect(reads).toBe(0);
    const encoded = encodeFindingDiscoveryCursor({
      ingestionId: INGESTION,
      componentId: COMPONENT_A,
      vulnerabilityId: VULN_A,
    });
    expect(decodeFindingDiscoveryCursor(encoded).ok).toBe(true);
    expect(decodeFindingDiscoveryCursor(`${encoded}!`).ok).toBe(false);
  });

  it('uses the session organization and does not accept a caller organization', async () => {
    const seen: string[] = [];
    const application = createControlledFindingDiscoveryApplication({
      discovery: {
        async read(query) {
          seen.push(query.organizationId);
          return { status: 'not_found' };
        },
      },
    });
    const result = await application.execute({
      actor: { ...actor('owner'), organizationId: ORG },
      assetId: ASSET,
      limit: 10,
      cursor: null,
    });
    expect(result).toEqual({ status: 'not_found' });
    expect(seen).toEqual([ORG]);
  });
});

function identity(candidate: FindingDiscoveryCandidate): string {
  return `${candidate.componentId}:${candidate.vulnerabilityId}`;
}
