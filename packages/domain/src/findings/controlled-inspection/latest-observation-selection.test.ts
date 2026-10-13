/**
 * Pure latest-observation selection.
 * These tests do not open a database or a clock.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseFindingCreationEvidenceSet } from '../controlled-creation/evidence-set.js';
import { FINDING_REPEATED_OBSERVATION_INVARIANTS } from '../controlled-observation/policy.js';
import {
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
  canonicalRepeatedObservationReplayFingerprint,
} from '../controlled-observation/support.js';
import { type FindingInspectionEvidenceBundle } from './port.js';
import { projectFindingInspection } from './projection.js';
import {
  FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
  FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
  FINDING_LATEST_OBSERVATION_INSPECTION_INVARIANTS,
  FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS,
  FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION,
  mapFindingLatestObservationInspectionResult,
  selectFindingLatestObservation,
  type FindingLatestObservationProjection,
} from './latest-observation-selection.js';

const ORG = '99999999-9999-4999-8999-999999999999';
const FINDING = '11111111-1111-4111-8111-111111111111';
const ASSET = '22222222-2222-4222-8222-222222222222';
const COMPONENT = '33333333-3333-4333-8333-333333333333';
const VULNERABILITY = '44444444-4444-4444-8444-444444444444';
const CREATION_OBSERVATION = '55555555-5555-4555-8555-555555555555';
const CREATION_INGESTION = '66666666-6666-4666-8666-666666666666';
const SBOM = '12121212-1212-4121-8121-121212121212';
const ACTOR = '13131313-1313-4131-8131-131313131313';
const CORRELATION = '14141414-1414-4141-8141-141414141414';
const FOREIGN = 'abcdefab-cdef-4abc-8abc-abcdefabcdef';
const OTHER_FINDING = 'fedcbaf0-dcba-4fed-8fed-fedcbafedcba';
const CREATED = '2026-10-06T16:00:00.000000Z';
const EARLY = '2026-10-07T16:00:00.000000Z';
const LATE = '2026-10-08T16:00:00.000000Z';
const TIE = '2026-10-09T16:00:00.000000Z';
const INSPECTION_CREATED = '2026-10-06T16:00:00.000Z';
const INGESTION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const INGESTION_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OBSERVATION_A = '15151515-1515-4151-8151-151515151515';
const OBSERVATION_B = '16161616-1616-4161-8161-161616161616';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../../..');

type ProductOutcome = 'affected' | 'unaffected' | 'unknown';

type SupportSpec =
  | {
      readonly kind: 'product';
      readonly outcome: ProductOutcome;
      readonly version: string;
      readonly evidenceId?: string;
      readonly occurrenceId?: string;
    }
  | { readonly kind: 'unknown_version'; readonly occurrenceId?: string };

function serial(value: number): string {
  return value.toString(16).padStart(12, '0');
}

function evidenceIdentity(value: number): string {
  return `77777777-7777-4777-8777-${serial(value)}`;
}

function occurrenceIdentity(value: number): string {
  return `88888888-8888-4888-8888-${serial(value)}`;
}

function currentEvidence(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    withdrawal: 'not_withdrawn',
    quarantine: 'not_quarantined',
    hasSuccessor: false,
    revisionOrigin: 'maintainer_reviewed_advisory',
    approvalPresent: true,
    approvalPurpose: 'approve_maintainer_reviewed_advisory_for_product_evaluation',
    approvalRevisionMatches: true,
    approvalVulnerabilityMatches: true,
    bindingPresent: true,
    bindingReviewed: true,
    ...overrides,
  };
}

function absentCurrentEvidence(): Record<string, unknown> {
  return {
    withdrawal: null,
    quarantine: null,
    hasSuccessor: null,
    revisionOrigin: null,
    approvalPresent: null,
    approvalPurpose: null,
    approvalRevisionMatches: null,
    approvalVulnerabilityMatches: null,
    bindingPresent: null,
    bindingReviewed: null,
  };
}

function lineage(version: string | null): Record<string, unknown> {
  return {
    occurrenceVersion: version,
    evidenceRawObservedVersion: version,
    productOrigin: version === null ? null : 'maintainer_reviewed_advisory',
    evaluatorId: version === null ? null : 'osv_first_ecosystem_affected_version_evaluator_v1',
    evaluatorVersion: version === null ? null : 'session_14_batch_2_in_memory',
    matchingPolicyId: version === null ? null : 'osv_first_ecosystem_matching_architecture_v1',
    matchingPolicyVersion: version === null ? null : 'osv_first_ecosystem_matching_architecture_v1',
    productEvidencePolicyId: version === null ? null : 'product_match_evaluation_policy_v1',
    productEvidencePolicyVersion: version === null ? null : 1,
    evidenceSchemaVersion: version === null ? null : 'product_match_evaluation_evidence_v1',
    findingCreation: version === null ? null : 'unavailable',
    suppressionAuthority: version === null ? null : false,
  };
}

function creationLink(version: string, index: number): Record<string, unknown> {
  return {
    organizationId: ORG,
    findingId: FINDING,
    findingObservationId: CREATION_OBSERVATION,
    evidenceId: evidenceIdentity(index),
    evidenceOrganizationId: ORG,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: CREATION_INGESTION,
    occurrenceId: occurrenceIdentity(index),
    outcome: 'affected',
    evidencePresent: true,
    occurrencePresent: true,
    occurrenceVersionKnown: true,
    evidenceAligned: true,
    evidenceOutcome: 'affected',
    occurrenceAssetId: ASSET,
    occurrenceComponentId: COMPONENT,
    occurrenceIngestionId: CREATION_INGESTION,
    ...lineage(version),
    ...currentEvidence(),
  };
}

function creationObservation(versions: readonly string[]): Record<string, unknown> {
  const links = versions.map((version, index) => creationLink(version, index + 1));
  const parsed = parseFindingCreationEvidenceSet(
    links.map((link) => link['evidenceId']).sort(compareText),
  );
  if (!parsed.ok) {
    throw new Error('creation fixture');
  }
  return {
    observationId: CREATION_OBSERVATION,
    organizationId: ORG,
    findingId: FINDING,
    sbomId: SBOM,
    sbomIngestionId: CREATION_INGESTION,
    observedAt: CREATED,
    createdAt: CREATED,
    method: 'controlled_finding_creation',
    result: 'present',
    occurrenceId: null,
    transitionClassification: 'initial_creation',
    creationPurpose: 'create_finding_from_product_match_evidence',
    creationPolicyId: 'finding_creation_policy_v1',
    creationPolicyVersion: 1,
    observationPurpose: null,
    observationPolicyId: null,
    observationPolicyVersion: null,
    aggregate: null,
    affectedEvidenceCount: links.length,
    replayFingerprint: parsed.evidenceSet.fingerprint,
    otherOccurrenceCount: 0,
    creationIngestionOccurrenceCount: links.length,
    evidence: {
      schemaVersion: 'finding_creation_observation_v1',
      transition: 'initial_creation',
      purpose: 'create_finding_from_product_match_evidence',
      policyId: 'finding_creation_policy_v1',
      policyVersion: 1,
      affectedEvidenceCount: links.length,
      evidenceSetFingerprint: parsed.evidenceSet.fingerprint,
    },
    ingestion: {
      id: CREATION_INGESTION,
      sbomId: SBOM,
      organizationId: ORG,
      assetId: ASSET,
      state: 'completed',
      normalizationVersion: '2',
      receivedAt: CREATED,
      createdAt: CREATED,
    },
    links,
  };
}

function supportRecord(
  spec: SupportSpec,
  ingestionId: string,
  observationId: string,
  index: number,
): Record<string, unknown> {
  if (spec.kind === 'unknown_version') {
    return {
      organizationId: ORG,
      findingId: FINDING,
      findingObservationId: observationId,
      assetId: ASSET,
      componentId: COMPONENT,
      vulnerabilityId: VULNERABILITY,
      sbomId: SBOM,
      sbomIngestionId: ingestionId,
      occurrenceId: spec.occurrenceId ?? occurrenceIdentity(index),
      supportKind: 'unknown_version_occurrence',
      evidenceId: null,
      evidenceOrganizationId: null,
      outcome: null,
      occurrenceVersionKnown: false,
      occurrenceAligned: true,
      evidencePresent: false,
      occurrencePresent: true,
      evidenceAligned: false,
      evidenceOutcome: null,
      ...lineage(null),
      ...absentCurrentEvidence(),
    };
  }
  const evidenceId = spec.evidenceId ?? evidenceIdentity(index);
  return {
    organizationId: ORG,
    findingId: FINDING,
    findingObservationId: observationId,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomId: SBOM,
    sbomIngestionId: ingestionId,
    occurrenceId: spec.occurrenceId ?? occurrenceIdentity(index),
    supportKind: 'product_match_evidence',
    evidenceId,
    evidenceOrganizationId: ORG,
    outcome: spec.outcome,
    occurrenceVersionKnown: true,
    occurrenceAligned: true,
    evidencePresent: true,
    occurrencePresent: true,
    evidenceAligned: true,
    evidenceOutcome: spec.outcome,
    ...lineage(spec.version),
    ...currentEvidence(),
  };
}

function repeatedObservation(input: {
  readonly observationId: string;
  readonly ingestionId: string;
  readonly observedAt: string;
  readonly aggregate: 'affected' | 'unaffected' | 'unknown' | 'component_absent';
  readonly supports?: readonly SupportSpec[];
  readonly absence?: {
    readonly graph: 'complete' | 'no_dependencies';
    readonly components: number;
    readonly edges: number;
  };
}): Record<string, unknown> {
  const supports = (input.supports ?? []).map((spec, index) =>
    supportRecord(spec, input.ingestionId, input.observationId, index + 1),
  );
  const evidenceIds = supports.flatMap((support) => {
    const evidenceId = support['evidenceId'];
    return typeof evidenceId === 'string' ? [evidenceId] : [];
  });
  const unknownIds = supports.flatMap((support) =>
    support['supportKind'] === 'unknown_version_occurrence'
      ? [String(support['occurrenceId'])]
      : [],
  );
  const mappedResult =
    input.aggregate === 'affected'
      ? 'present'
      : input.aggregate === 'unknown'
        ? 'inconclusive'
        : 'absent';
  const supportFingerprint =
    input.aggregate === 'component_absent'
      ? canonicalRepeatedObservationAbsenceFingerprint({
          sbomIngestionId: input.ingestionId,
          graphCompleteness: input.absence?.graph ?? 'complete',
          componentCount: input.absence?.components ?? 2,
          occurrenceCardinality: input.absence?.components ?? 2,
          dependencyEdgeCount: input.absence?.edges ?? 1,
        })
      : canonicalRepeatedObservationEvidenceFingerprint(
          [...evidenceIds].sort(compareText),
          [...unknownIds].sort(compareText),
          supports.length,
        );
  const replayFingerprint = canonicalRepeatedObservationReplayFingerprint({
    organizationId: ORG,
    findingId: FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: input.ingestionId,
    aggregate: input.aggregate,
    mappedResult,
    supportFingerprint,
    supportCount: input.aggregate === 'component_absent' ? 0 : supports.length,
  });
  const absence = input.absence ?? { graph: 'complete' as const, components: 2, edges: 1 };
  return {
    observationId: input.observationId,
    organizationId: ORG,
    findingId: FINDING,
    sbomId: SBOM,
    sbomIngestionId: input.ingestionId,
    method: 'controlled_finding_repeated_observation',
    result: mappedResult,
    occurrenceId: null,
    transitionClassification: 'evidence_observation',
    creationPurpose: null,
    creationPolicyId: null,
    creationPolicyVersion: null,
    observationPurpose: 'record_finding_repeated_observation',
    observationPolicyId: 'finding_observation_policy_v1',
    observationPolicyVersion: 1,
    aggregate: input.aggregate,
    evidenceLinkCount: input.aggregate === 'component_absent' ? 0 : supports.length,
    replayFingerprint,
    actorMembershipId: ACTOR,
    correlationId: CORRELATION,
    observedAt: input.observedAt,
    createdAt: input.observedAt,
    membershipPresent: true,
    absenceGraphCompleteness: input.aggregate === 'component_absent' ? absence.graph : null,
    absenceComponentCount: input.aggregate === 'component_absent' ? absence.components : null,
    absenceDependencyEdgeCount: input.aggregate === 'component_absent' ? absence.edges : null,
    unknownVersionOccurrenceHasEvidence: false,
    evidence: {
      schemaVersion: 'finding_repeated_observation_v1',
      purpose: 'record_finding_repeated_observation',
      policyId: 'finding_observation_policy_v1',
      policyVersion: 1,
      aggregate: input.aggregate,
      mappedResult,
      evidenceLinkCount: input.aggregate === 'component_absent' ? 0 : supports.length,
      replayFingerprint,
    },
    ingestion: {
      id: input.ingestionId,
      sbomId: SBOM,
      organizationId: ORG,
      assetId: ASSET,
      state: 'completed',
      normalizationVersion: '2',
      receivedAt: input.observedAt,
      createdAt: input.observedAt,
      graphCompleteness: absence.graph,
      componentCount: absence.components,
      dependencyEdgeCount: absence.edges,
      liveComponentCount: absence.components,
      liveEdgeCount: absence.edges,
      targetOccurrenceIds:
        input.aggregate === 'component_absent'
          ? []
          : supports.map((support) => String(support['occurrenceId'])),
    },
    supports: input.aggregate === 'component_absent' ? [] : supports,
  };
}

function findingRecord(
  lastObservedAt: string,
  assetCurrentIngestionId = CREATION_INGESTION,
): Record<string, unknown> {
  return {
    organizationId: ORG,
    findingId: FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    state: 'open',
    version: 1,
    componentOccurrenceId: null,
    resolvedAt: null,
    reopenedAt: null,
    assignedMembershipId: null,
    assignedTeamId: null,
    dueAt: null,
    currentRiskCalculationId: null,
    firstObservedAt: CREATED,
    lastObservedAt,
    createdAt: CREATED,
    updatedAt: lastObservedAt,
    remediationTaskCount: 0,
    riskAcceptanceCount: 0,
    riskCalculationCount: 0,
    genericEvidenceCount: 0,
    assetCurrentIngestionId,
  };
}

function selection(repeated: readonly Record<string, unknown>[]): Record<string, unknown> {
  let last = '';
  let assetCurrentIngestionId = CREATION_INGESTION;
  for (const observation of repeated) {
    const observedAt = observation['observedAt'];
    const ingestionId = observation['sbomIngestionId'];
    if (typeof observedAt !== 'string' || typeof ingestionId !== 'string') {
      continue;
    }
    if (
      last === '' ||
      observedAt > last ||
      (observedAt === last && ingestionId > assetCurrentIngestionId)
    ) {
      last = observedAt;
      assetCurrentIngestionId = ingestionId;
    }
  }
  if (last === '') {
    last = CREATED;
    assetCurrentIngestionId = CREATION_INGESTION;
  }
  return {
    schemaVersion: 'finding_latest_observation_selection_v1',
    authorizedOrganizationId: ORG,
    requestedFindingId: FINDING,
    finding: findingRecord(last, assetCurrentIngestionId),
    creation: creationObservation(['1.2.0']),
    repeated,
  };
}

function affected(version: string, index = 1): SupportSpec {
  return {
    kind: 'product',
    outcome: 'affected',
    version,
    evidenceId: evidenceIdentity(index),
    occurrenceId: occurrenceIdentity(index),
  };
}

function select(input: unknown) {
  return selectFindingLatestObservation(input);
}

function found(input: unknown): FindingLatestObservationProjection {
  const result = select(input);
  expect(result.status).toBe('found');
  if (result.status !== 'found') {
    throw new Error('expected a projection');
  }
  return result.projection;
}

function compareText(left: unknown, right: unknown): number {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function freeze(value: unknown): void {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
    return;
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    freeze((value as Record<string, unknown>)[key]);
  }
  Object.freeze(value);
}

describe('creation fallback', () => {
  it('projects the legal creation observation when no repeated observation exists', () => {
    const input = selection([]);
    const before = JSON.stringify(input);
    freeze(input);
    const now = Date.now;
    const random = Math.random;
    Date.now = () => {
      throw new Error('clock');
    };
    Math.random = () => {
      throw new Error('random');
    };
    try {
      const projection = found(input);
      expect(projection).toMatchObject({
        schemaVersion: 'finding_latest_observation_projection_v1',
        findingId: FINDING,
        assetId: ASSET,
        componentId: COMPONENT,
        vulnerabilityId: VULNERABILITY,
        observationSource: 'creation',
        observedAt: CREATED,
        aggregate: 'affected',
        mappedResult: 'present',
        evidence: {
          kind: 'occurrence_support',
          affectedSupportCount: 1,
          unaffectedSupportCount: 0,
          unknownSupportCount: 0,
          unknownVersionSupportCount: 0,
          knownVersions: ['1.2.0'],
        },
      });
    } finally {
      Date.now = now;
      Math.random = random;
    }
    expect(JSON.stringify(input)).toBe(before);
  });

  it('sorts creation evidence versions without a clock or a persistence call', () => {
    const input = selection([]);
    input['creation'] = creationObservation(['1.2.0', '1.10.0', '1.1.0']);
    const projection = found(input);
    expect(projection.evidence).toMatchObject({
      knownVersions: ['1.1.0', '1.10.0', '1.2.0'],
      affectedSupportCount: 3,
    });
  });
});

describe('latest repeated selection', () => {
  it('selects the only legal repeated observation ahead of creation', () => {
    const projection = found(
      selection([
        repeatedObservation({
          observationId: OBSERVATION_A,
          ingestionId: INGESTION_A,
          observedAt: LATE,
          aggregate: 'unaffected',
          supports: [{ kind: 'product', outcome: 'unaffected', version: '2.0.0' }],
        }),
      ]),
    );
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.observedAt).toBe(LATE);
    expect(projection.aggregate).toBe('unaffected');
    expect(JSON.stringify(projection)).not.toContain(CREATED);
    expect(JSON.stringify(projection)).not.toContain(OBSERVATION_A);
    expect(JSON.stringify(projection)).not.toContain(INGESTION_A);
  });

  it('selects the latest timestamp independent of candidate order', () => {
    const early = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: EARLY,
      aggregate: 'affected',
      supports: [affected('1.0.0', 1)],
    });
    const late = repeatedObservation({
      observationId: OBSERVATION_B,
      ingestionId: INGESTION_B,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('9.0.0', 2)],
    });
    const forward = found(selection([early, late]));
    const reverse = found(selection([late, early]));
    expect(forward).toEqual(reverse);
    expect(forward.observedAt).toBe(LATE);
    expect(forward.evidence).toMatchObject({ knownVersions: ['9.0.0'] });
    expect(JSON.stringify(forward)).not.toContain(EARLY);
    expect(JSON.stringify(forward)).not.toContain('1.0.0');
  });
});

describe('timestamp ties', () => {
  function tied(ingestionId: string, observationId: string, version: string, index: number) {
    return repeatedObservation({
      observationId,
      ingestionId,
      observedAt: TIE,
      aggregate: 'affected',
      supports: [affected(version, index)],
    });
  }

  it('breaks equal timestamps by descending PostgreSQL uuid ingestion identity', () => {
    const lower = tied(INGESTION_A, OBSERVATION_A, '1.0.0', 1);
    const higher = tied(INGESTION_B, OBSERVATION_B, '2.0.0', 2);
    const first = found(selection([lower, higher]));
    const second = found(selection([higher, lower]));
    expect(first).toEqual(second);
    expect(first).toEqual(found(selection([lower, higher])));
    expect(first.evidence).toMatchObject({ knownVersions: ['2.0.0'] });
    expect(INGESTION_B > INGESTION_A).toBe(true);
  });

  it('rejects a duplicated natural identity with a divergent payload', () => {
    const left = tied(INGESTION_A, OBSERVATION_A, '1.0.0', 1);
    const right = tied(INGESTION_A, OBSERVATION_B, '2.0.0', 2);
    const result = select(selection([left, right]));
    expect(result).toEqual({
      schemaVersion: FINDING_LATEST_OBSERVATION_RESULT_SCHEMA_VERSION,
      status: 'malformed_persisted_state',
    });
    expect(JSON.stringify(result)).not.toContain('1.0.0');
    expect(JSON.stringify(result)).not.toContain(OBSERVATION_B);
  });
});

describe('aggregate applicability', () => {
  it('projects each legal aggregate with its required evidence or absence proof', () => {
    const cases = [
      {
        aggregate: 'affected' as const,
        supports: [affected('3.1.0')] as readonly SupportSpec[],
        mappedResult: 'present',
        evidence: { kind: 'occurrence_support', affectedSupportCount: 1, knownVersions: ['3.1.0'] },
      },
      {
        aggregate: 'unaffected' as const,
        supports: [{ kind: 'product', outcome: 'unaffected', version: '3.2.0' }] as const,
        mappedResult: 'absent',
        evidence: {
          kind: 'occurrence_support',
          unaffectedSupportCount: 1,
          knownVersions: ['3.2.0'],
        },
      },
      {
        aggregate: 'unknown' as const,
        supports: [{ kind: 'product', outcome: 'unknown', version: '3.3.0' }] as const,
        mappedResult: 'inconclusive',
        evidence: { kind: 'occurrence_support', unknownSupportCount: 1, knownVersions: ['3.3.0'] },
      },
      {
        aggregate: 'unknown' as const,
        supports: [{ kind: 'unknown_version' }] as const,
        mappedResult: 'inconclusive',
        evidence: {
          kind: 'occurrence_support',
          unknownVersionSupportCount: 1,
          knownVersions: [],
        },
      },
    ];
    for (const entry of cases) {
      const projection = found(
        selection([
          repeatedObservation({
            observationId: OBSERVATION_A,
            ingestionId: INGESTION_A,
            observedAt: LATE,
            aggregate: entry.aggregate,
            supports: entry.supports,
          }),
        ]),
      );
      expect(projection.aggregate).toBe(entry.aggregate);
      expect(projection.mappedResult).toBe(entry.mappedResult);
      expect(projection.evidence).toMatchObject(entry.evidence);
    }
    const absent = found(
      selection([
        repeatedObservation({
          observationId: OBSERVATION_A,
          ingestionId: INGESTION_A,
          observedAt: LATE,
          aggregate: 'component_absent',
          absence: { graph: 'no_dependencies', components: 1, edges: 0 },
        }),
      ]),
    );
    expect(absent.evidence).toEqual({
      kind: 'component_absence',
      graphCompleteness: 'no_dependencies',
      componentCount: 1,
      dependencyEdgeCount: 0,
    });
    expect(JSON.stringify(absent)).not.toContain('remediat');
    expect(JSON.stringify(absent)).not.toContain('resolved');
  });

  it('lets affected dominate and lets unknown dominate unaffected', () => {
    const affectedProjection = found(
      selection([
        repeatedObservation({
          observationId: OBSERVATION_A,
          ingestionId: INGESTION_A,
          observedAt: LATE,
          aggregate: 'affected',
          supports: [
            affected('1.0.0', 1),
            {
              kind: 'product',
              outcome: 'unaffected',
              version: '2.0.0',
              evidenceId: evidenceIdentity(2),
              occurrenceId: occurrenceIdentity(2),
            },
          ],
        }),
      ]),
    );
    expect(affectedProjection.aggregate).toBe('affected');
    const unknownProjection = found(
      selection([
        repeatedObservation({
          observationId: OBSERVATION_A,
          ingestionId: INGESTION_A,
          observedAt: LATE,
          aggregate: 'unknown',
          supports: [
            {
              kind: 'product',
              outcome: 'unaffected',
              version: '2.0.0',
              evidenceId: evidenceIdentity(1),
              occurrenceId: occurrenceIdentity(1),
            },
            {
              kind: 'product',
              outcome: 'unknown',
              version: '3.0.0',
              evidenceId: evidenceIdentity(2),
              occurrenceId: occurrenceIdentity(2),
            },
          ],
        }),
      ]),
    );
    expect(unknownProjection.aggregate).toBe('unknown');
  });
});

describe('evidence and support hostility', () => {
  function legalRepeated(): Record<string, unknown> {
    return repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('4.0.0')],
    });
  }

  it('fails closed instead of skipping an illegal repeated observation', () => {
    const legal = legalRepeated();
    const illegal = legalRepeated();
    illegal['supports'] = [];
    const result = select(selection([legal, illegal]));
    expect(result.status).toBe('malformed_persisted_state');
  });

  it.each([
    [
      'missing support',
      (row: Record<string, unknown>) => {
        row['supports'] = [];
      },
    ],
    [
      'missing evidence',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          first['evidencePresent'] = false;
        }
      },
    ],
    [
      'cross-finding support',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          first['findingId'] = OTHER_FINDING;
        }
      },
    ],
    [
      'wrong observation',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          first['findingObservationId'] = CREATION_OBSERVATION;
        }
      },
    ],
    [
      'contradictory aggregate',
      (row: Record<string, unknown>) => {
        row['aggregate'] = 'unaffected';
        row['result'] = 'absent';
      },
    ],
    [
      'invalid component',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          first['componentId'] = FOREIGN;
        }
      },
    ],
    [
      'invalid version',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          first['evidenceRawObservedVersion'] = 'other';
        }
      },
    ],
    [
      'duplicate support',
      (row: Record<string, unknown>) => {
        const supports = row['supports'] as Record<string, unknown>[];
        const first = supports[0];
        if (first !== undefined) {
          row['supports'] = [first, { ...first }];
          row['evidenceLinkCount'] = 2;
        }
      },
    ],
  ])('rejects %s', (_name, mutate) => {
    const row = legalRepeated();
    mutate(row);
    const result = select(selection([row]));
    expect(['malformed_persisted_state', 'evidence_unavailable']).toContain(result.status);
    expect(JSON.stringify(result)).not.toContain(OTHER_FINDING);
    expect(JSON.stringify(result)).not.toContain(FOREIGN);
  });

  it('rejects a malformed absence proof and absence combined with evidence', () => {
    const partial = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'component_absent',
    });
    partial['absenceGraphCompleteness'] = 'partial';
    expect(select(selection([partial])).status).toBe('malformed_persisted_state');
    const mixed = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'component_absent',
    });
    mixed['supports'] = [supportRecord(affected('1.0.0'), INGESTION_A, OBSERVATION_A, 1)];
    expect(select(selection([mixed])).status).toBe('malformed_persisted_state');
  });
});

describe('tenant isolation', () => {
  it('maps a missing Finding and a foreign Finding to the same external result', () => {
    const missing = selection([]);
    missing['requestedFindingId'] = OTHER_FINDING;
    const foreignFinding = selection([]);
    foreignFinding['finding'] = { ...findingRecord(CREATED), organizationId: FOREIGN };
    const missingResult = select(missing);
    const foreignResult = select(foreignFinding);
    expect(missingResult.status).toBe('not_found');
    expect(foreignResult.status).toBe('not_found');
    const missingExternal = mapFindingLatestObservationInspectionResult(missingResult);
    const foreignExternal = mapFindingLatestObservationInspectionResult(foreignResult);
    expect(missingExternal).toEqual(foreignExternal);
    expect(missingExternal).toEqual({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(JSON.stringify(missingExternal)).not.toContain(FOREIGN);
    expect(JSON.stringify(foreignExternal)).not.toContain(OTHER_FINDING);
  });
});

describe('malformed persisted state', () => {
  it('rejects unknown applicability, bad classification, bad time, and bad identity', () => {
    const row = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('4.0.0')],
    });
    expect(select(selection([{ ...row, aggregate: 'not-an-aggregate' }])).status).toBe(
      'malformed_persisted_state',
    );
    expect(
      select(
        selection([
          {
            ...row,
            method: 'controlled_finding_creation',
            result: 'present',
            aggregate: null,
            observationPurpose: null,
            observationPolicyId: null,
            observationPolicyVersion: null,
            creationPurpose: 'create_finding_from_product_match_evidence',
            creationPolicyId: 'finding_creation_policy_v1',
            creationPolicyVersion: 1,
          },
        ]),
      ).status,
    ).toBe('malformed_persisted_state');
    expect(select(selection([{ ...row, observedAt: '2026-10-08' }])).status).toBe(
      'malformed_persisted_state',
    );
    expect(select(selection([{ ...row, observationId: 'not-a-uuid' }])).status).toBe(
      'malformed_persisted_state',
    );
    expect(select(selection([{ ...row, sbomIngestionId: null }])).status).toBe(
      'malformed_persisted_state',
    );
    const backwards = selection([row]);
    backwards['finding'] = findingRecord(CREATED);
    expect(select(backwards).status).toBe('malformed_persisted_state');
    const resolved = selection([]);
    resolved['finding'] = { ...findingRecord(CREATED), state: 'resolved' };
    expect(select(resolved).status).toBe('malformed_persisted_state');
    const versioned = selection([]);
    versioned['finding'] = { ...findingRecord(CREATED), version: 2 };
    expect(select(versioned).status).toBe('malformed_persisted_state');
  });
});

describe('bounded projection', () => {
  it('exposes one observation and no history, cursor, support id, or lifecycle field', () => {
    const projection = found(
      selection([
        repeatedObservation({
          observationId: OBSERVATION_A,
          ingestionId: INGESTION_A,
          observedAt: LATE,
          aggregate: 'affected',
          supports: [affected('4.0.0')],
        }),
      ]),
    );
    expect(Object.keys(projection).sort()).toEqual(
      [...FINDING_LATEST_OBSERVATION_PROJECTION_FIELDS].sort(),
    );
    expect(projection).not.toHaveProperty('observations');
    expect(projection).not.toHaveProperty('history');
    expect(projection).not.toHaveProperty('state');
    expect(projection).not.toHaveProperty('version');
    const encoded = JSON.stringify(projection);
    for (const token of [
      'cursor',
      'page',
      'supportId',
      'authorization',
      'replayFingerprint',
      'correlationId',
      ACTOR,
      CORRELATION,
      OBSERVATION_A,
    ]) {
      expect(encoded).not.toContain(token);
    }
    expect(Array.isArray(projection.evidence)).toBe(false);
  });
});

describe('compatibility and non-composition', () => {
  it('keeps production inspection creation based and unregistered', () => {
    const bundle: FindingInspectionEvidenceBundle = {
      findingId: FINDING,
      state: 'open',
      createdAt: INSPECTION_CREATED,
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
      assetDisplayName: 'asset',
      assetCurrentIngestionId: CREATION_INGESTION,
      componentPresent: true,
      componentEcosystem: 'npm',
      componentNamespace: null,
      componentName: 'widget',
      vulnerabilityPresent: true,
      vulnerabilityPublicId: 'REVIEWED-NPM-1',
      remediationTaskCount: 0,
      riskAcceptanceCount: 0,
      riskCalculationCount: 0,
      genericEvidenceCount: 0,
      creationIngestionOccurrenceCount: 1,
      otherOccurrenceCount: 0,
      observations: [
        {
          id: CREATION_OBSERVATION,
          sbomIngestionId: CREATION_INGESTION,
          occurrenceId: null,
          result: 'present',
          method: 'controlled_finding_creation',
          transitionClassification: 'initial_creation',
          creationPurpose: 'create_finding_from_product_match_evidence',
          creationPolicyId: 'finding_creation_policy_v1',
          creationPolicyVersion: 1,
          affectedEvidenceCount: 1,
          replayAgrees: true,
          evidenceRecordAgrees: true,
        },
      ],
      links: [
        {
          evidenceId: evidenceIdentity(1),
          findingObservationId: CREATION_OBSERVATION,
          assetId: ASSET,
          componentId: COMPONENT,
          vulnerabilityId: VULNERABILITY,
          sbomIngestionId: CREATION_INGESTION,
          componentOccurrenceId: occurrenceIdentity(1),
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
          rawObservedVersion: '1.2.0',
          occurrencePresent: true,
          occurrenceVersion: '1.2.0',
          occurrenceVersionKnown: true,
          occurrenceAssetId: ASSET,
          occurrenceComponentId: COMPONENT,
          occurrenceIngestionId: CREATION_INGESTION,
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
        },
      ],
    };
    const current = projectFindingInspection(bundle, FINDING);
    expect(current.status).toBe('found');
    if (current.status === 'found') {
      expect(current.projection.creationObservationPolicy.policyId).toBe(
        'finding_creation_policy_v1',
      );
      expect(current.projection).not.toHaveProperty('observationSource');
    }
    const domainIndex = readFileSync(path.join(repoRoot, 'packages/domain/src/index.ts'), 'utf8');
    const inspectionIndex = readFileSync(path.join(here, 'index.ts'), 'utf8');
    const service = readFileSync(path.join(here, 'service.ts'), 'utf8');
    const permissions = readFileSync(
      path.join(repoRoot, 'packages/domain/src/findings/controlled-operator/permissions.ts'),
      'utf8',
    );
    expect(domainIndex).not.toContain('selectFindingLatestObservation');
    expect(inspectionIndex).not.toContain('selectFindingLatestObservation');
    expect(service).not.toContain('selectFindingLatestObservation');
    expect(permissions).not.toContain('latest_observation');
    expect(permissions).not.toContain('finding:observe');
    expect(FINDING_REPEATED_OBSERVATION_INVARIANTS.nextSession).toBe(
      'controlled_finding_repeated_observation_session_3r',
    );
    expect(FINDING_LATEST_OBSERVATION_INSPECTION_INVARIANTS).toMatchObject({
      productionRegistration: 'absent',
      persistenceReadImplemented: true,
      postgresqlReadImplemented: true,
      productionInspection: 'creation_based',
      nextSession: 'controlled_finding_latest_observation_inspection_successor_boundary_review',
      writes: 0,
    });
    const selector = readFileSync(path.join(here, 'latest-observation-selection.ts'), 'utf8');
    expect(selector).not.toContain('prisma');
    expect(selector).not.toContain('Date.now');
    expect(selector).not.toContain('new Date');
    expect(selector).not.toContain('process.env');
    expect(selector).not.toContain('FINDING_LATEST_OBSERVATION_CANDIDATE_INPUT_LIMIT');
    const migrations = readdirSync(
      path.join(repoRoot, 'packages/database/prisma/migrations'),
    ).filter((name) => name !== 'migration_lock.toml');
    expect(migrations).toHaveLength(25);
    const offenders: string[] = [];
    for (const root of ['apps/api/src', 'apps/web', 'apps/worker/src', 'packages/database/src']) {
      for (const filePath of walk(path.join(repoRoot, root))) {
        if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) {
          continue;
        }
        const source = readFileSync(filePath, 'utf8');
        if (
          source.includes('selectFindingLatestObservation') ||
          source.includes('mapFindingLatestObservationInspectionResult') ||
          source.includes('latest-observation-selection')
        ) {
          offenders.push(path.relative(repoRoot, filePath));
        }
      }
    }
    expect(domainIndex).not.toContain('mapFindingLatestObservationInspectionResult');
    expect(inspectionIndex).not.toContain('mapFindingLatestObservationInspectionResult');
    const allowedPersistence = new Set([
      'packages/database/src/controlled-finding-latest-observation-read.ts',
      'packages/database/src/controlled-finding-latest-observation-read.test.ts',
      'packages/database/src/controlled-finding-latest-observation-read.integration.test.ts',
    ]);
    expect(offenders.filter((file) => !allowedPersistence.has(file))).toEqual([]);
    expect(offenders).toContain(
      'packages/database/src/controlled-finding-latest-observation-read.ts',
    );
  });
});

describe('microsecond observation order', () => {
  const laterInstant = '2026-10-09T16:00:00.000001Z';
  const earlierInstant = '2026-10-09T16:00:00.000000Z';
  const equalInstant = '2026-10-09T16:00:00.123456Z';
  const lowIngestion = '00000000-0000-4000-8000-000000000001';
  const highIngestion = 'ffffffff-ffff-4fff-8fff-ffffffffffff';

  function at(
    observedAt: string,
    ingestionId: string,
    observationId: string,
    version: string,
    index: number,
  ) {
    return repeatedObservation({
      observationId,
      ingestionId,
      observedAt,
      aggregate: 'affected',
      supports: [affected(version, index)],
    });
  }

  it('selects the later microsecond when that row has the lower ingestion id', () => {
    const later = at(laterInstant, lowIngestion, OBSERVATION_A, 'later-microsecond', 1);
    const earlier = at(earlierInstant, highIngestion, OBSERVATION_B, 'earlier-microsecond', 2);
    const forward = found(selection([later, earlier]));
    const reverse = found(selection([earlier, later]));
    expect(forward).toEqual(reverse);
    expect(forward.observedAt).toBe(laterInstant);
    expect(forward.evidence).toMatchObject({ knownVersions: ['later-microsecond'] });
    expect(lowIngestion < highIngestion).toBe(true);
  });

  it('breaks an exact six-digit tie by descending PostgreSQL uuid byte order', () => {
    const lower = at(equalInstant, lowIngestion, OBSERVATION_A, 'lower-uuid', 1);
    const higher = at(equalInstant, highIngestion, OBSERVATION_B, 'higher-uuid', 2);
    expect(found(selection([lower, higher])).evidence).toMatchObject({
      knownVersions: ['higher-uuid'],
    });
    expect(found(selection([higher, lower])).evidence).toMatchObject({
      knownVersions: ['higher-uuid'],
    });
  });

  it.each([
    ['short fraction', '2026-10-08T16:00:00.123Z'],
    ['extra fraction', '2026-10-08T16:00:00.1234567Z'],
    ['offset', '2026-10-08T16:00:00.000000+00:00'],
    ['lowercase zone', '2026-10-08T16:00:00.000000z'],
    ['invalid day', '2026-02-31T00:00:00.000000Z'],
    ['non-leap day', '2026-02-29T00:00:00.000000Z'],
    ['invalid month', '2026-13-01T00:00:00.000000Z'],
    ['leap second', '2026-10-08T16:00:60.000000Z'],
  ])('rejects %s', (_name, observedAt) => {
    const result = select(selection([at(observedAt, INGESTION_A, OBSERVATION_A, 'rejected', 1)]));
    expect(result.status).toBe('malformed_persisted_state');
    expect(result).not.toHaveProperty('projection');
  });

  it('accepts a real leap day at six-digit precision', () => {
    const projection = found(
      selection([at('2028-02-29T00:00:00.000001Z', INGESTION_A, OBSERVATION_A, 'leap', 1)]),
    );
    expect(projection.observedAt).toBe('2028-02-29T00:00:00.000001Z');
  });
});

describe('uuid byte order', () => {
  function tied(ingestionId: string, observationId: string, version: string, index: number) {
    return repeatedObservation({
      observationId,
      ingestionId,
      observedAt: TIE,
      aggregate: 'affected',
      supports: [affected(version, index)],
    });
  }

  it('follows PostgreSQL byte order rather than RFC 4122 timestamp order', () => {
    const byteLater = tied('ffffffff-0000-1000-8000-000000000000', OBSERVATION_A, 'byte-later', 1);
    const rfcLater = tied('00000000-0000-1fff-8000-000000000000', OBSERVATION_B, 'rfc-later', 2);
    expect(found(selection([rfcLater, byteLater])).evidence).toMatchObject({
      knownVersions: ['byte-later'],
    });
    expect(found(selection([byteLater, rfcLater])).evidence).toMatchObject({
      knownVersions: ['byte-later'],
    });
  });

  it('uses the digit before a hyphen and the digit after a hyphen', () => {
    const beforeLow = tied('aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaaa', OBSERVATION_A, 'before-low', 1);
    const beforeHigh = tied(
      'aaaaaaa2-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      OBSERVATION_B,
      'before-high',
      2,
    );
    expect(found(selection([beforeLow, beforeHigh])).evidence).toMatchObject({
      knownVersions: ['before-high'],
    });
    const afterLow = tied('aaaaaaaa-aaa1-4aaa-8aaa-aaaaaaaaaaaa', OBSERVATION_A, 'after-low', 1);
    const afterHigh = tied('aaaaaaaa-aaa2-4aaa-8aaa-aaaaaaaaaaaa', OBSERVATION_B, 'after-high', 2);
    expect(found(selection([afterHigh, afterLow])).evidence).toMatchObject({
      knownVersions: ['after-high'],
    });
  });

  it('does not stop at the first character when later bytes differ', () => {
    const tailLow = tied('a0000000-0000-4000-8000-000000000000', OBSERVATION_A, 'tail-low', 1);
    const tailHigh = tied('a0000000-0000-4000-8000-000000000001', OBSERVATION_B, 'tail-high', 2);
    expect(found(selection([tailLow, tailHigh]))).toEqual(found(selection([tailHigh, tailLow])));
    expect(found(selection([tailLow, tailHigh])).evidence).toMatchObject({
      knownVersions: ['tail-high'],
    });
  });

  it.each([
    ['uppercase', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'],
    ['unhyphenated', 'aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaaaaaa'],
    ['invalid version', 'aaaaaaaa-aaaa-0aaa-8aaa-aaaaaaaaaaaa'],
    ['invalid variant', 'aaaaaaaa-aaaa-4aaa-0aaa-aaaaaaaaaaaa'],
  ])('rejects %s ingestion identity', (_name, ingestionId) => {
    const result = select(selection([tied(ingestionId, OBSERVATION_A, 'rejected', 1)]));
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain(ingestionId);
  });
});

describe('total order', () => {
  function permute<T>(items: readonly T[]): T[][] {
    if (items.length <= 1) {
      return [items.slice()];
    }
    const results: T[][] = [];
    items.forEach((item, index) => {
      const rest = [...items.slice(0, index), ...items.slice(index + 1)];
      for (const tail of permute(rest)) {
        results.push([item, ...tail]);
      }
    });
    return results;
  }

  it('selects the same latest row for every permutation of three timestamps', () => {
    const early = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      observedAt: EARLY,
      aggregate: 'affected',
      supports: [affected('early', 1)],
    });
    const middle = repeatedObservation({
      observationId: OBSERVATION_B,
      ingestionId: INGESTION_A,
      observedAt: '2026-10-07T16:00:00.500000Z',
      aggregate: 'affected',
      supports: [affected('middle', 2)],
    });
    const late = repeatedObservation({
      observationId: '17171717-1717-4171-8171-171717171717',
      ingestionId: '00000000-0000-4000-8000-000000000010',
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('late', 3)],
    });
    const projections = permute([early, middle, late]).map((rows) => found(selection(rows)));
    const firstProjection = projections[0];
    if (firstProjection === undefined) {
      throw new Error('fixture');
    }
    expect(projections).toHaveLength(6);
    for (const projection of projections) {
      expect(projection).toEqual(firstProjection);
      expect(projection.evidence).toMatchObject({ knownVersions: ['late'] });
    }
    expect(found(selection([late, middle, early]))).toEqual(
      found(selection([late, middle, early])),
    );
  });

  it('selects the greatest ingestion id for every permutation of one timestamp', () => {
    const low = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: '10000000-0000-4000-8000-000000000001',
      observedAt: TIE,
      aggregate: 'affected',
      supports: [affected('low', 1)],
    });
    const mid = repeatedObservation({
      observationId: OBSERVATION_B,
      ingestionId: '10000000-0000-4000-8000-000000000002',
      observedAt: TIE,
      aggregate: 'affected',
      supports: [affected('mid', 2)],
    });
    const high = repeatedObservation({
      observationId: '17171717-1717-4171-8171-171717171717',
      ingestionId: 'f0000000-0000-4000-8000-000000000003',
      observedAt: TIE,
      aggregate: 'affected',
      supports: [affected('high', 3)],
    });
    for (const rows of permute([low, mid, high])) {
      expect(found(selection(rows)).evidence).toMatchObject({ knownVersions: ['high'] });
    }
  });

  it('rejects a duplicated surrogate observation id', () => {
    const left = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: EARLY,
      aggregate: 'affected',
      supports: [affected('1.0.0', 1)],
    });
    const right = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_B,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('2.0.0', 2)],
    });
    expect(select(selection([left, right])).status).toBe('malformed_persisted_state');
  });
});

describe('ingestion tuple order', () => {
  const lowIngestion = '00000000-0000-4000-8000-000000000001';
  const higherThanCreation = '66666666-6666-4666-8666-666666666667';
  const lowerThanCreation = '66666666-6666-4666-8666-666666666665';

  function withTuple(ingestionId: string, receivedAt: string, createdAt: string, version: string) {
    const row = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected(version, 1)],
    });
    const ingestion = row['ingestion'] as Record<string, unknown>;
    ingestion['receivedAt'] = receivedAt;
    ingestion['createdAt'] = createdAt;
    return row;
  }

  it('treats a one-microsecond later received_at as strictly later', () => {
    const projection = found(
      selection([
        withTuple(lowIngestion, '2026-10-06T16:00:00.000001Z', CREATED, 'received-later'),
      ]),
    );
    expect(projection.evidence).toMatchObject({ knownVersions: ['received-later'] });
  });

  it('treats a one-microsecond later created_at as strictly later when received_at ties', () => {
    const projection = found(
      selection([withTuple(lowIngestion, CREATED, '2026-10-06T16:00:00.000001Z', 'created-later')]),
    );
    expect(projection.evidence).toMatchObject({ knownVersions: ['created-later'] });
  });

  it('lets the ingestion id decide when both timestamps tie', () => {
    expect(
      found(selection([withTuple(higherThanCreation, CREATED, CREATED, 'id-later')])).evidence,
    ).toMatchObject({ knownVersions: ['id-later'] });
    expect(
      select(selection([withTuple(lowerThanCreation, CREATED, CREATED, 'id-earlier')])).status,
    ).toBe('malformed_persisted_state');
  });

  it('accepts a later millisecond and rejects an identical tuple', () => {
    expect(
      found(
        selection([
          withTuple(lowIngestion, '2026-10-06T16:00:00.001000Z', CREATED, 'millisecond-later'),
        ]),
      ).evidence,
    ).toMatchObject({ knownVersions: ['millisecond-later'] });
    expect(
      select(selection([withTuple(CREATION_INGESTION, CREATED, CREATED, 'equal-tuple')])).status,
    ).toBe('malformed_persisted_state');
  });

  it('does not change a legal pair when the candidate array is reversed', () => {
    const received = withTuple(INGESTION_A, '2026-10-06T16:00:00.000001Z', CREATED, 'received');
    received['observationId'] = OBSERVATION_A;
    received['observedAt'] = EARLY;
    received['createdAt'] = EARLY;
    const created = repeatedObservation({
      observationId: OBSERVATION_B,
      ingestionId: INGESTION_B,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('created', 2)],
    });
    const ingestion = created['ingestion'] as Record<string, unknown>;
    ingestion['receivedAt'] = CREATED;
    ingestion['createdAt'] = '2026-10-06T16:00:00.000002Z';
    expect(found(selection([received, created]))).toEqual(found(selection([created, received])));
  });
});

describe('current evidence legality', () => {
  function productRow(version = '4.0.0'): Record<string, unknown> {
    return repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected(version, 1)],
    });
  }

  function patchSupport(
    row: Record<string, unknown>,
    index: number,
    patch: Record<string, unknown>,
  ): void {
    const supports = row['supports'] as Record<string, unknown>[];
    const support = supports[index];
    if (support === undefined) {
      throw new Error('fixture');
    }
    Object.assign(support, patch);
  }

  it('projects legal approved current evidence', () => {
    const projection = found(selection([productRow('legal')]));
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.evidence).toMatchObject({ knownVersions: ['legal'] });
  });

  it.each([
    ['withdrawn evidence', { withdrawal: 'withdrawn' }],
    ['quarantined evidence', { quarantine: 'quarantined' }],
    ['superseded evidence', { hasSuccessor: true }],
    ['wrong approval purpose', { approvalPurpose: 'record_only' }],
    ['unreviewed binding', { bindingReviewed: false }],
    ['revision origin mismatch', { revisionOrigin: 'osv' }],
    ['approval revision mismatch', { approvalRevisionMatches: false }],
  ])('fails the set for %s', (_name, patch) => {
    const row = productRow();
    patchSupport(row, 0, patch);
    const result = select(selection([row]));
    expect(result.status).toBe('integrity_failure');
    const mapped = mapFindingLatestObservationInspectionResult(result);
    expect(mapped).toEqual({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
    });
    expect(JSON.stringify(mapped)).not.toContain('4.0.0');
    expect(JSON.stringify(mapped)).not.toContain('withdrawn');
  });

  it('fails the set when one of several supports is illegal', () => {
    const row = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('1.0.0', 1), affected('2.0.0', 2)],
    });
    patchSupport(row, 1, { quarantine: 'quarantined' });
    expect(select(selection([row])).status).toBe('integrity_failure');
    expect(
      mapFindingLatestObservationInspectionResult(select(selection([row]))),
    ).not.toHaveProperty('projection');
  });

  it('does not replace an illegal newest observation with an older legal one', () => {
    const older = repeatedObservation({
      observationId: OBSERVATION_A,
      ingestionId: INGESTION_A,
      observedAt: EARLY,
      aggregate: 'affected',
      supports: [affected('older-legal', 1)],
    });
    const newer = repeatedObservation({
      observationId: OBSERVATION_B,
      ingestionId: INGESTION_B,
      observedAt: LATE,
      aggregate: 'affected',
      supports: [affected('newer-illegal', 2)],
    });
    patchSupport(newer, 0, { withdrawal: 'withdrawn' });
    const result = select(selection([older, newer]));
    expect(result.status).toBe('integrity_failure');
    const mapped = mapFindingLatestObservationInspectionResult(result);
    expect(mapped.status).toBe(FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE);
    expect(JSON.stringify(mapped)).not.toContain('older-legal');
    expect(JSON.stringify(mapped)).not.toContain('newer-illegal');
    expect(select(selection([newer, older])).status).toBe('integrity_failure');
  });

  it('still selects a legal repeated observation when creation evidence is historical', () => {
    const input = selection([productRow('repeated-legal')]);
    const links = (input['creation'] as Record<string, unknown>)['links'] as Record<
      string,
      unknown
    >[];
    const link = links[0];
    if (link === undefined) {
      throw new Error('fixture');
    }
    link['hasSuccessor'] = true;
    const projection = found(input);
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.evidence).toMatchObject({ knownVersions: ['repeated-legal'] });
  });

  it('does not project creation when its product-match evidence is no longer current', () => {
    const input = selection([]);
    const links = (input['creation'] as Record<string, unknown>)['links'] as Record<
      string,
      unknown
    >[];
    const link = links[0];
    if (link === undefined) {
      throw new Error('fixture');
    }
    link['withdrawal'] = 'withdrawn';
    const result = select(input);
    expect(result.status).toBe('integrity_failure');
    expect(mapFindingLatestObservationInspectionResult(result).status).toBe(
      FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
    );
  });

  it('does not project a product-match observation outside the asset current ingestion', () => {
    const input = selection([productRow()]);
    input['finding'] = {
      ...(input['finding'] as Record<string, unknown>),
      assetCurrentIngestionId: CREATION_INGESTION,
    };
    expect(select(input).status).toBe('integrity_failure');
    expect(mapFindingLatestObservationInspectionResult(select(input)).status).toBe(
      FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
    );
  });
});

describe('external failure mapping', () => {
  function mapped(input: unknown) {
    return mapFindingLatestObservationInspectionResult(select(input));
  }

  it('maps an unsupported envelope without a diagnostic name', () => {
    const internal = select({ schemaVersion: 'not-a-selection' });
    expect(internal.status).toBe('unsupported_envelope');
    const result = mapFindingLatestObservationInspectionResult(internal);
    expect(result).toEqual({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
    });
    expect(JSON.stringify(result)).not.toContain('unsupported_envelope');
    expect(JSON.stringify(result)).not.toContain('internal_failure');
  });

  it('hides foreign nested evidence, cross-finding corruption, and storage detail', () => {
    const foreignEvidence = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('4.0.0')],
      }),
    ]);
    const evidence = (
      (foreignEvidence['repeated'] as Record<string, unknown>[])[0]?.['supports'] as Record<
        string,
        unknown
      >[]
    )[0];
    if (evidence === undefined) {
      throw new Error('fixture');
    }
    evidence['evidenceOrganizationId'] = FOREIGN;
    const foreignSupport = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('4.0.0')],
      }),
    ]);
    const support = (
      (foreignSupport['repeated'] as Record<string, unknown>[])[0]?.['supports'] as Record<
        string,
        unknown
      >[]
    )[0];
    if (support === undefined) {
      throw new Error('fixture');
    }
    support['organizationId'] = FOREIGN;
    const crossFinding = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('4.0.0')],
      }),
    ]);
    const cross = (
      (crossFinding['repeated'] as Record<string, unknown>[])[0]?.['supports'] as Record<
        string,
        unknown
      >[]
    )[0];
    if (cross === undefined) {
      throw new Error('fixture');
    }
    cross['findingId'] = OTHER_FINDING;
    const missingEvidence = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('4.0.0')],
      }),
    ]);
    const missing = (
      (missingEvidence['repeated'] as Record<string, unknown>[])[0]?.['supports'] as Record<
        string,
        unknown
      >[]
    )[0];
    if (missing === undefined) {
      throw new Error('fixture');
    }
    missing['evidencePresent'] = false;
    const foreignObservation = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('4.0.0')],
      }),
    ]);
    const observation = (foreignObservation['repeated'] as Record<string, unknown>[])[0];
    if (observation === undefined) {
      throw new Error('fixture');
    }
    observation['organizationId'] = FOREIGN;
    for (const input of [
      foreignEvidence,
      foreignSupport,
      foreignObservation,
      crossFinding,
      missingEvidence,
    ]) {
      const internal = select(input);
      expect(internal.status).not.toBe('not_found');
      expect(internal.status).not.toBe('found');
      const result = mapFindingLatestObservationInspectionResult(internal);
      expect(result).toEqual({
        schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
        status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
      });
      const encoded = JSON.stringify(result);
      expect(encoded).not.toContain(FOREIGN);
      expect(encoded).not.toContain(OTHER_FINDING);
      expect(encoded).not.toContain('integrity_failure');
      expect(encoded).not.toContain('malformed_persisted_state');
      expect(encoded).not.toContain('evidence_unavailable');
      expect(encoded).not.toContain('internal_failure');
    }
    expect(select(crossFinding).status).toBe('malformed_persisted_state');
    expect(select(missingEvidence).status).toBe('evidence_unavailable');
  });

  it('keeps one external failure when internal diagnostics differ by validation order', () => {
    function combined(withdrawnFirst: boolean) {
      const row = repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('1.0.0', 1), affected('2.0.0', 2)],
      });
      const supports = row['supports'] as Record<string, unknown>[];
      const first = supports[0];
      const second = supports[1];
      if (first === undefined || second === undefined) {
        throw new Error('fixture');
      }
      if (withdrawnFirst) {
        first['withdrawal'] = 'withdrawn';
        second['evidencePresent'] = false;
      } else {
        first['evidencePresent'] = false;
        second['withdrawal'] = 'withdrawn';
      }
      return selection([row]);
    }
    const forward = select(combined(true));
    const reverse = select(combined(false));
    expect(mapped(combined(true))).toEqual(mapped(combined(false)));
    expect(mapped(combined(true)).status).toBe(FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE);
    expect(forward.status).toBe('integrity_failure');
    expect(reverse.status).toBe('integrity_failure');
    expect(JSON.stringify(mapped(combined(true)))).not.toContain('withdrawn');
    expect(JSON.stringify(mapped(combined(true)))).not.toContain(OBSERVATION_A);
  });
});

describe('mutation and aliasing', () => {
  it('leaves candidate arrays and nested evidence unchanged', () => {
    const input = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'affected',
        supports: [affected('9.0.0', 1), affected('1.0.0', 2)],
      }),
    ]);
    const snapshot = JSON.stringify(input);
    const projection = found(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    const evidence = projection.evidence;
    expect(evidence.kind).toBe('occurrence_support');
    if (evidence.kind !== 'occurrence_support') {
      throw new Error('fixture');
    }
    expect(Object.isFrozen(evidence)).toBe(true);
    expect(Object.isFrozen(evidence.knownVersions)).toBe(true);
    expect(() => {
      (evidence.knownVersions as unknown as string[]).push('mutated');
    }).toThrow();
    const supports = (input['repeated'] as Record<string, unknown>[])[0]?.['supports'] as Record<
      string,
      unknown
    >[];
    const first = supports[0];
    if (first === undefined) {
      throw new Error('fixture');
    }
    first['occurrenceVersion'] = 'changed-after-selection';
    expect(evidence.knownVersions).toEqual(['1.0.0', '9.0.0']);
    expect(evidence.knownVersions).not.toBe(supports);
  });

  it('accepts frozen nested candidates', () => {
    const input = selection([
      repeatedObservation({
        observationId: OBSERVATION_A,
        ingestionId: INGESTION_A,
        observedAt: LATE,
        aggregate: 'unaffected',
        supports: [{ kind: 'product', outcome: 'unaffected', version: '8.0.0' }],
      }),
    ]);
    freeze(input);
    const projection = found(input);
    expect(projection.aggregate).toBe('unaffected');
    expect(projection.evidence).toMatchObject({ knownVersions: ['8.0.0'] });
  });
});

describe('candidate cardinality', () => {
  it('selects from more than 1024 legal candidates without a count ceiling', () => {
    const count = 1025;
    const rows: Record<string, unknown>[] = [];
    for (let index = 1; index <= count; index += 1) {
      const suffix = index.toString(16).padStart(12, '0');
      rows.push(
        repeatedObservation({
          observationId: `15151515-1515-4151-8151-${suffix}`,
          ingestionId: `abababab-abab-4aba-8aba-${suffix}`,
          observedAt: index === count ? '2026-10-09T16:00:00.000001Z' : TIE,
          aggregate: 'affected',
          supports: [affected(`v${String(index)}`, index)],
        }),
      );
    }
    const winner = rows[count - 1];
    const first = rows[0];
    if (winner === undefined || first === undefined) {
      throw new Error('fixture');
    }
    const projection = found(selection([first, winner, ...rows.slice(1, count - 1)]));
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.observedAt).toBe('2026-10-09T16:00:00.000001Z');
    expect(projection.evidence).toMatchObject({ knownVersions: [`v${String(count)}`] });
  });
});

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '.next') {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else {
      files.push(fullPath);
    }
  }
  return files;
}
