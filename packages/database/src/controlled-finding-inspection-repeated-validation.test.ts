/**
 * Closed repeated-observation facts for inspection.
 * These cases do not open a database and do not expose a history projection.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
} from '@patchpilot/domain';
import { describe, expect, it } from 'vitest';

import { canonicalRepeatedObservationReplayFingerprint } from '../../domain/dist/findings/controlled-observation/support.js';
import {
  repeatedObservationFactsAgree,
  repeatedSupportLinksStayOnLaterObservations,
  type RepeatedObservationFact,
  type RepeatedObservationInspectionFacts,
  type RepeatedObservationSupportFact,
} from './controlled-finding-inspection-repeated-validation.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const FINDING = '22222222-2222-4222-8222-222222222222';
const ASSET = '33333333-3333-4333-8333-333333333333';
const COMPONENT = '44444444-4444-4444-8444-444444444444';
const VULNERABILITY = '55555555-5555-4555-8555-555555555555';
const CREATION_INGESTION = '66666666-6666-4666-8666-666666666666';
const LATER_INGESTION = '77777777-7777-4777-8777-777777777777';
const SBOM = '88888888-8888-4888-8888-888888888888';
const OCCURRENCE = '99999999-9999-4999-8999-999999999999';
const EVIDENCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const MEMBERSHIP = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const CORRELATION = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const CREATED = '2026-10-02T13:00:00.000Z';
const OBSERVED = '2026-10-08T12:00:00.000Z';

function supportFingerprint(): string {
  return canonicalRepeatedObservationEvidenceFingerprint([EVIDENCE], [], 1);
}

function replayFingerprint(
  aggregate = 'affected',
  result = 'present',
  support = supportFingerprint(),
  count = 1,
  ingestionId = LATER_INGESTION,
): string {
  return canonicalRepeatedObservationReplayFingerprint({
    organizationId: ORG,
    findingId: FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomIngestionId: ingestionId,
    aggregate,
    mappedResult: result,
    supportFingerprint: support,
    supportCount: count,
  });
}

function link(
  overrides: Partial<RepeatedObservationSupportFact> = {},
): RepeatedObservationSupportFact {
  return {
    findingId: FINDING,
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    sbomId: SBOM,
    sbomIngestionId: LATER_INGESTION,
    occurrenceId: OCCURRENCE,
    supportKind: 'product_match_evidence',
    evidenceId: EVIDENCE,
    outcome: 'affected',
    occurrenceVersionKnown: true,
    occurrenceAligned: true,
    evidenceOutcome: 'affected',
    evidenceAligned: true,
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
    occurrenceVersion: '1.2.0',
    evidenceRawObservedVersion: '1.2.0',
    ...overrides,
  };
}

function observation(
  overrides: Partial<RepeatedObservationFact> = {},
  support: readonly RepeatedObservationSupportFact[] = [link()],
): RepeatedObservationFact {
  const aggregate = overrides.aggregate === undefined ? 'affected' : overrides.aggregate;
  const result = overrides.result ?? 'present';
  const count =
    overrides.evidenceLinkCount === undefined ? support.length : overrides.evidenceLinkCount;
  const fingerprint =
    overrides.replayFingerprint ??
    replayFingerprint(aggregate ?? 'affected', result, supportFingerprint(), count ?? 0);
  const evidence = {
    schemaVersion: FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    aggregate,
    mappedResult: result,
    evidenceLinkCount: count,
    replayFingerprint: fingerprint,
  };
  return {
    organizationId: ORG,
    findingId: FINDING,
    sbomId: SBOM,
    sbomIngestionId: LATER_INGESTION,
    method: 'controlled_finding_repeated_observation',
    result,
    occurrenceId: null,
    transitionClassification: 'evidence_observation',
    creationPurpose: null,
    creationPolicyId: null,
    creationPolicyVersion: null,
    observationPurpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    observationPolicyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    observationPolicyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    aggregate,
    evidenceLinkCount: count,
    replayFingerprint: fingerprint,
    actorMembershipId: MEMBERSHIP,
    correlationId: CORRELATION,
    observedAt: OBSERVED,
    createdAt: OBSERVED,
    membershipPresent: true,
    absenceGraphCompleteness: null,
    absenceComponentCount: null,
    absenceDependencyEdgeCount: null,
    evidence: overrides.evidence === undefined ? evidence : overrides.evidence,
    unknownVersionOccurrenceHasEvidence: false,
    ingestion: {
      present: true,
      organizationId: ORG,
      assetId: ASSET,
      sbomId: SBOM,
      state: 'completed',
      normalizationVersion: '2',
      strictlyLater: true,
      graphCompleteness: 'no_dependencies',
      componentCount: 1,
      dependencyEdgeCount: 0,
      liveComponentCount: 1,
      liveEdgeCount: 0,
      targetOccurrenceIds: [OCCURRENCE],
    },
    links: support,
    ...overrides,
  };
}

function facts(
  repeated: readonly RepeatedObservationFact[],
  last = repeated.length === 0 ? CREATED : OBSERVED,
): RepeatedObservationInspectionFacts {
  return {
    target: {
      organizationId: ORG,
      findingId: FINDING,
      assetId: ASSET,
      componentId: COMPONENT,
      vulnerabilityId: VULNERABILITY,
    },
    finding: {
      firstObservedAt: CREATED,
      lastObservedAt: last,
      createdAt: CREATED,
      updatedAt: last,
    },
    creation: {
      observedAt: CREATED,
      createdAt: CREATED,
      sbomIngestionId: CREATION_INGESTION,
    },
    repeated,
  };
}

describe('repeated observation inspection facts', () => {
  it('accepts creation alone and one legal affected observation', () => {
    expect(repeatedObservationFactsAgree(facts([]))).toBe(true);
    expect(repeatedObservationFactsAgree(facts([observation()]))).toBe(true);
  });

  it('rejects a later timestamp that no repeated observation explains', () => {
    expect(repeatedObservationFactsAgree(facts([], OBSERVED))).toBe(false);
    const early = observation({ observedAt: CREATED, createdAt: CREATED });
    expect(repeatedObservationFactsAgree(facts([early], OBSERVED))).toBe(false);
  });

  it('rejects aggregate and result disagreement', () => {
    expect(
      repeatedObservationFactsAgree(
        facts([observation({ aggregate: 'affected', result: 'absent' })]),
      ),
    ).toBe(false);
  });

  it('rejects support that does not carry the stored aggregate', () => {
    const unaffected = link({ outcome: 'unaffected', evidenceOutcome: 'unaffected' });
    expect(repeatedObservationFactsAgree(facts([observation({}, [unaffected])]))).toBe(false);
  });

  it('rejects a non-absence observation with missing links', () => {
    expect(
      repeatedObservationFactsAgree(
        facts([
          observation(
            {
              evidenceLinkCount: 1,
              links: [],
              ingestion: { ...observation().ingestion, targetOccurrenceIds: [OCCURRENCE] },
            },
            [],
          ),
        ]),
      ),
    ).toBe(false);
  });

  it('accepts legal unaffected, unknown, and component-absent observations', () => {
    const unaffected = link({ outcome: 'unaffected', evidenceOutcome: 'unaffected' });
    const unaffectedSupport = canonicalRepeatedObservationEvidenceFingerprint([EVIDENCE], [], 1);
    const unaffectedRow = observation(
      {
        aggregate: 'unaffected',
        result: 'absent',
        replayFingerprint: replayFingerprint('unaffected', 'absent', unaffectedSupport, 1),
      },
      [unaffected],
    );
    const unknownSupport = canonicalRepeatedObservationEvidenceFingerprint([], [OCCURRENCE], 1);
    const unknownLink = link({
      supportKind: 'unknown_version_occurrence',
      evidenceId: null,
      outcome: null,
      occurrenceVersionKnown: false,
      evidenceOutcome: null,
      evidenceAligned: false,
      productOrigin: null,
      evaluatorId: null,
      evaluatorVersion: null,
      matchingPolicyId: null,
      matchingPolicyVersion: null,
      productEvidencePolicyId: null,
      productEvidencePolicyVersion: null,
      evidenceSchemaVersion: null,
      findingCreation: null,
      suppressionAuthority: null,
      occurrenceVersion: '',
      evidenceRawObservedVersion: null,
    });
    const unknownRow = observation(
      {
        aggregate: 'unknown',
        result: 'inconclusive',
        replayFingerprint: replayFingerprint('unknown', 'inconclusive', unknownSupport, 1),
      },
      [unknownLink],
    );
    const absenceSupport = canonicalRepeatedObservationAbsenceFingerprint({
      sbomIngestionId: LATER_INGESTION,
      graphCompleteness: 'no_dependencies',
      componentCount: 1,
      occurrenceCardinality: 1,
      dependencyEdgeCount: 0,
    });
    const absent = observation(
      {
        aggregate: 'component_absent',
        result: 'absent',
        evidenceLinkCount: 0,
        replayFingerprint: replayFingerprint('component_absent', 'absent', absenceSupport, 0),
        absenceGraphCompleteness: 'no_dependencies',
        absenceComponentCount: 1,
        absenceDependencyEdgeCount: 0,
        ingestion: {
          ...observation().ingestion,
          targetOccurrenceIds: [],
          graphCompleteness: 'no_dependencies',
          componentCount: 1,
          dependencyEdgeCount: 0,
          liveComponentCount: 1,
          liveEdgeCount: 0,
        },
      },
      [],
    );
    expect(repeatedObservationFactsAgree(facts([unaffectedRow]))).toBe(true);
    expect(repeatedObservationFactsAgree(facts([unknownRow]))).toBe(true);
    expect(repeatedObservationFactsAgree(facts([absent]))).toBe(true);
  });

  it('rejects an unknown-version proof that carries evidence', () => {
    const proof = link({
      supportKind: 'unknown_version_occurrence',
      evidenceId: EVIDENCE,
      outcome: null,
      occurrenceVersionKnown: false,
      evidenceOutcome: null,
      evidenceAligned: false,
    });
    expect(
      repeatedObservationFactsAgree(
        facts([observation({ aggregate: 'unknown', result: 'inconclusive' }, [proof])]),
      ),
    ).toBe(false);
  });

  it('rejects duplicate and cross-target support', () => {
    const duplicate = observation({ evidenceLinkCount: 2 }, [link(), link()]);
    expect(repeatedObservationFactsAgree(facts([duplicate]))).toBe(false);
    const foreign = link({ assetId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' });
    expect(repeatedObservationFactsAgree(facts([observation({}, [foreign])]))).toBe(false);
  });

  it('rejects unsupported evaluator lineage and support outside the later observation', () => {
    const hostile = 'untrusted_evaluator';
    const rejected = repeatedObservationFactsAgree(
      facts([observation({}, [link({ evaluatorId: hostile })])]),
    );
    expect(rejected).toBe(false);
    expect(JSON.stringify(rejected)).not.toContain(hostile);
    expect(
      repeatedSupportLinksStayOnLaterObservations(
        [FINDING],
        ['dddddddd-dddd-4ddd-8ddd-dddddddddddd'],
      ),
    ).toBe(false);
    expect(repeatedSupportLinksStayOnLaterObservations([], [])).toBe(true);
    expect(repeatedSupportLinksStayOnLaterObservations([FINDING], [])).toBe(true);
  });

  it('rejects component absence that still has support links', () => {
    const absent = observation(
      {
        aggregate: 'component_absent',
        result: 'absent',
        evidenceLinkCount: 0,
        absenceGraphCompleteness: 'no_dependencies',
        absenceComponentCount: 1,
        absenceDependencyEdgeCount: 0,
        links: [link()],
        ingestion: {
          ...observation().ingestion,
          targetOccurrenceIds: [],
          liveComponentCount: 1,
          liveEdgeCount: 0,
        },
      },
      [link()],
    );
    expect(repeatedObservationFactsAgree(facts([absent]))).toBe(false);
  });

  it('keeps repeated support identifiers out of the validation result', () => {
    const rejected = repeatedObservationFactsAgree(
      facts([observation({}, [link({ assetId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' })])]),
    );
    expect(rejected).toBe(false);
    expect(JSON.stringify(rejected)).not.toContain(EVIDENCE);
    expect(JSON.stringify(rejected)).not.toContain(MEMBERSHIP);
  });

  it('does not write and is not a package export', () => {
    const source = readFileSync(
      fileURLToPath(import.meta.url).replace(/\.test\.ts$/, '.ts'),
      'utf8',
    );
    expect(source).not.toMatch(/(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"?finding/i);
    expect(source).not.toContain('$executeRaw');
    expect(source).not.toContain('reviewerIdentity');
    const barrel = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'index.ts'),
      'utf8',
    );
    expect(barrel).not.toContain('repeatedObservationFactsAgree');
    expect(barrel).not.toContain('repeatedObservationInspectionAgrees');
    expect(barrel).not.toContain('repeatedSupportLinksStayOnLaterObservations');
    const apps = walk(
      path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'apps'),
    );
    const offenders = apps.filter((filePath) => {
      if (!/\.(ts|tsx)$/.test(filePath)) {
        return false;
      }
      const text = readFileSync(filePath, 'utf8');
      return (
        text.includes('createControlledFindingRepeatedObservationPersistence') ||
        text.includes('repeatedObservationInspectionAgrees')
      );
    });
    expect(offenders).toEqual([]);
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
