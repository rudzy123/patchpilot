/**
 * Framework-independent Finding inspection.
 * These tests do not open a database.
 */

import { describe, expect, it } from 'vitest';

import {
  FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  openFindingInspection,
  type FindingInspectionEvidenceBundle,
  type FindingInspectionLinkRecord,
  type FindingInspectionLoad,
  type FindingInspectionPort,
} from './index.js';

const FINDING_ID = '11111111-1111-4111-8111-111111111111';
const ASSET_ID = '22222222-2222-4222-8222-222222222222';
const COMPONENT_ID = '33333333-3333-4333-8333-333333333333';
const VULNERABILITY_ID = '44444444-4444-4444-8444-444444444444';
const OBSERVATION_ID = '55555555-5555-4555-8555-555555555555';
const INGESTION_ID = '66666666-6666-4666-8666-666666666666';
const ORGANIZATION_ID = '99999999-9999-4999-8999-999999999999';

function link(index: number, version: string): FindingInspectionLinkRecord {
  const suffix = index.toString(16).padStart(12, '0');
  return {
    evidenceId: `77777777-7777-4777-8777-${suffix}`,
    findingObservationId: OBSERVATION_ID,
    assetId: ASSET_ID,
    componentId: COMPONENT_ID,
    vulnerabilityId: VULNERABILITY_ID,
    sbomIngestionId: INGESTION_ID,
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
    occurrenceAssetId: ASSET_ID,
    occurrenceComponentId: COMPONENT_ID,
    occurrenceIngestionId: INGESTION_ID,
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
    assetId: ASSET_ID,
    componentId: COMPONENT_ID,
    vulnerabilityId: VULNERABILITY_ID,
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
    assetCurrentIngestionId: INGESTION_ID,
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
        sbomIngestionId: INGESTION_ID,
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

function port(load: FindingInspectionPort['load']): {
  readonly port: FindingInspectionPort;
  readonly calls: number;
} {
  const state = { calls: 0 };
  return {
    port: {
      async load(query) {
        state.calls += 1;
        return load(query);
      },
    },
    get calls() {
      return state.calls;
    },
  };
}

function command(findingId = FINDING_ID, organizationId = ORGANIZATION_ID) {
  return {
    schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
    trustedContext: {
      schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
      organizationId,
    },
    findingId,
  };
}

describe('controlled finding inspection projection', () => {
  it('projects one current affected version without lifecycle fields', async () => {
    const loaded = port(async () => ({ status: 'ready', bundle: bundle(['1.2.0']) }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'found',
      projection: {
        schemaVersion: 'finding_inspection_projection_v1',
        findingId: FINDING_ID,
        state: 'open',
        asset: { id: ASSET_ID, displayName: 'asset <untrusted>' },
        component: {
          id: COMPONENT_ID,
          ecosystem: 'npm',
          namespace: null,
          name: 'widget <untrusted>',
        },
        vulnerability: { id: VULNERABILITY_ID, publicId: 'REVIEWED-NPM-1' },
        affectedVersions: {
          values: ['1.2.0'],
          truncated: false,
          omittedDistinctCount: 0,
          distinctCount: 1,
        },
        affectedOccurrenceCount: 1,
        otherOccurrenceCount: 0,
        otherOccurrenceClassification: 'no_other_occurrences_in_creation_ingestion',
        createdAt: '2026-10-06T16:00:00.000Z',
        creationObservationPolicy: {
          policyId: 'finding_creation_policy_v1',
          policyVersion: 1,
        },
        explanationCodes: [
          'finding_created_from_affected_product_match_evidence',
          'maintainer_reviewed_advisory_source',
          'independent_reviewer_approval',
          'affected_within_introduced_fixed_range',
        ],
        creationEvidenceApplicability: 'current',
      },
    });
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain('reviewerIdentity');
    expect(encoded).not.toContain('fingerprint');
    expect(encoded).not.toContain('membership');
    expect(encoded).not.toContain('prisma');
    expect(encoded).not.toContain('unaffected');
    expect(loaded.calls).toBe(1);
  });

  it('sorts distinct affected versions and keeps the occurrence count', async () => {
    const loaded = port(async () => ({
      status: 'ready',
      bundle: bundle(['1.2.0', '1.10.0', '1.1.0']),
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions.values).toEqual(['1.1.0', '1.10.0', '1.2.0']);
    expect(result.projection.affectedOccurrenceCount).toBe(3);
    expect(result.projection.explanationCodes).toContain('several_affected_occurrences');
  });

  it('deduplicates exact version text and still counts both occurrences', async () => {
    const first = link(1, '1.2.0');
    const second = link(2, '1.2.0');
    const value = bundle(['1.2.0']);
    const observation = value.observations[0];
    if (observation === undefined) {
      throw new Error('missing observation');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        links: [second, first],
        creationIngestionOccurrenceCount: 2,
        observations: [{ ...observation, affectedEvidenceCount: 2 }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions).toEqual({
      values: ['1.2.0'],
      truncated: false,
      omittedDistinctCount: 0,
      distinctCount: 1,
    });
    expect(result.projection.affectedOccurrenceCount).toBe(2);
  });

  it('truncates the displayed versions and reports the omitted count', async () => {
    const versions = Array.from(
      { length: FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT + 1 },
      (_, index) => {
        return `1.0.${String(index + 1)}`;
      },
    );
    const loaded = port(async () => ({ status: 'ready', bundle: bundle(versions) }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions.truncated).toBe(true);
    expect(result.projection.affectedVersions.values).toHaveLength(
      FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
    );
    expect(result.projection.affectedVersions.omittedDistinctCount).toBe(1);
    expect(result.projection.affectedVersions.distinctCount).toBe(versions.length);
    expect(result.projection.affectedOccurrenceCount).toBe(versions.length);
  });

  it('counts unlinked occurrences without calling them unaffected', async () => {
    const value = bundle(['1.1.0']);
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        otherOccurrenceCount: 1,
        creationIngestionOccurrenceCount: 2,
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.otherOccurrenceCount).toBe(1);
    expect(result.projection.otherOccurrenceClassification).toBe(
      'other_occurrences_not_in_creation_evidence',
    );
    expect(result.projection.explanationCodes).toContain(
      'other_occurrences_not_in_creation_evidence',
    );
    expect(JSON.stringify(result)).not.toContain('unaffected');
  });

  it.each([
    ['withdrawn', { withdrawal: 'withdrawn' }],
    ['quarantined', { quarantine: 'quarantined' }],
    ['superseded', { hasSuccessor: true }],
    ['binding', { bindingReviewed: false }],
    ['ingestion', { assetCurrentIngestionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }],
  ] as const)('classifies %s creation evidence as historical', async (_label, patch) => {
    const value = bundle(['1.1.0']);
    const current = value.links[0];
    if (current === undefined) {
      throw new Error('missing link');
    }
    const { assetCurrentIngestionId, ...linkPatch } = {
      assetCurrentIngestionId: value.assetCurrentIngestionId,
      ...patch,
    };
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        assetCurrentIngestionId,
        links: [{ ...current, ...linkPatch }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.creationEvidenceApplicability).toBe('historical');
    expect(result.projection.explanationCodes).toContain('creation_evidence_historical');
  });

  it('fails closed on malformed persisted rows', async () => {
    const cases: FindingInspectionEvidenceBundle[] = [];
    const resolved = bundle(['1.1.0']);
    cases.push({ ...resolved, state: 'resolved' });
    cases.push({ ...resolved, dueAt: '2026-10-07T00:00:00.000Z' });
    cases.push({ ...resolved, remediationTaskCount: 1 });
    cases.push({ ...resolved, observations: [] });
    cases.push({ ...resolved, links: [] });
    const contradictory = resolved.links[0];
    if (contradictory === undefined) {
      throw new Error('missing link');
    }
    cases.push({
      ...resolved,
      links: [{ ...contradictory, assetId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }],
    });
    cases.push({
      ...resolved,
      links: [{ ...contradictory, evidenceOutcome: 'unaffected' }],
    });
    cases.push({
      ...resolved,
      links: [{ ...contradictory, evaluatorId: 'untrusted_evaluator' }],
    });
    const observation = resolved.observations[0];
    if (observation === undefined) {
      throw new Error('missing observation');
    }
    cases.push({
      ...resolved,
      observations: [{ ...observation, replayAgrees: false }],
    });
    const reader = openFindingInspection({
      async load() {
        const next = cases.shift();
        if (next === undefined) {
          return { status: 'internal_failure' };
        }
        return { status: 'ready', bundle: next };
      },
    });
    const statuses: string[] = [];
    for (let index = 0; index < 9; index += 1) {
      const result = await reader.inspect(command());
      statuses.push(result.status);
    }
    expect(statuses).toEqual(Array.from({ length: 9 }, () => 'malformed_persisted_state'));
  });

  it('reports missing evidence parents as evidence unavailable', async () => {
    const value = bundle(['1.1.0']);
    const current = value.links[0];
    if (current === undefined) {
      throw new Error('missing link');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        links: [{ ...current, evidencePresent: false, explanationCodes: [] }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'evidence_unavailable',
    });
  });

  it('fails closed when stored evidence targets disagree with the finding', async () => {
    const value = bundle(['1.1.0']);
    const current = value.links[0];
    if (current === undefined) {
      throw new Error('missing link');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        links: [{ ...current, evidencePresent: false, evidenceTargetAligned: false }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'malformed_persisted_state',
    });
  });

  it.each(['failed', 'processing', 'rejected', 'quarantined'] as const)(
    'fails closed when the linked ingestion is %s',
    async (ingestionState) => {
      const value = bundle(['1.1.0']);
      const current = value.links[0];
      if (current === undefined) {
        throw new Error('missing link');
      }
      const loaded = port(async () => ({
        status: 'ready',
        bundle: { ...value, links: [{ ...current, ingestionState }] },
      }));
      const result = await openFindingInspection(loaded.port).inspect(command());
      expect(result.status).toBe('malformed_persisted_state');
      expect(JSON.stringify(result)).not.toContain(ingestionState);
    },
  );

  it('fails closed on an incomplete normalization version', async () => {
    const value = bundle(['1.1.0']);
    const current = value.links[0];
    if (current === undefined) {
      throw new Error('missing link');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: { ...value, links: [{ ...current, normalizationVersion: '1' }] },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('malformed_persisted_state');
  });

  it('keeps every linked version when only one occurrence is historical', async () => {
    const value = bundle(['1.2.0', '1.1.0']);
    const first = value.links[0];
    const second = value.links[1];
    if (first === undefined || second === undefined) {
      throw new Error('missing link');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        links: [first, { ...second, hasSuccessor: true }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.creationEvidenceApplicability).toBe('historical');
    expect(result.projection.affectedVersions.values).toEqual(['1.1.0', '1.2.0']);
    expect(result.projection.affectedOccurrenceCount).toBe(2);
    expect(result.projection.state).toBe('open');
  });

  it('preserves the occurrence count when display truncation and other occurrences combine', async () => {
    const versions = Array.from(
      { length: FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT + 1 },
      (_, index) => `1.0.${String(index + 1)}`,
    );
    const value = bundle(versions);
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        otherOccurrenceCount: 2,
        creationIngestionOccurrenceCount: versions.length + 2,
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions.truncated).toBe(true);
    expect(result.projection.affectedVersions.omittedDistinctCount).toBe(1);
    expect(result.projection.affectedOccurrenceCount).toBe(versions.length);
    expect(result.projection.otherOccurrenceCount).toBe(2);
    expect(result.projection.otherOccurrenceClassification).toBe(
      'other_occurrences_not_in_creation_evidence',
    );
    expect(JSON.stringify(result)).not.toContain('unaffected');
  });

  it('keeps untrusted display values as data and does not mark them safe to render', async () => {
    const value = bundle(['1.2.0 <observed>']);
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        assetDisplayName: 'asset <untrusted>',
        componentName: 'widget <untrusted>',
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.asset.displayName).toBe('asset <untrusted>');
    expect(result.projection.component.name).toBe('widget <untrusted>');
    expect(result.projection.affectedVersions.values).toEqual(['1.2.0 <observed>']);
    expect(JSON.stringify(result)).not.toContain('safeToRender');
    expect(JSON.stringify(result)).not.toContain('renderingSafe');
    const planted = {
      ...value,
      reviewerIdentity: 'reviewer.two',
      organizationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      replayFingerprint: 'c'.repeat(64),
    };
    const hidden = await openFindingInspection({
      async load() {
        return { status: 'ready', bundle: planted };
      },
    }).inspect(command());
    const encoded = JSON.stringify(hidden);
    expect(encoded).not.toContain('reviewer.two');
    expect(encoded).not.toContain('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    expect(encoded).not.toContain('c'.repeat(64));
  });

  it('does not echo a contradictory explanation code', async () => {
    const value = bundle(['1.1.0']);
    const current = value.links[0];
    if (current === undefined) {
      throw new Error('missing link');
    }
    const loaded = port(async () => ({
      status: 'ready',
      bundle: {
        ...value,
        links: [{ ...current, explanationCodes: ['reviewer_secret_code'] }],
      },
    }));
    const result = await openFindingInspection(loaded.port).inspect(command());
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain('reviewer_secret_code');
  });
});

describe('controlled finding inspection tenancy', () => {
  it('uses one organization-scoped load and equates foreign and absent results', async () => {
    const queries: unknown[] = [];
    const reader = openFindingInspection({
      async load(query) {
        queries.push(query);
        return { status: 'not_found' };
      },
    });
    const foreign = await reader.inspect(command(FINDING_ID));
    const absent = await reader.inspect(command('abababab-abab-4bab-8bab-abababababab'));
    expect(foreign).toEqual(absent);
    expect(foreign).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(Object.keys(foreign)).toEqual(['schemaVersion', 'status']);
    expect(queries).toEqual([
      { organizationId: ORGANIZATION_ID, findingId: FINDING_ID },
      { organizationId: ORGANIZATION_ID, findingId: 'abababab-abab-4bab-8bab-abababababab' },
    ]);
    expect(JSON.stringify(foreign)).not.toContain(FINDING_ID);
  });

  it('repeats the same public miss for a foreign id and an absent id', async () => {
    const reader = openFindingInspection({
      async load() {
        return { status: 'not_found' };
      },
    });
    const firstForeign = await reader.inspect(command(FINDING_ID));
    const secondForeign = await reader.inspect(command(FINDING_ID));
    const firstAbsent = await reader.inspect(command('abababab-abab-4bab-8bab-abababababab'));
    const secondAbsent = await reader.inspect(command('abababab-abab-4bab-8bab-abababababab'));
    expect(firstForeign).toEqual(secondForeign);
    expect(firstAbsent).toEqual(secondAbsent);
    expect(firstForeign).toEqual(firstAbsent);
    expect(Object.keys(firstForeign).sort()).toEqual(['schemaVersion', 'status']);
  });

  it('does not query when the command is untrusted or malformed', async () => {
    let calls = 0;
    const reader = openFindingInspection({
      async load(): Promise<FindingInspectionLoad> {
        calls += 1;
        return { status: 'not_found' };
      },
    });
    const malformed = await reader.inspect({
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: 'not-a-uuid',
      },
      findingId: FINDING_ID,
    });
    const ambient = await reader.inspect({ ...command(), role: 'admin' });
    const host = command();
    Object.defineProperty(host, 'findingId', { get: () => FINDING_ID });
    const getter = await reader.inspect(host);
    expect(malformed).toEqual(ambient);
    expect(ambient).toEqual(getter);
    expect(malformed.status).toBe('internal_failure');
    expect(calls).toBe(0);
  });
});
