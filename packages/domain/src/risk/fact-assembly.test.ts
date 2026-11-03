/**
 * Pure KEV token mapping and priority fact assembly.
 * No database and no policy engine.
 */

import { describe, expect, it } from 'vitest';

import {
  parseCalendarDate,
  type CalendarDate,
  type CanonicalCve,
} from '../intelligence/normalize.js';
import type { FindingState } from '../lifecycle.js';
import type { RiskCalculationKevSourceV2 } from '../json-documents.js';
import { parseExactCanonicalCve } from '../vulnerability/cve-identity.js';
import type {
  ActiveKevCatalogFreshness,
  ActiveKevMembership,
} from '../vulnerability/kev-membership.js';
import { PRIORITY_FACTOR_IDS, PRIORITY_FINDING_AGE_DAYS_MAX } from './catalog.js';
import {
  assemblePriorityFacts,
  assembleRiskCalculationFactorSources,
  assessFindingRiskEligibility,
  findingRiskCanonicalCveFailureCodes,
  findingRiskFactAssemblyFailureCodes,
  findingRiskIneligibleReasons,
  findingRiskKevMappingFailureCodes,
  findingRiskKevMembershipError,
  findingRiskKevMembershipErrorCodes,
  mapActiveKevToListedFact,
  selectFindingRiskCanonicalCves,
  type FindingRiskCreationEvidence,
  type FindingRiskKevMembershipError,
  type FindingRiskSourceAsset,
  type FindingRiskSourceSnapshot,
} from './fact-assembly.js';
import type { PriorityKevListedFact } from './facts.js';

const FIRST_OBSERVED_AT = new Date('2026-01-01T00:00:00.000Z');
const AS_OF = new Date('2026-01-03T01:00:00.000Z');
const RELEASED_AT = new Date('2026-09-01T12:00:00.000Z');
const CATALOG_VERSION = '2099.01.01';

const CVE_A = requireCve('CVE-1900-00001');
const CVE_B = requireCve('CVE-1900-00002');
const DATE_ADDED = requireCalendar('2024-01-15');
const DUE_DATE = requireCalendar('2024-02-15');

const DEFAULT_ASSET: FindingRiskSourceAsset = {
  sensitivityClass: 'production',
  internetExposure: 'unknown',
  businessCriticality: 'unspecified',
  dataClassification: 'unspecified',
};

const LISTED_CURRENT: PriorityKevListedFact = Object.freeze({
  state: 'observed',
  value: 'listed_catalog_current',
});

function requireCve(value: string): CanonicalCve {
  const parsed = parseExactCanonicalCve(value);
  if (!parsed.ok) {
    throw new Error(`expected canonical CVE ${value}`);
  }
  return parsed.value;
}

function requireCalendar(value: string): CalendarDate {
  const parsed = parseCalendarDate(value);
  if (!parsed.ok) {
    throw new Error(`expected calendar date ${value}`);
  }
  return parsed.value;
}

function evidence(
  overrides: Partial<FindingRiskCreationEvidence> = {},
): FindingRiskCreationEvidence {
  return {
    evidenceId: overrides.evidenceId ?? 'evidence-1',
    advisoryRevisionId: overrides.advisoryRevisionId ?? 'revision-1',
    componentOccurrenceId: overrides.componentOccurrenceId ?? 'occurrence-1',
    vulnerabilityId: overrides.vulnerabilityId ?? 'vulnerability-1',
    sbomIngestionId: overrides.sbomIngestionId ?? 'ingestion-1',
    isDirect: overrides.isDirect === undefined ? true : overrides.isDirect,
    withdrawalClassification: overrides.withdrawalClassification ?? 'not_withdrawn',
    bindingClassification: overrides.bindingClassification ?? 'one_cve_alias_evidence',
    canonicalCves: overrides.canonicalCves ?? ['CVE-1900-00001'],
  };
}

function sourceSnapshot(input?: {
  readonly finding?: Partial<FindingRiskSourceSnapshot['finding']>;
  readonly asset?: FindingRiskSourceAsset | null;
  readonly creationEvidence?: readonly FindingRiskCreationEvidence[];
  readonly hasControlledCreationObservation?: boolean;
}): FindingRiskSourceSnapshot {
  const finding = input?.finding;
  return {
    finding: {
      id: finding?.id ?? 'finding-1',
      organizationId: finding?.organizationId ?? 'org-1',
      state: finding?.state ?? 'open',
      version: finding?.version === undefined ? 1 : finding.version,
      firstObservedAt: finding?.firstObservedAt ?? FIRST_OBSERVED_AT,
      currentRiskCalculationId:
        finding?.currentRiskCalculationId === undefined ? null : finding.currentRiskCalculationId,
      dueAt: finding?.dueAt === undefined ? null : finding.dueAt,
      assetId: finding?.assetId ?? 'asset-1',
    },
    asset: input?.asset === undefined ? DEFAULT_ASSET : input.asset,
    creationEvidence: input?.creationEvidence ?? [evidence()],
    hasControlledCreationObservation: input?.hasControlledCreationObservation ?? true,
  };
}

function listed(
  freshness: ActiveKevCatalogFreshness,
  cve: CanonicalCve = CVE_A,
): ActiveKevMembership {
  return {
    status: 'listedInActiveKev',
    cve,
    catalogVersion: CATALOG_VERSION,
    catalogReleasedAt: RELEASED_AT,
    dateAdded: DATE_ADDED,
    kevDueDate: DUE_DATE,
    knownRansomwareCampaignUse: 'known',
    freshness,
  };
}

function absent(
  freshness: ActiveKevCatalogFreshness,
  cve: CanonicalCve = CVE_A,
): ActiveKevMembership {
  return {
    status: 'absent',
    cve,
    catalogVersion: CATALOG_VERSION,
    catalogReleasedAt: RELEASED_AT,
    freshness,
  };
}

function unavailableMembership(): ActiveKevMembership {
  return { status: 'unavailable', reason: 'no_active_generation' };
}

function expectFacts(
  snapshot: FindingRiskSourceSnapshot,
  kevFact: PriorityKevListedFact,
  asOf: Date = AS_OF,
): PriorityFactInputSuccess {
  const result = assemblePriorityFacts(snapshot, kevFact, asOf);
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error('expected assembled facts');
  }
  return result.value;
}

type PriorityFactInputSuccess = Extract<
  ReturnType<typeof assemblePriorityFacts>,
  { ok: true }
>['value'];

describe('finding risk eligibility', () => {
  it('accepts an open version-1 finding with creation evidence', () => {
    const snapshot = sourceSnapshot({
      creationEvidence: [evidence({ withdrawalClassification: 'withdrawn', canonicalCves: [] })],
    });
    expect(assessFindingRiskEligibility(snapshot)).toEqual({ outcome: 'eligible' });
  });

  it('accepts a finding whose asset row is absent', () => {
    expect(assessFindingRiskEligibility(sourceSnapshot({ asset: null }))).toEqual({
      outcome: 'eligible',
    });
  });

  it.each([
    ['state_not_open', sourceSnapshot({ finding: { state: 'resolved' satisfies FindingState } })],
    ['version_not_one', sourceSnapshot({ finding: { version: 2 } })],
    [
      'current_risk_calculation_present',
      sourceSnapshot({ finding: { currentRiskCalculationId: 'calculation-1' } }),
    ],
    ['due_at_present', sourceSnapshot({ finding: { dueAt: FIRST_OBSERVED_AT } })],
    [
      'controlled_creation_observation_absent',
      sourceSnapshot({ hasControlledCreationObservation: false }),
    ],
    ['creation_evidence_absent', sourceSnapshot({ creationEvidence: [] })],
  ] as const)('rejects %s', (reason, snapshot) => {
    expect(assessFindingRiskEligibility(snapshot)).toEqual({ outcome: 'ineligible', reason });
  });

  it('reports the earliest ineligible reason', () => {
    const snapshot = sourceSnapshot({
      finding: {
        state: 'mitigated',
        version: 4,
        currentRiskCalculationId: 'calculation-1',
        dueAt: FIRST_OBSERVED_AT,
      },
      hasControlledCreationObservation: false,
      creationEvidence: [],
    });
    expect(assessFindingRiskEligibility(snapshot)).toEqual({
      outcome: 'ineligible',
      reason: 'state_not_open',
    });
    expect(findingRiskIneligibleReasons[0]).toBe('state_not_open');
  });
});

describe('canonical CVE selection', () => {
  it('returns the supplied alias string and ignores other bindings', () => {
    const snapshot = sourceSnapshot({
      creationEvidence: [
        evidence({
          bindingClassification: 'provider_native_without_cve',
          canonicalCves: ['GHSA-0000-0000-0000', 'CVE-1900-00009'],
        }),
        evidence({
          evidenceId: 'evidence-2',
          canonicalCves: ['GHSA-1111-1111-1111'],
        }),
        evidence({
          evidenceId: 'evidence-3',
          advisoryRevisionId: 'revision-3',
          canonicalCves: ['CVE-1900-00002'],
        }),
        evidence({
          evidenceId: 'evidence-4',
          canonicalCves: ['CVE-1900-00002'],
        }),
      ],
    });
    expect(selectFindingRiskCanonicalCves(snapshot)).toEqual({
      ok: true,
      value: ['GHSA-1111-1111-1111', 'CVE-1900-00002'],
    });
  });

  it.each([[[]], [['CVE-1900-00001', 'CVE-1900-00002']]] as const)(
    'fails closed when one alias row has %j canonical CVEs',
    (canonicalCves) => {
      const snapshot = sourceSnapshot({
        creationEvidence: [
          evidence({ canonicalCves: ['CVE-1900-00001'] }),
          evidence({ evidenceId: 'evidence-2', canonicalCves }),
        ],
      });
      expect(selectFindingRiskCanonicalCves(snapshot)).toEqual({
        ok: false,
        error: { code: 'canonical_cve_cardinality' },
      });
    },
  );

  it('returns an empty set when no alias binding is present', () => {
    const snapshot = sourceSnapshot({
      creationEvidence: [
        evidence({
          bindingClassification: 'provider_native_without_cve',
          canonicalCves: ['CVE-1900-00001'],
        }),
      ],
    });
    expect(selectFindingRiskCanonicalCves(snapshot)).toEqual({ ok: true, value: [] });
    expect(findingRiskCanonicalCveFailureCodes).toEqual(['canonical_cve_cardinality']);
  });
});

describe('KEV token mapping', () => {
  it.each([
    ['current', 'listed_catalog_current'],
    ['stale', 'listed_catalog_stale'],
    ['disabled_with_history', 'listed_catalog_disabled_with_history'],
  ] as const)('maps listed %s membership to %s', (freshness, token) => {
    const result = mapActiveKevToListedFact(1, [listed(freshness)]);
    expect(result).toEqual({ ok: true, value: { state: 'observed', value: token } });
    if (result.ok && result.value.state === 'observed') {
      expect(result.value).not.toHaveProperty('kevDueDate');
      expect(result.value).not.toHaveProperty('knownRansomwareCampaignUse');
      expect(result.value).not.toHaveProperty('requiredAction');
    }
  });

  it('maps every current absence to not listed', () => {
    expect(
      mapActiveKevToListedFact(2, [absent('current', CVE_A), absent('current', CVE_B)]),
    ).toEqual({
      ok: true,
      value: { state: 'observed', value: 'not_listed_catalog_current' },
    });
  });

  it.each([
    ['stale', 'absent_catalog_stale'],
    ['disabled_with_history', 'absent_catalog_disabled_with_history'],
  ] as const)('maps %s absence to unknown %s', (freshness, token) => {
    expect(mapActiveKevToListedFact(1, [absent(freshness)])).toEqual({
      ok: true,
      value: { state: 'unknown', value: token },
    });
  });

  it('lets one non-current absence make a mixed absence unknown', () => {
    expect(
      mapActiveKevToListedFact(3, [
        absent('current', CVE_A),
        absent('stale', CVE_B),
        absent('current', CVE_A),
      ]),
    ).toEqual({
      ok: true,
      value: { state: 'unknown', value: 'absent_catalog_stale' },
    });
  });

  it('lets any agreeing listing win over absence', () => {
    expect(
      mapActiveKevToListedFact(3, [
        absent('stale', CVE_A),
        listed('current', CVE_B),
        listed('current', CVE_A),
      ]),
    ).toEqual({
      ok: true,
      value: { state: 'observed', value: 'listed_catalog_current' },
    });
  });

  it('fails closed when listed freshness values differ', () => {
    expect(mapActiveKevToListedFact(2, [listed('current', CVE_A), listed('stale', CVE_B)])).toEqual(
      {
        ok: false,
        error: { code: 'listed_freshness_disagreement' },
      },
    );
  });

  it('fails closed when unknown absence tokens differ', () => {
    expect(
      mapActiveKevToListedFact(2, [absent('stale', CVE_A), absent('disabled_with_history', CVE_B)]),
    ).toEqual({
      ok: false,
      error: { code: 'unknown_token_disagreement' },
    });
  });

  it('maps zero canonical CVEs to unavailable without a membership result', () => {
    expect(mapActiveKevToListedFact(0, [])).toEqual({
      ok: true,
      value: { state: 'unavailable', reason: 'no_canonical_cve' },
    });
  });

  it('maps an unavailable membership to no active generation', () => {
    expect(mapActiveKevToListedFact(2, [unavailableMembership(), unavailableMembership()])).toEqual(
      {
        ok: true,
        value: { state: 'unavailable', reason: 'no_active_generation' },
      },
    );
  });

  it('fails closed when membership length or status does not cover the CVE count', () => {
    expect(mapActiveKevToListedFact(0, [listed('current')])).toEqual({
      ok: false,
      error: { code: 'membership_count_mismatch' },
    });
    expect(mapActiveKevToListedFact(2, [absent('current')])).toEqual({
      ok: false,
      error: { code: 'membership_count_mismatch' },
    });
    expect(mapActiveKevToListedFact(1.5, [])).toEqual({
      ok: false,
      error: { code: 'membership_count_mismatch' },
    });
    expect(mapActiveKevToListedFact(2, [unavailableMembership(), absent('current')])).toEqual({
      ok: false,
      error: { code: 'membership_status_disagreement' },
    });
    expect(findingRiskKevMappingFailureCodes).toEqual([
      'membership_count_mismatch',
      'listed_freshness_disagreement',
      'unknown_token_disagreement',
      'membership_status_disagreement',
    ]);
  });

  it('keeps membership read errors off ActiveKevMembership', () => {
    type ErrorIsMembership = FindingRiskKevMembershipError extends ActiveKevMembership
      ? true
      : false;
    const errorIsMembership: ErrorIsMembership = false;
    expect(errorIsMembership).toBe(false);
    expect(findingRiskKevMembershipErrorCodes).toEqual([
      'source_missing',
      'inconsistent_active_generation',
      'malformed_persisted_entry',
    ]);
    expect(findingRiskKevMembershipError('source_missing')).toEqual({ code: 'source_missing' });
    expect(findingRiskKevMembershipError('inconsistent_active_generation')).not.toHaveProperty(
      'status',
    );
    expect(findingRiskKevMembershipError('malformed_persisted_entry')).not.toHaveProperty('cve');
  });
});

describe('priority fact assembly', () => {
  it('assembles all ten keys with unavailable severity and fix', () => {
    const facts = expectFacts(sourceSnapshot(), LISTED_CURRENT);
    expect(Object.keys(facts)).toEqual([...PRIORITY_FACTOR_IDS]);
    expect(facts.source_severity).toEqual({ state: 'unavailable' });
    expect(facts.fix_available).toEqual({ state: 'unavailable' });
    expect(facts.kev_listed).toEqual(LISTED_CURRENT);
    expect(facts.environment_sensitivity).toEqual({ state: 'observed', value: 'production' });
    expect(facts.internet_exposure).toEqual({ state: 'unknown', value: 'unknown' });
    expect(facts.business_criticality).toEqual({ state: 'unknown', value: 'unspecified' });
    expect(facts.asset_data_classification).toEqual({ state: 'unknown', value: 'unspecified' });
    expect(facts.direct_dependency).toEqual({ state: 'observed', value: 'direct' });
    expect(facts.finding_age_days).toEqual({ state: 'observed', value: 2 });
    expect(facts.advisory_withdrawn).toEqual({ state: 'observed', value: 'not_withdrawn' });
    expect(findingRiskFactAssemblyFailureCodes).toEqual([
      'finding_age_out_of_range',
      'advisory_withdrawal_disagreement',
    ]);
  });

  it('keeps stored asset enums and leaves a null environment unavailable', () => {
    const facts = expectFacts(
      sourceSnapshot({
        asset: {
          sensitivityClass: null,
          internetExposure: 'internet_facing',
          businessCriticality: 'high',
          dataClassification: 'restricted',
        },
      }),
      LISTED_CURRENT,
    );
    expect(facts.environment_sensitivity).toEqual({ state: 'unavailable' });
    expect(facts.internet_exposure).toEqual({ state: 'observed', value: 'internet_facing' });
    expect(facts.business_criticality).toEqual({ state: 'observed', value: 'high' });
    expect(facts.asset_data_classification).toEqual({ state: 'observed', value: 'restricted' });
  });

  it('marks asset context unavailable when the asset is absent', () => {
    const facts = expectFacts(sourceSnapshot({ asset: null }), LISTED_CURRENT);
    expect(facts.environment_sensitivity).toEqual({ state: 'unavailable' });
    expect(facts.internet_exposure).toEqual({ state: 'unavailable' });
    expect(facts.business_criticality).toEqual({ state: 'unavailable' });
    expect(facts.asset_data_classification).toEqual({ state: 'unavailable' });
    expect(facts.internet_exposure).not.toHaveProperty('reason');
  });

  it('maps agreeing directness and leaves disagreement or null unavailable', () => {
    const transitive = expectFacts(
      sourceSnapshot({
        creationEvidence: [
          evidence({ isDirect: false }),
          evidence({ evidenceId: 'evidence-2', isDirect: false }),
        ],
      }),
      LISTED_CURRENT,
    );
    expect(transitive.direct_dependency).toEqual({ state: 'observed', value: 'transitive' });

    const disagreed = expectFacts(
      sourceSnapshot({
        creationEvidence: [
          evidence({ isDirect: true }),
          evidence({ evidenceId: 'evidence-2', isDirect: false }),
        ],
      }),
      LISTED_CURRENT,
    );
    expect(disagreed.direct_dependency).toEqual({ state: 'unavailable' });

    const missing = expectFacts(
      sourceSnapshot({
        creationEvidence: [evidence({ isDirect: null })],
      }),
      LISTED_CURRENT,
    );
    expect(missing.direct_dependency).toEqual({ state: 'unavailable' });
  });

  it('floors age to whole UTC days', () => {
    const sameDay = expectFacts(
      sourceSnapshot(),
      LISTED_CURRENT,
      new Date(FIRST_OBSERVED_AT.getTime() + 86400000 - 1),
    );
    expect(sameDay.finding_age_days).toEqual({ state: 'observed', value: 0 });

    const exactDay = expectFacts(
      sourceSnapshot(),
      LISTED_CURRENT,
      new Date(FIRST_OBSERVED_AT.getTime() + 86400000),
    );
    expect(exactDay.finding_age_days).toEqual({ state: 'observed', value: 1 });
  });

  it('rejects negative, non-finite, and over-max age', () => {
    const maxAsOf = new Date(
      FIRST_OBSERVED_AT.getTime() + PRIORITY_FINDING_AGE_DAYS_MAX * 86400000,
    );
    const atMax = expectFacts(sourceSnapshot(), LISTED_CURRENT, maxAsOf);
    expect(atMax.finding_age_days).toEqual({
      state: 'observed',
      value: PRIORITY_FINDING_AGE_DAYS_MAX,
    });

    expect(
      assemblePriorityFacts(
        sourceSnapshot(),
        LISTED_CURRENT,
        new Date(FIRST_OBSERVED_AT.getTime() + (PRIORITY_FINDING_AGE_DAYS_MAX + 1) * 86400000),
      ),
    ).toEqual({ ok: false, error: { code: 'finding_age_out_of_range' } });
    expect(
      assemblePriorityFacts(
        sourceSnapshot(),
        LISTED_CURRENT,
        new Date(FIRST_OBSERVED_AT.getTime() - 1),
      ),
    ).toEqual({ ok: false, error: { code: 'finding_age_out_of_range' } });
    expect(
      assemblePriorityFacts(
        sourceSnapshot({ finding: { firstObservedAt: new Date(Number.NaN) } }),
        LISTED_CURRENT,
        AS_OF,
      ),
    ).toEqual({ ok: false, error: { code: 'finding_age_out_of_range' } });
  });

  it('observes an agreed withdrawal and fails closed on disagreement', () => {
    const withdrawn = expectFacts(
      sourceSnapshot({
        creationEvidence: [
          evidence({ withdrawalClassification: 'withdrawn' }),
          evidence({
            evidenceId: 'evidence-2',
            advisoryRevisionId: 'revision-2',
            withdrawalClassification: 'withdrawn',
          }),
        ],
      }),
      LISTED_CURRENT,
    );
    expect(withdrawn.advisory_withdrawn).toEqual({ state: 'observed', value: 'withdrawn' });

    const disagreed = assemblePriorityFacts(
      sourceSnapshot({
        creationEvidence: [
          evidence({ withdrawalClassification: 'withdrawn' }),
          evidence({
            evidenceId: 'evidence-2',
            withdrawalClassification: 'not_withdrawn',
          }),
        ],
      }),
      LISTED_CURRENT,
      AS_OF,
    );
    expect(disagreed).toEqual({
      ok: false,
      error: { code: 'advisory_withdrawal_disagreement' },
    });
  });

  it('leaves withdrawal and directness unavailable when no revision is linked', () => {
    const facts = expectFacts(sourceSnapshot({ creationEvidence: [] }), LISTED_CURRENT);
    expect(facts.advisory_withdrawn).toEqual({ state: 'unavailable' });
    expect(facts.direct_dependency).toEqual({ state: 'unavailable' });
    expect(Object.keys(facts)).toEqual([...PRIORITY_FACTOR_IDS]);
  });

  it('reports age before withdrawal when both are closed failures', () => {
    const result = assemblePriorityFacts(
      sourceSnapshot({
        finding: { firstObservedAt: new Date(AS_OF.getTime() + 86400000) },
        creationEvidence: [
          evidence({ withdrawalClassification: 'withdrawn' }),
          evidence({ evidenceId: 'evidence-2', withdrawalClassification: 'not_withdrawn' }),
        ],
      }),
      LISTED_CURRENT,
      AS_OF,
    );
    expect(result).toEqual({ ok: false, error: { code: 'finding_age_out_of_range' } });
  });
});

describe('calculation factor sources', () => {
  it('copies distinct ids and catalog metadata without KEV prose', () => {
    const snapshot = sourceSnapshot({
      creationEvidence: [
        evidence(),
        evidence({
          evidenceId: 'evidence-2',
          advisoryRevisionId: 'revision-1',
          componentOccurrenceId: 'occurrence-2',
          vulnerabilityId: 'vulnerability-2',
          sbomIngestionId: 'ingestion-2',
        }),
      ],
    });
    const kev: RiskCalculationKevSourceV2 = {
      state: 'catalog',
      catalogVersion: CATALOG_VERSION,
      catalogReleasedAt: '2026-09-01T12:00:00.000Z',
      freshness: 'stale',
      generationId: null,
      snapshotSha256: null,
    };
    const sources = assembleRiskCalculationFactorSources(snapshot, kev);
    expect(sources.evidenceIds).toEqual(['evidence-1', 'evidence-2']);
    expect(sources.advisoryRevisionIds).toEqual(['revision-1']);
    expect(sources.componentOccurrenceIds).toEqual(['occurrence-1', 'occurrence-2']);
    expect(sources.intelligenceSourceRecordIds).toEqual([]);
    expect(sources.kev).toEqual(kev);
    expect(sources).not.toHaveProperty('vulnerabilityIds');
    expect(sources.kev).not.toHaveProperty('kevDueDate');
    expect(sources.kev).not.toHaveProperty('requiredAction');
    expect(sources.kev).not.toHaveProperty('knownRansomwareCampaignUse');
    expect(sources.kev).not.toHaveProperty('notes');
  });

  it('uses empty id arrays and the unavailable KEV reason when nothing is linked', () => {
    const sources = assembleRiskCalculationFactorSources(sourceSnapshot({ creationEvidence: [] }), {
      state: 'unavailable',
      reason: 'no_canonical_cve',
    });
    expect(sources.evidenceIds).toEqual([]);
    expect(sources.advisoryRevisionIds).toEqual([]);
    expect(sources.componentOccurrenceIds).toEqual([]);
    expect(sources.intelligenceSourceRecordIds).toEqual([]);
    expect(sources.kev).toEqual({ state: 'unavailable', reason: 'no_canonical_cve' });
  });
});
