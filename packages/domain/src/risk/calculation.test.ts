/**
 * Risk-calculation use case with fakes. No database, route, or policy engine.
 * The fingerprint hashes the parsed fact input returned by parseFactInput.
 */

import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { PriorityEvaluationDocument, PriorityFactorRow } from '../json-documents.js';
import { JSON_SCHEMA_VERSION_V1 } from '../json-documents.js';
import type { MembershipRole } from '../lifecycle.js';
import { err, ok, type AppError, type Result } from '../result.js';
import type { ControlledFindingOperatorActor } from '../findings/controlled-operator/actor.js';
import {
  parseCalendarDate,
  type CalendarDate,
  type CanonicalCve,
} from '../intelligence/normalize.js';
import { parseExactCanonicalCve } from '../vulnerability/cve-identity.js';
import {
  ACTIVE_KEV_MEMBERSHIP_INCONSISTENT,
  ACTIVE_KEV_MEMBERSHIP_UNAVAILABLE,
  createAbsentActiveKevMembership,
  createListedInActiveKevMembership,
  type ActiveKevMembership,
} from '../vulnerability/kev-membership.js';
import {
  PRIORITY_CALCULATION_ENGINE_VERSION,
  PRIORITY_ESCALATION_REASONS,
  PRIORITY_FACTOR_IDS,
  type PriorityFactorExplanationCode,
  type PriorityFactorId,
} from './catalog.js';
import {
  createCalculateFindingRiskUseCase,
  createPublishOrganizationPriorityOverrideUseCase,
  createReadCurrentFindingRiskUseCase,
  ORGANIZATION_PRIORITY_OVERRIDE_PERMISSION,
} from './calculation.js';
import type { PriorityEnginePort } from './engine-port.js';
import type { FindingRiskCreationEvidence, FindingRiskSourceSnapshot } from './fact-assembly.js';
import type { PriorityFactInput } from './facts.js';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  type CurrentRiskCalculationRead,
  type LockedPriorityCalculationContext,
  type LockedPriorityCalculationDecision,
  type LockedPriorityCalculationOutcome,
  type LockedPriorityCalculationScope,
  type PersistFindingRiskCalculationCommand,
  type PersistFindingRiskCalculationResult,
  type PriorityPolicyLookup,
  type PublishOrganizationPriorityOverrideCommand,
  type RiskCalculationFactGraphRead,
  type RiskCalculationScope,
  type StoredRiskCalculation,
} from './persistence-port.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const OTHER_ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const ASSET = '44444444-4444-4444-8444-444444444444';
const POLICY_ID = '55555555-5555-4555-8555-555555555555';
const OVERRIDE_ID = '66666666-6666-4666-8666-666666666666';
const CALCULATION_ID = '77777777-7777-4777-8777-777777777777';
const CORRELATION = '88888888-8888-4888-8888-888888888888';
const FIRST_OBSERVED_AT = new Date('2026-01-01T00:00:00.000Z');
const AS_OF = new Date('2026-01-11T00:00:00.000Z');
const RELEASED_AT = new Date('2026-09-01T12:00:00.000Z');
const CATALOG_VERSION = '2099.01.01';

const BUILTIN = Object.freeze({
  schemaVersion: 2,
  policyKey: BUILTIN_PRIORITY_POLICY_KEY,
  marker: 'builtin-v2',
});

const OTHER_DEFINITION = Object.freeze({
  schemaVersion: 2,
  policyKey: BUILTIN_PRIORITY_POLICY_KEY,
  marker: 'not-the-builtin',
});

type Validated = typeof BUILTIN;
type ParsedFacts = PriorityFactInput;

const UNAVAILABLE_EXPLANATION = {
  source_severity: 'severity_unavailable',
  kev_listed: 'kev_unavailable_no_active_generation',
  environment_sensitivity: 'environment_unavailable',
  internet_exposure: 'exposure_unavailable',
  business_criticality: 'criticality_unavailable',
  asset_data_classification: 'data_unavailable',
  direct_dependency: 'dependency_unavailable',
  fix_available: 'fix_unavailable',
  finding_age_days: 'age_unavailable',
  advisory_withdrawn: 'advisory_withdrawal_unavailable',
} as const satisfies Record<PriorityFactorId, PriorityFactorExplanationCode>;

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function stableCanonical(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('non-finite');
      }
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new Error('unsupported canonical value');
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableCanonical(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableCanonical(record[key])}`)
    .join(',')}}`;
}

const BUILTIN_HASH = sha256(stableCanonical(BUILTIN));

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

function listed(cve: string, freshness: 'current' | 'stale'): ActiveKevMembership {
  const parsed = createListedInActiveKevMembership({
    cve: requireCve(cve),
    catalogVersion: CATALOG_VERSION,
    catalogReleasedAt: RELEASED_AT,
    dateAdded: requireCalendar('2024-01-15'),
    kevDueDate: requireCalendar('2024-02-15'),
    knownRansomwareCampaignUse: 'unknown',
    freshness,
  });
  if (!parsed.ok) {
    throw new Error('expected listed membership');
  }
  return parsed.value;
}

function absent(cve: string): ActiveKevMembership {
  const parsed = createAbsentActiveKevMembership({
    cve: requireCve(cve),
    catalogVersion: CATALOG_VERSION,
    catalogReleasedAt: RELEASED_AT,
    freshness: 'current',
  });
  if (!parsed.ok) {
    throw new Error('expected absent membership');
  }
  return parsed.value;
}

const LISTED = listed('CVE-1900-00001', 'current');
const ABSENT = absent('CVE-1900-00001');

function evidence(
  overrides: Partial<FindingRiskCreationEvidence> = {},
): FindingRiskCreationEvidence {
  return {
    evidenceId: overrides.evidenceId ?? '12121212-1212-4121-8121-121212121212',
    advisoryRevisionId: overrides.advisoryRevisionId ?? '13131313-1313-4131-8131-131313131313',
    componentOccurrenceId:
      overrides.componentOccurrenceId ?? '14141414-1414-4141-8141-141414141414',
    vulnerabilityId: overrides.vulnerabilityId ?? '15151515-1515-4151-8151-151515151515',
    sbomIngestionId: overrides.sbomIngestionId ?? '16161616-1616-4161-8161-161616161616',
    isDirect: overrides.isDirect === undefined ? true : overrides.isDirect,
    withdrawalClassification: overrides.withdrawalClassification ?? 'not_withdrawn',
    bindingClassification: overrides.bindingClassification ?? 'one_cve_alias_evidence',
    canonicalCves: overrides.canonicalCves ?? ['CVE-1900-00001'],
  };
}

function snapshot(
  overrides: {
    readonly state?: FindingRiskSourceSnapshot['finding']['state'];
    readonly organizationId?: string;
    readonly firstObservedAt?: Date;
    readonly creationEvidence?: readonly FindingRiskCreationEvidence[];
    readonly hasControlledCreationObservation?: boolean;
  } = {},
): FindingRiskSourceSnapshot {
  return {
    finding: {
      id: FINDING,
      organizationId: overrides.organizationId ?? ORG,
      state: overrides.state ?? 'open',
      version: 1,
      firstObservedAt: overrides.firstObservedAt ?? FIRST_OBSERVED_AT,
      currentRiskCalculationId: null,
      dueAt: null,
      assetId: ASSET,
    },
    asset: {
      sensitivityClass: 'production',
      internetExposure: 'unknown',
      businessCriticality: 'unspecified',
      dataClassification: 'unspecified',
    },
    creationEvidence: overrides.creationEvidence ?? [evidence()],
    hasControlledCreationObservation: overrides.hasControlledCreationObservation ?? true,
  };
}

function factorRow(
  factorId: PriorityFactorId,
  ordinal: number,
  inputState: PriorityFactorRow['inputState'],
  observedValue: PriorityFactorRow['observedValue'],
  explanationCode: PriorityFactorExplanationCode,
): PriorityFactorRow {
  return {
    factorId,
    ordinal,
    inputState,
    observedValue,
    normalizedPercent: 0,
    weight: 0,
    contributionCenti: 0,
    status: 'non_contributing',
    explanationCode,
  };
}

function evaluation(): PriorityEvaluationDocument {
  return {
    engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    weightedScoreCenti: 0,
    upliftCenti: 0,
    priority: 0,
    priorityBand: 'P4',
    dueDateRecommendationDays: 180,
    escalation: { recommended: false, reasons: [] },
    factors: PRIORITY_FACTOR_IDS.map((factorId, index) =>
      factorRow(factorId, index + 1, 'unavailable', null, UNAVAILABLE_EXPLANATION[factorId]),
    ),
    rules: [
      {
        ruleId: 'kev_minimum_band',
        triggered: false,
        upliftCenti: 0,
        explanationCode: 'kev_minimum_band_not_triggered',
      },
      {
        ruleId: 'kev_escalation',
        triggered: false,
        upliftCenti: 0,
        explanationCode: 'kev_escalation_not_triggered',
      },
    ],
    evidenceSummary: { observed: 0, unknown: 0, unavailable: PRIORITY_FACTOR_IDS.length },
  };
}

function emptySources(): StoredRiskCalculation['factors']['sources'] {
  return {
    evidenceIds: [],
    advisoryRevisionIds: [],
    componentOccurrenceIds: [],
    intelligenceSourceRecordIds: [],
    kev: { state: 'unavailable', reason: 'no_canonical_cve' },
  };
}

function storedCalculation(overrides: Partial<StoredRiskCalculation> = {}): StoredRiskCalculation {
  return {
    id: CALCULATION_ID,
    organizationId: ORG,
    findingId: FINDING,
    riskPolicyId: POLICY_ID,
    policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
    policyDefinitionSha256: BUILTIN_HASH,
    calculatedAt: AS_OF,
    factors: {
      schemaVersion: 2,
      factors: [
        factorRow(
          'kev_listed',
          2,
          'observed',
          'listed_catalog_current',
          'kev_listed_catalog_current',
        ),
        factorRow('environment_sensitivity', 3, 'observed', 'production', 'environment_production'),
        factorRow('internet_exposure', 4, 'unknown', null, 'exposure_unknown'),
        factorRow('business_criticality', 5, 'unknown', null, 'criticality_unspecified'),
        factorRow('asset_data_classification', 6, 'unknown', null, 'data_unspecified'),
      ],
      rules: [],
      escalationReasons: [],
      evidenceSummary: { observed: 2, unknown: 3, unavailable: 0 },
      weightedScoreCenti: 0,
      upliftCenti: 0,
      sources: emptySources(),
    },
    result: {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      priority: 0,
      priorityBand: 'P4',
      dueDateRecommendationDays: 180,
      escalationRecommendation: false,
    },
    calculationEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    calculationReason: 'initial',
    inputFingerprint: 'aa'.repeat(32),
    ...overrides,
  };
}

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

type HarnessOptions = {
  readonly role?: MembershipRole | null;
  readonly organizationId?: string | null;
  readonly actorExtras?: Record<string, unknown>;
  readonly command?: unknown;
  readonly envelope?: Record<string, unknown>;
  readonly graph?: RiskCalculationFactGraphRead;
  readonly builtin?: PriorityPolicyLookup;
  readonly builtinDefinition?: unknown;
  readonly override?: PriorityPolicyLookup;
  readonly overrideInvalid?: boolean;
  readonly current?: CurrentRiskCalculationRead;
  readonly membership?: (input: unknown) => Result<ActiveKevMembership, AppError>;
  readonly evaluation?: PriorityEvaluationDocument;
  readonly persist?: (
    command: PersistFindingRiskCalculationCommand,
  ) => PersistFindingRiskCalculationResult;
};

function createHarness(options: HarnessOptions = {}) {
  const evaluateCalls: unknown[][] = [];
  const parseInputs: unknown[] = [];
  const persistCalls: PersistFindingRiskCalculationCommand[] = [];
  const membershipInputs: unknown[] = [];
  const graphInputs: RiskCalculationScope[] = [];
  const overrideLookups: string[] = [];
  const publishCalls: PublishOrganizationPriorityOverrideCommand[] = [];
  const canonicalInputs: unknown[] = [];
  const lockedScopes: Array<{
    readonly organizationId: string;
    readonly actorUserId: string;
    readonly membershipId: string;
    readonly findingId: string;
  }> = [];
  let parsedFacts: ParsedFacts | undefined;
  let insideLock = false;
  let membershipInsideLock: boolean | null = null;

  const engine: PriorityEnginePort<Validated, ParsedFacts> = {
    parseFactInput(input) {
      parseInputs.push(input);
      parsedFacts = input as ParsedFacts;
      return { ok: true, value: parsedFacts };
    },
    evaluatePriority(definition, facts) {
      evaluateCalls.push([definition, facts]);
      return { ok: true, value: options.evaluation ?? evaluation() };
    },
    validatePolicyDefinition(input) {
      return { ok: true, value: input as Validated };
    },
    validatePolicyOverride(_parent, candidate) {
      if (options.overrideInvalid) {
        return {
          ok: false,
          error: {
            kind: 'invalid_policy_override',
            issues: [{ path: 'weights', code: 'out_of_bounds' }],
          },
        };
      }
      return { ok: true, value: candidate as Validated };
    },
    canonicalJson(value) {
      canonicalInputs.push(value);
      return { ok: true, value: stableCanonical(value) };
    },
  };

  async function loadPriorityCalculationFactGraph(input: RiskCalculationScope) {
    graphInputs.push(input);
    return (
      options.graph ?? {
        kind: 'found' as const,
        asOf: AS_OF,
        snapshot: snapshot(),
      }
    );
  }

  async function findPublishedBuiltinPriorityPolicy() {
    return (
      options.builtin ?? {
        kind: 'found' as const,
        policy: {
          id: POLICY_ID,
          policyKey: BUILTIN_PRIORITY_POLICY_KEY,
          version: BUILTIN_PRIORITY_POLICY_VERSION,
          definition: BUILTIN,
        },
      }
    );
  }

  async function findSelectedOrganizationPriorityOverride(organizationId: string) {
    overrideLookups.push(organizationId);
    return options.override ?? { kind: 'not_found' as const };
  }

  async function findCurrentRiskCalculation() {
    return options.current ?? { kind: 'not_found' as const };
  }

  async function persistRiskCalculation(command: PersistFindingRiskCalculationCommand) {
    persistCalls.push(command);
    if (options.persist) {
      return options.persist(command);
    }
    return {
      kind: 'persisted' as const,
      calculation: storedCalculation({
        riskPolicyId: command.riskPolicyId,
        policyDefinitionSha256: command.policyDefinitionSha256,
        calculatedAt: command.calculatedAt,
        factors: command.factors,
        result: command.result,
        calculationReason: command.calculationReason,
        inputFingerprint: command.inputFingerprint,
      }),
    };
  }

  const persistence = {
    loadPriorityCalculationFactGraph,
    findPublishedBuiltinPriorityPolicy,
    findSelectedOrganizationPriorityOverride,
    findCurrentRiskCalculation,
    persistRiskCalculation,
    async executeLockedPriorityCalculation<TStop>(
      scope: LockedPriorityCalculationScope,
      work: (
        context: LockedPriorityCalculationContext,
      ) => Promise<LockedPriorityCalculationDecision<TStop>>,
    ): Promise<LockedPriorityCalculationOutcome<TStop>> {
      lockedScopes.push(scope);
      insideLock = true;
      try {
        const graph = await loadPriorityCalculationFactGraph({
          organizationId: scope.organizationId,
          findingId: scope.findingId,
        });
        const builtin = await findPublishedBuiltinPriorityPolicy();
        const override = await findSelectedOrganizationPriorityOverride(scope.organizationId);
        const current = await findCurrentRiskCalculation();
        const decision = await work({
          asOf: graph.kind === 'found' ? graph.asOf : null,
          graph,
          builtin,
          override,
          current,
          async queryActiveKevMembership(input: unknown) {
            membershipInsideLock = insideLock;
            membershipInputs.push(input);
            if (options.membership) {
              return options.membership(input);
            }
            return ok(LISTED);
          },
        });
        if (decision.kind === 'stop') {
          return { kind: 'stop' as const, result: decision.result };
        }
        return { kind: 'write' as const, result: await persistRiskCalculation(decision.command) };
      } finally {
        insideLock = false;
      }
    },
    async publishOrganizationPriorityOverride(input: PublishOrganizationPriorityOverrideCommand) {
      publishCalls.push(input);
      return { kind: 'published' as const, policy: { id: OVERRIDE_ID, version: 1 } };
    },
  };

  const dependencies = {
    engine,
    persistence,
    builtinDefinition: options.builtinDefinition ?? BUILTIN,
    createCorrelationId: () => CORRELATION,
  };
  return {
    calculate: createCalculateFindingRiskUseCase(dependencies),
    read: createReadCurrentFindingRiskUseCase({ persistence }),
    publish: createPublishOrganizationPriorityOverrideUseCase({
      engine,
      persistence,
      builtinDefinition: options.builtinDefinition ?? BUILTIN,
    }),
    evaluateCalls,
    parseInputs,
    persistCalls,
    membershipInputs,
    graphInputs,
    overrideLookups,
    publishCalls,
    canonicalInputs,
    lockedScopes,
    membershipInsideLock: () => membershipInsideLock,
    parsedFacts: () => parsedFacts,
    input: {
      actor: actor(
        options.role === undefined ? 'owner' : options.role,
        options.actorExtras,
        options.organizationId === undefined ? ORG : options.organizationId,
      ),
      command: options.command === undefined ? { findingId: FINDING } : options.command,
      ...options.envelope,
    },
  };
}

function fingerprintMaterial(
  canonicalInputs: readonly unknown[],
): Record<string, unknown> | undefined {
  for (const value of canonicalInputs) {
    if (
      typeof value === 'object' &&
      value !== null &&
      'facts' in value &&
      'policyDefinitionSha256' in value &&
      'engineVersion' in value
    ) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

describe('createCalculateFindingRiskUseCase', () => {
  it('calculates a listed Finding once and hashes the parsed facts', async () => {
    const now = Date.now;
    Date.now = () => {
      throw new Error('clock');
    };
    try {
      const harness = createHarness();
      const result = await harness.calculate.execute(harness.input);
      expect(result.kind).toBe('calculated');
      expect(harness.evaluateCalls).toHaveLength(1);
      expect(harness.parseInputs).toHaveLength(1);
      expect(harness.lockedScopes).toEqual([
        {
          organizationId: ORG,
          actorUserId: ACTOR,
          membershipId: MEMBERSHIP,
          findingId: FINDING,
        },
      ]);
      expect(harness.membershipInsideLock()).toBe(true);
      expect(harness.membershipInputs).toEqual([{ cve: 'CVE-1900-00001' }]);
      expect(harness.graphInputs).toEqual([{ organizationId: ORG, findingId: FINDING }]);
      expect(harness.overrideLookups).toEqual([ORG]);
      expect(harness.persistCalls).toHaveLength(1);
      const command = harness.persistCalls[0];
      expect(command?.organizationId).toBe(ORG);
      expect(command?.actorUserId).toBe(ACTOR);
      expect(command?.membershipId).toBe(MEMBERSHIP);
      expect(command?.calculatedAt).toBe(AS_OF);
      expect(command?.calculationReason).toBe('initial');
      expect(command?.riskPolicyId).toBe(POLICY_ID);
      expect(command?.correlationId).toBe(CORRELATION);
      expect(command?.policyDefinitionSha256).toBe(BUILTIN_HASH);
      expect(command?.factors.escalationReasons).toEqual([]);
      expect(command?.factors.sources.kev).toEqual({
        state: 'catalog',
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: RELEASED_AT.toISOString(),
        freshness: 'current',
        generationId: null,
        snapshotSha256: null,
      });
      expect(Object.keys(command?.result ?? {}).sort()).toEqual([
        'dueDateRecommendationDays',
        'escalationRecommendation',
        'priority',
        'priorityBand',
        'schemaVersion',
      ]);
      expect(command?.result.escalationRecommendation).toBe(false);
      expect(command?.factors.sources).not.toHaveProperty('requiredAction');
      expect(JSON.stringify(command?.factors.sources)).not.toContain('ransomware');
      const material = fingerprintMaterial(harness.canonicalInputs);
      expect(material?.['engineVersion']).toBe(PRIORITY_CALCULATION_ENGINE_VERSION);
      expect(material?.['policyDefinitionSha256']).toBe(BUILTIN_HASH);
      expect(material?.['facts']).toBe(harness.parsedFacts());
      expect(Object.keys(material ?? {}).sort()).toEqual([
        'engineVersion',
        'facts',
        'policyDefinitionSha256',
      ]);
      expect(command?.inputFingerprint).toBe(sha256(stableCanonical(material)));
      expect(harness.parsedFacts()?.kev_listed).toEqual({
        state: 'observed',
        value: 'listed_catalog_current',
      });
      if (result.kind === 'calculated') {
        expect(result.calculation.calculationReason).toBe('initial');
        expect(result.calculation.inputFingerprint).toBe(command?.inputFingerprint);
      }
    } finally {
      Date.now = now;
    }
  });

  it('copies escalation reasons onto the factors document and keeps the result boolean', async () => {
    const listed = createHarness({
      evaluation: {
        ...evaluation(),
        escalation: { recommended: true, reasons: [...PRIORITY_ESCALATION_REASONS] },
      },
    });
    const listedResult = await listed.calculate.execute(listed.input);
    expect(listedResult.kind).toBe('calculated');
    expect(listed.persistCalls[0]?.factors.escalationReasons).toEqual([
      ...PRIORITY_ESCALATION_REASONS,
    ]);
    expect(listed.persistCalls[0]?.factors.rules.map((row) => row.ruleId)).toEqual([
      'kev_minimum_band',
      'kev_escalation',
    ]);
    expect(listed.persistCalls[0]?.result.escalationRecommendation).toBe(true);
    expect(listed.persistCalls[0]?.result).not.toHaveProperty('escalationReasons');

    const absent = createHarness({
      evaluation: {
        ...evaluation(),
        escalation: {
          recommended: false,
        } as unknown as PriorityEvaluationDocument['escalation'],
      },
    });
    const absentResult = await absent.calculate.execute(absent.input);
    expect(absentResult.kind).toBe('calculated');
    expect(absent.persistCalls[0]?.factors.escalationReasons).toEqual([]);
    expect(absent.persistCalls[0]?.result.escalationRecommendation).toBe(false);
  });

  it('stores not-listed catalog current as an observed fact', async () => {
    const harness = createHarness({
      membership: () => ok(ABSENT),
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result.kind).toBe('calculated');
    expect(harness.evaluateCalls).toHaveLength(1);
    expect(harness.parsedFacts()?.kev_listed).toEqual({
      state: 'observed',
      value: 'not_listed_catalog_current',
    });
    expect(harness.persistCalls[0]?.factors.sources.kev).toMatchObject({
      state: 'catalog',
      freshness: 'current',
      generationId: null,
      snapshotSha256: null,
    });
  });

  it('stores unavailable no_canonical_cve without a membership read', async () => {
    const harness = createHarness({
      graph: {
        kind: 'found',
        asOf: AS_OF,
        snapshot: snapshot({
          creationEvidence: [
            evidence({ bindingClassification: 'provider_native_without_cve', canonicalCves: [] }),
          ],
        }),
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result.kind).toBe('calculated');
    expect(harness.membershipInputs).toEqual([]);
    expect(harness.evaluateCalls).toHaveLength(1);
    expect(harness.parsedFacts()?.kev_listed).toEqual({
      state: 'unavailable',
      reason: 'no_canonical_cve',
    });
    expect(harness.persistCalls[0]?.factors.sources.kev).toEqual({
      state: 'unavailable',
      reason: 'no_canonical_cve',
    });
  });

  it.each([
    {
      name: 'source_missing',
      error: ACTIVE_KEV_MEMBERSHIP_UNAVAILABLE,
      code: 'source_missing',
    },
    {
      name: 'inconsistent generation',
      error: ACTIVE_KEV_MEMBERSHIP_INCONSISTENT,
      code: 'inconsistent_active_generation',
    },
    {
      name: 'malformed cve',
      error: { code: 'validation', message: 'Canonical CVE must match exactly.' } as const,
      code: 'malformed_persisted_entry',
    },
  ])('writes nothing on KEV membership $name', async ({ error, code }) => {
    const harness = createHarness({
      membership: () => err(error),
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'kev_membership_error', error: { code } });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('writes nothing when listed freshness disagrees', async () => {
    const harness = createHarness({
      graph: {
        kind: 'found',
        asOf: AS_OF,
        snapshot: snapshot({
          creationEvidence: [
            evidence(),
            evidence({
              evidenceId: '17171717-1717-4171-8171-171717171717',
              canonicalCves: ['CVE-1900-00002'],
            }),
          ],
        }),
      },
      membership: (input) => {
        const cve = (input as { cve?: string }).cve;
        return ok(cve === 'CVE-1900-00002' ? listed('CVE-1900-00002', 'stale') : LISTED);
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'kev_mapping_rejected', code: 'listed_freshness_disagreement' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('denies admin, member, and a caller-supplied permission', async () => {
    for (const role of ['admin', 'member', 'viewer'] as const) {
      const harness = createHarness({
        role,
        actorExtras: { permissions: ['priority:calculate_controlled'] },
      });
      const result = await harness.calculate.execute(harness.input);
      expect(result, role).toEqual({ kind: 'unauthorized' });
      expect(harness.graphInputs, role).toEqual([]);
      expect(harness.persistCalls, role).toEqual([]);
      expect(harness.evaluateCalls, role).toEqual([]);
    }
  });

  it('rejects a command organizationId and does not query that organization', async () => {
    const harness = createHarness({
      command: { findingId: FINDING, organizationId: OTHER_ORG },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'unauthorized' });
    expect(harness.graphInputs).toEqual([]);
    expect(harness.persistCalls).toEqual([]);
  });

  it('reports a missing Finding as not_found', async () => {
    const harness = createHarness({ graph: { kind: 'not_found' } });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'not_found' });
    expect(harness.graphInputs).toEqual([{ organizationId: ORG, findingId: FINDING }]);
    expect(harness.persistCalls).toEqual([]);
    expect(harness.membershipInputs).toEqual([]);
  });

  it('reports a snapshot for another organization as not_found', async () => {
    const harness = createHarness({
      graph: {
        kind: 'found',
        asOf: AS_OF,
        snapshot: snapshot({ organizationId: OTHER_ORG }),
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'not_found' });
    expect(harness.persistCalls).toEqual([]);
  });

  it('writes nothing when the Finding is ineligible', async () => {
    const harness = createHarness({
      graph: {
        kind: 'found',
        asOf: AS_OF,
        snapshot: snapshot({ state: 'resolved' }),
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'ineligible', reason: 'state_not_open' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('writes nothing when age is out of range', async () => {
    const harness = createHarness({
      graph: {
        kind: 'found',
        asOf: AS_OF,
        snapshot: snapshot({
          firstObservedAt: new Date(AS_OF.getTime() + 86_400_000),
        }),
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'facts_rejected', code: 'finding_age_out_of_range' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('selects a valid organization override instead of the builtin', async () => {
    const harness = createHarness({
      override: {
        kind: 'found',
        policy: {
          id: OVERRIDE_ID,
          policyKey: BUILTIN_PRIORITY_POLICY_KEY,
          version: 4,
          definition: OTHER_DEFINITION,
        },
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result.kind).toBe('calculated');
    expect(harness.evaluateCalls[0]?.[0]).toBe(OTHER_DEFINITION);
    expect(harness.persistCalls[0]?.riskPolicyId).toBe(OVERRIDE_ID);
    expect(harness.persistCalls[0]?.policyDefinitionSha256).toBe(
      sha256(stableCanonical(OTHER_DEFINITION)),
    );
  });

  it('writes nothing when the builtin version 2 row is absent', async () => {
    const harness = createHarness({ builtin: { kind: 'not_found' } });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'builtin_unavailable', reason: 'absent' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('writes nothing when the builtin row is not version 2', async () => {
    const harness = createHarness({
      builtin: {
        kind: 'found',
        policy: {
          id: POLICY_ID,
          policyKey: BUILTIN_PRIORITY_POLICY_KEY,
          version: 1,
          definition: BUILTIN,
        },
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'builtin_unavailable', reason: 'version' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
  });

  it('writes nothing when the stored builtin does not match the injected document', async () => {
    const harness = createHarness({
      builtin: {
        kind: 'found',
        policy: {
          id: POLICY_ID,
          policyKey: BUILTIN_PRIORITY_POLICY_KEY,
          version: 2,
          definition: OTHER_DEFINITION,
        },
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'builtin_unavailable', reason: 'mismatch' });
    expect(harness.persistCalls).toEqual([]);
  });

  it('fails closed when the published override is invalid', async () => {
    const harness = createHarness({
      overrideInvalid: true,
      override: {
        kind: 'found',
        policy: {
          id: OVERRIDE_ID,
          policyKey: BUILTIN_PRIORITY_POLICY_KEY,
          version: 3,
          definition: OTHER_DEFINITION,
        },
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'override_rejected', reason: 'invalid' });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
    expect(harness.publishCalls).toEqual([]);
  });

  it('returns the stored row on replay and does not treat it as a new calculation', async () => {
    const stored = storedCalculation({ calculationReason: 'initial' });
    const harness = createHarness({
      current: { kind: 'found', calculation: stored },
      persist: () => ({ kind: 'replay', calculation: stored }),
    });
    const result = await harness.calculate.execute(harness.input);
    expect(harness.persistCalls[0]?.calculationReason).toBe('rescan');
    expect(result).toEqual({ kind: 'replayed', calculation: stored });
    expect(harness.evaluateCalls).toHaveLength(1);
  });

  it('uses policy_change when the policy hash differs', async () => {
    const harness = createHarness({
      current: {
        kind: 'found',
        calculation: storedCalculation({ policyDefinitionSha256: 'bb'.repeat(32) }),
      },
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result.kind).toBe('calculated');
    expect(harness.persistCalls[0]?.calculationReason).toBe('policy_change');
    expect(harness.evaluateCalls).toHaveLength(1);
  });

  it('uses intel_refresh before asset_change when the KEV fact differs', async () => {
    const current = storedCalculation();
    const calculation = storedCalculation({
      factors: {
        ...current.factors,
        factors: current.factors.factors.map((row) => {
          if (row.factorId === 'kev_listed') {
            return factorRow(
              'kev_listed',
              2,
              'observed',
              'not_listed_catalog_current',
              'kev_not_listed_catalog_current',
            );
          }
          if (row.factorId === 'environment_sensitivity') {
            return factorRow(
              'environment_sensitivity',
              3,
              'observed',
              'non_production',
              'environment_non_production',
            );
          }
          return row;
        }),
      },
    });
    const harness = createHarness({ current: { kind: 'found', calculation } });
    const result = await harness.calculate.execute(harness.input);
    expect(result.kind).toBe('calculated');
    expect(harness.persistCalls[0]?.calculationReason).toBe('intel_refresh');
  });

  it('fails closed on an immutable conflict', async () => {
    const harness = createHarness({
      persist: () => ({ kind: 'immutable_conflict' }),
    });
    const result = await harness.calculate.execute(harness.input);
    expect(result).toEqual({ kind: 'immutable_conflict' });
  });
});

describe('createReadCurrentFindingRiskUseCase', () => {
  it('lets an admin read the current calculation without writing or rendering KEV prose', async () => {
    const stored = storedCalculation();
    const harness = createHarness({
      role: 'admin',
      current: { kind: 'found', calculation: stored },
    });
    const result = await harness.read.execute(harness.input);
    expect(result).toEqual({ kind: 'found', calculation: stored });
    expect(harness.persistCalls).toEqual([]);
    expect(harness.membershipInputs).toEqual([]);
    expect(harness.evaluateCalls).toEqual([]);
    expect(result).not.toHaveProperty('requiredAction');
    expect(result).not.toHaveProperty('ransomware');
  });

  it('denies a member', async () => {
    const harness = createHarness({ role: 'member' });
    const result = await harness.read.execute(harness.input);
    expect(result).toEqual({ kind: 'unauthorized' });
    expect(harness.persistCalls).toEqual([]);
  });
});

describe('createPublishOrganizationPriorityOverrideUseCase', () => {
  it('publishes a validated override for an owner without a client organization', async () => {
    const harness = createHarness();
    const definition = {
      schemaVersion: 2,
      policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      marker: 'override',
    };
    const result = await harness.publish.execute({
      actor: actor('owner'),
      command: { definition },
    });
    expect(ORGANIZATION_PRIORITY_OVERRIDE_PERMISSION).toBe('policy:manage');
    expect(result).toEqual({ kind: 'published', policy: { id: OVERRIDE_ID, version: 1 } });
    expect(harness.publishCalls).toEqual([
      {
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        definition,
        policySchemaVersion: 2,
        policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      },
    ]);
    expect(harness.persistCalls).toEqual([]);
  });

  it('lets an admin publish and denies a member', async () => {
    const admin = createHarness({ role: 'admin' });
    const published = await admin.publish.execute({
      actor: actor('admin'),
      command: { definition: { marker: 'admin' } },
    });
    expect(published.kind).toBe('published');
    const member = createHarness({ role: 'member' });
    const denied = await member.publish.execute({
      actor: actor('member'),
      command: { definition: { marker: 'member' } },
    });
    expect(denied).toEqual({ kind: 'unauthorized' });
    expect(member.publishCalls).toEqual([]);
  });

  it('inserts nothing when the override is out of bounds', async () => {
    const harness = createHarness({ overrideInvalid: true });
    const result = await harness.publish.execute({
      actor: actor('owner'),
      command: { definition: { weights: { advisory_withdrawn: 5 } } },
    });
    expect(result).toEqual({ kind: 'override_rejected', reason: 'invalid' });
    expect(harness.publishCalls).toEqual([]);
  });

  it('rejects a command organizationId', async () => {
    const harness = createHarness();
    const result = await harness.publish.execute({
      actor: actor('owner'),
      command: { definition: BUILTIN, organizationId: OTHER_ORG },
    });
    expect(result).toEqual({ kind: 'unauthorized' });
    expect(harness.publishCalls).toEqual([]);
  });
});
