/**
 * Pure fact assembly for one controlled Finding.
 * Produces eligibility, the distinct canonical CVE set, KEV fact tokens,
 * the ten priority facts, and calculation source ids.
 * Membership read failures stay on FindingRiskKevMembershipError.
 * Callers pass ActiveKevMembership values only after a successful read.
 * Severity and fix availability are unavailable facts.
 */

import {
  PRIORITY_FINDING_AGE_DAYS_MAX,
  type PriorityAdvisoryWithdrawnToken,
  type PriorityKevObservedToken,
  type PriorityKevUnknownToken,
} from './catalog.js';
import type {
  PriorityAdvisoryWithdrawnFact,
  PriorityAssetDataClassificationFact,
  PriorityBusinessCriticalityFact,
  PriorityDirectDependencyFact,
  PriorityEnvironmentSensitivityFact,
  PriorityFactInput,
  PriorityInternetExposureFact,
  PriorityKevListedFact,
} from './facts.js';
import type {
  RiskCalculationFactorSourcesV2,
  RiskCalculationKevSourceV2,
} from '../json-documents.js';
import type {
  AssetDataClassification,
  BusinessCriticality,
  EnvironmentSensitivityClass,
  FindingState,
  InternetExposure,
} from '../lifecycle.js';
import { assertNever, err, ok, type Result } from '../result.js';
import type {
  ActiveKevCatalogFreshness,
  ActiveKevMembership,
} from '../vulnerability/kev-membership.js';

const MILLISECONDS_PER_DAY = 86400000;

const UNAVAILABLE_FACT = Object.freeze({ state: 'unavailable' as const });

export const findingRiskIneligibleReasons = [
  'state_not_open',
  'version_not_one',
  'current_risk_calculation_present',
  'due_at_present',
  'controlled_creation_observation_absent',
  'creation_evidence_absent',
] as const;
export type FindingRiskIneligibleReason = (typeof findingRiskIneligibleReasons)[number];

export const findingRiskCanonicalCveFailureCodes = ['canonical_cve_cardinality'] as const;
export type FindingRiskCanonicalCveFailureCode =
  (typeof findingRiskCanonicalCveFailureCodes)[number];
export type FindingRiskCanonicalCveFailure = {
  readonly code: FindingRiskCanonicalCveFailureCode;
};

export const findingRiskKevMappingFailureCodes = [
  'membership_count_mismatch',
  'listed_freshness_disagreement',
  'unknown_token_disagreement',
  'membership_status_disagreement',
] as const;
export type FindingRiskKevMappingFailureCode = (typeof findingRiskKevMappingFailureCodes)[number];
export type FindingRiskKevMappingFailure = {
  readonly code: FindingRiskKevMappingFailureCode;
};

export const findingRiskFactAssemblyFailureCodes = [
  'finding_age_out_of_range',
  'advisory_withdrawal_disagreement',
] as const;
export type FindingRiskFactAssemblyFailureCode =
  (typeof findingRiskFactAssemblyFailureCodes)[number];
export type FindingRiskFactAssemblyFailure = {
  readonly code: FindingRiskFactAssemblyFailureCode;
};

/**
 * Closed failure for a KEV membership read that did not return ActiveKevMembership.
 * source_missing, an inconsistent generation, and a malformed entry stay here.
 */
export const findingRiskKevMembershipErrorCodes = [
  'source_missing',
  'inconsistent_active_generation',
  'malformed_persisted_entry',
] as const;
export type FindingRiskKevMembershipErrorCode = (typeof findingRiskKevMembershipErrorCodes)[number];
export type FindingRiskKevMembershipError = {
  readonly code: FindingRiskKevMembershipErrorCode;
};

export type FindingRiskBindingClassification =
  'one_cve_alias_evidence' | 'provider_native_without_cve';

export type FindingRiskSourceFinding = {
  readonly id: string;
  readonly organizationId: string;
  readonly state: FindingState;
  readonly version: number;
  readonly firstObservedAt: Date;
  readonly currentRiskCalculationId: string | null;
  readonly dueAt: Date | null;
  readonly assetId: string;
};

/**
 * sensitivityClass null means the asset has no environment.
 * Exposure, criticality, and data classification use the stored asset enums,
 * including the defaults unknown and unspecified.
 */
export type FindingRiskSourceAsset = {
  readonly sensitivityClass: EnvironmentSensitivityClass | null;
  readonly internetExposure: InternetExposure;
  readonly businessCriticality: BusinessCriticality;
  readonly dataClassification: AssetDataClassification;
};

export type FindingRiskCreationEvidence = {
  readonly evidenceId: string;
  readonly advisoryRevisionId: string;
  readonly componentOccurrenceId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly isDirect: boolean | null;
  readonly withdrawalClassification: PriorityAdvisoryWithdrawnToken;
  readonly bindingClassification: FindingRiskBindingClassification;
  readonly canonicalCves: readonly string[];
};

export type FindingRiskSourceSnapshot = {
  readonly finding: FindingRiskSourceFinding;
  readonly asset: FindingRiskSourceAsset | null;
  readonly creationEvidence: readonly FindingRiskCreationEvidence[];
  readonly hasControlledCreationObservation: boolean;
};

export type FindingRiskEligibilityAssessment =
  | { readonly outcome: 'eligible' }
  | { readonly outcome: 'ineligible'; readonly reason: FindingRiskIneligibleReason };

const ELIGIBLE_ASSESSMENT: FindingRiskEligibilityAssessment = Object.freeze({
  outcome: 'eligible',
});

type ListedMembership = Extract<ActiveKevMembership, { readonly status: 'listedInActiveKev' }>;
type AbsentMembership = Extract<ActiveKevMembership, { readonly status: 'absent' }>;

function ineligible(reason: FindingRiskIneligibleReason): FindingRiskEligibilityAssessment {
  return Object.freeze({ outcome: 'ineligible', reason });
}

function canonicalCveFailure(): FindingRiskCanonicalCveFailure {
  return Object.freeze({ code: 'canonical_cve_cardinality' });
}

function kevMappingFailure(code: FindingRiskKevMappingFailureCode): FindingRiskKevMappingFailure {
  return Object.freeze({ code });
}

function factAssemblyFailure(
  code: FindingRiskFactAssemblyFailureCode,
): FindingRiskFactAssemblyFailure {
  return Object.freeze({ code });
}

/**
 * Eligible when the Finding is open at version 1, has no current calculation
 * or due date, has its controlled creation observation, and has creation evidence.
 * Reasons are reported in findingRiskIneligibleReasons order.
 * Withdrawal and KEV are factors, not gates.
 */
export function assessFindingRiskEligibility(
  snapshot: FindingRiskSourceSnapshot,
): FindingRiskEligibilityAssessment {
  if (snapshot.finding.state !== 'open') {
    return ineligible('state_not_open');
  }
  if (snapshot.finding.version !== 1) {
    return ineligible('version_not_one');
  }
  if (snapshot.finding.currentRiskCalculationId !== null) {
    return ineligible('current_risk_calculation_present');
  }
  if (snapshot.finding.dueAt !== null) {
    return ineligible('due_at_present');
  }
  if (!snapshot.hasControlledCreationObservation) {
    return ineligible('controlled_creation_observation_absent');
  }
  if (snapshot.creationEvidence.length === 0) {
    return ineligible('creation_evidence_absent');
  }
  return ELIGIBLE_ASSESSMENT;
}

/**
 * Distinct canonical CVE strings from creation evidence.
 * Rows whose binding is not one_cve_alias_evidence contribute no CVE.
 * A one_cve_alias_evidence row whose canonicalCves length is not 1 fails closed.
 * The strings are used as already selected; this function does not parse them.
 */
export function selectFindingRiskCanonicalCves(
  snapshot: FindingRiskSourceSnapshot,
): Result<readonly string[], FindingRiskCanonicalCveFailure> {
  const seen = new Set<string>();
  const canonicalCves: string[] = [];
  for (const row of snapshot.creationEvidence) {
    switch (row.bindingClassification) {
      case 'provider_native_without_cve':
        continue;
      case 'one_cve_alias_evidence': {
        const selected = oneCanonicalCve(row.canonicalCves);
        if (!selected.ok) {
          return selected;
        }
        if (seen.has(selected.value)) {
          continue;
        }
        seen.add(selected.value);
        canonicalCves.push(selected.value);
        continue;
      }
      default:
        return assertNever(row.bindingClassification);
    }
  }
  return ok(Object.freeze(canonicalCves));
}

function oneCanonicalCve(
  canonicalCves: readonly string[],
): Result<string, FindingRiskCanonicalCveFailure> {
  if (!Array.isArray(canonicalCves) || canonicalCves.length !== 1) {
    return err(canonicalCveFailure());
  }
  const cve = canonicalCves[0];
  if (typeof cve !== 'string') {
    return err(canonicalCveFailure());
  }
  return ok(cve);
}

/**
 * Maps successful ActiveKevMembership values for a canonical CVE count.
 * A count of zero is unavailable no_canonical_cve and is not a membership result.
 * Listed freshness disagreement and disagreeing unknown absence tokens fail closed.
 */
export function mapActiveKevToListedFact(
  canonicalCveCount: number,
  memberships: readonly ActiveKevMembership[],
): Result<PriorityKevListedFact, FindingRiskKevMappingFailure> {
  if (!Number.isSafeInteger(canonicalCveCount) || canonicalCveCount < 0) {
    return err(kevMappingFailure('membership_count_mismatch'));
  }
  if (memberships.length !== canonicalCveCount) {
    return err(kevMappingFailure('membership_count_mismatch'));
  }
  if (canonicalCveCount === 0) {
    return ok(Object.freeze({ state: 'unavailable', reason: 'no_canonical_cve' }));
  }

  const listed: ListedMembership[] = [];
  const absent: AbsentMembership[] = [];
  let unavailableCount = 0;
  for (const membership of memberships) {
    switch (membership.status) {
      case 'unavailable':
        unavailableCount += 1;
        break;
      case 'listedInActiveKev':
        listed.push(membership);
        break;
      case 'absent':
        absent.push(membership);
        break;
      default:
        return assertNever(membership);
    }
  }

  if (unavailableCount === memberships.length) {
    return ok(Object.freeze({ state: 'unavailable', reason: 'no_active_generation' }));
  }
  if (unavailableCount > 0) {
    return err(kevMappingFailure('membership_status_disagreement'));
  }
  if (listed.length > 0) {
    return listedFact(listed);
  }
  if (absent.length !== memberships.length) {
    return err(kevMappingFailure('membership_status_disagreement'));
  }
  return absentFact(absent);
}

function listedFact(
  listed: readonly ListedMembership[],
): Result<PriorityKevListedFact, FindingRiskKevMappingFailure> {
  const first = listed[0];
  if (first === undefined) {
    return err(kevMappingFailure('membership_status_disagreement'));
  }
  for (const membership of listed) {
    if (membership.freshness !== first.freshness) {
      return err(kevMappingFailure('listed_freshness_disagreement'));
    }
  }
  return ok(
    Object.freeze({
      state: 'observed',
      value: listedCatalogToken(first.freshness),
    }),
  );
}

function listedCatalogToken(freshness: ActiveKevCatalogFreshness): PriorityKevObservedToken {
  switch (freshness) {
    case 'current':
      return 'listed_catalog_current';
    case 'stale':
      return 'listed_catalog_stale';
    case 'disabled_with_history':
      return 'listed_catalog_disabled_with_history';
    default:
      return assertNever(freshness);
  }
}

function absentFact(
  absent: readonly AbsentMembership[],
): Result<PriorityKevListedFact, FindingRiskKevMappingFailure> {
  let unknownFreshness: Exclude<ActiveKevCatalogFreshness, 'current'> | null = null;
  for (const membership of absent) {
    if (membership.freshness === 'current') {
      continue;
    }
    if (unknownFreshness === null) {
      unknownFreshness = membership.freshness;
      continue;
    }
    if (unknownFreshness !== membership.freshness) {
      return err(kevMappingFailure('unknown_token_disagreement'));
    }
  }
  if (unknownFreshness === null) {
    return ok(Object.freeze({ state: 'observed', value: 'not_listed_catalog_current' }));
  }
  return ok(
    Object.freeze({
      state: 'unknown',
      value: unknownAbsenceToken(unknownFreshness),
    }),
  );
}

function unknownAbsenceToken(
  freshness: Exclude<ActiveKevCatalogFreshness, 'current'>,
): PriorityKevUnknownToken {
  switch (freshness) {
    case 'stale':
      return 'absent_catalog_stale';
    case 'disabled_with_history':
      return 'absent_catalog_disabled_with_history';
    default:
      return assertNever(freshness);
  }
}

/**
 * All ten fact keys, or a closed failure with no fact document.
 * Age is floor((asOf - firstObservedAt) / 86400000). Negative, non-finite,
 * and values above PRIORITY_FINDING_AGE_DAYS_MAX fail closed.
 */
export function assemblePriorityFacts(
  snapshot: FindingRiskSourceSnapshot,
  kevFact: PriorityKevListedFact,
  asOf: Date,
): Result<PriorityFactInput, FindingRiskFactAssemblyFailure> {
  const ageDays = findingAgeDays(snapshot.finding.firstObservedAt, asOf);
  if (!ageDays.ok) {
    return err(ageDays.error);
  }
  const withdrawn = advisoryWithdrawnFact(snapshot.creationEvidence);
  if (!withdrawn.ok) {
    return err(withdrawn.error);
  }
  const facts: PriorityFactInput = {
    source_severity: UNAVAILABLE_FACT,
    kev_listed: copyKevFact(kevFact),
    environment_sensitivity: environmentFact(snapshot.asset),
    internet_exposure: internetExposureFact(snapshot.asset),
    business_criticality: businessCriticalityFact(snapshot.asset),
    asset_data_classification: dataClassificationFact(snapshot.asset),
    direct_dependency: directDependencyFact(snapshot.creationEvidence),
    fix_available: UNAVAILABLE_FACT,
    finding_age_days: Object.freeze({ state: 'observed', value: ageDays.value }),
    advisory_withdrawn: withdrawn.value,
  };
  return ok(Object.freeze(facts));
}

function findingAgeDays(
  firstObservedAt: Date,
  asOf: Date,
): Result<number, FindingRiskFactAssemblyFailure> {
  if (!(firstObservedAt instanceof Date) || !(asOf instanceof Date)) {
    return err(factAssemblyFailure('finding_age_out_of_range'));
  }
  const origin = firstObservedAt.getTime();
  const clock = asOf.getTime();
  if (!Number.isFinite(origin) || !Number.isFinite(clock)) {
    return err(factAssemblyFailure('finding_age_out_of_range'));
  }
  const ageDays = Math.floor((clock - origin) / MILLISECONDS_PER_DAY);
  if (ageDays < 0 || ageDays > PRIORITY_FINDING_AGE_DAYS_MAX) {
    return err(factAssemblyFailure('finding_age_out_of_range'));
  }
  return ok(ageDays);
}

function advisoryWithdrawnFact(
  evidence: readonly FindingRiskCreationEvidence[],
): Result<PriorityAdvisoryWithdrawnFact, FindingRiskFactAssemblyFailure> {
  const first = evidence[0];
  if (first === undefined) {
    return ok(UNAVAILABLE_FACT);
  }
  const classification: PriorityAdvisoryWithdrawnToken = first.withdrawalClassification;
  for (const row of evidence) {
    if (row.withdrawalClassification !== classification) {
      return err(factAssemblyFailure('advisory_withdrawal_disagreement'));
    }
  }
  return ok(Object.freeze({ state: 'observed', value: classification }));
}

function environmentFact(asset: FindingRiskSourceAsset | null): PriorityEnvironmentSensitivityFact {
  if (asset === null || asset.sensitivityClass === null) {
    return UNAVAILABLE_FACT;
  }
  switch (asset.sensitivityClass) {
    case 'production':
    case 'non_production':
      return Object.freeze({ state: 'observed', value: asset.sensitivityClass });
    default:
      return assertNever(asset.sensitivityClass);
  }
}

function internetExposureFact(asset: FindingRiskSourceAsset | null): PriorityInternetExposureFact {
  if (asset === null) {
    return UNAVAILABLE_FACT;
  }
  switch (asset.internetExposure) {
    case 'unknown':
      return Object.freeze({ state: 'unknown', value: 'unknown' });
    case 'internet_facing':
    case 'internal':
      return Object.freeze({ state: 'observed', value: asset.internetExposure });
    default:
      return assertNever(asset.internetExposure);
  }
}

function businessCriticalityFact(
  asset: FindingRiskSourceAsset | null,
): PriorityBusinessCriticalityFact {
  if (asset === null) {
    return UNAVAILABLE_FACT;
  }
  switch (asset.businessCriticality) {
    case 'unspecified':
      return Object.freeze({ state: 'unknown', value: 'unspecified' });
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
      return Object.freeze({ state: 'observed', value: asset.businessCriticality });
    default:
      return assertNever(asset.businessCriticality);
  }
}

function dataClassificationFact(
  asset: FindingRiskSourceAsset | null,
): PriorityAssetDataClassificationFact {
  if (asset === null) {
    return UNAVAILABLE_FACT;
  }
  switch (asset.dataClassification) {
    case 'unspecified':
      return Object.freeze({ state: 'unknown', value: 'unspecified' });
    case 'restricted':
    case 'confidential':
    case 'internal':
    case 'public':
      return Object.freeze({ state: 'observed', value: asset.dataClassification });
    default:
      return assertNever(asset.dataClassification);
  }
}

function directDependencyFact(
  evidence: readonly FindingRiskCreationEvidence[],
): PriorityDirectDependencyFact {
  const first = evidence[0];
  if (first === undefined || first.isDirect === null) {
    return UNAVAILABLE_FACT;
  }
  const isDirect = first.isDirect;
  for (const row of evidence) {
    if (row.isDirect !== isDirect) {
      return UNAVAILABLE_FACT;
    }
  }
  return Object.freeze({
    state: 'observed',
    value: isDirect ? 'direct' : 'transitive',
  });
}

function copyKevFact(fact: PriorityKevListedFact): PriorityKevListedFact {
  switch (fact.state) {
    case 'observed':
      return Object.freeze({ state: 'observed', value: fact.value });
    case 'unknown':
      return Object.freeze({ state: 'unknown', value: fact.value });
    case 'unavailable':
      return Object.freeze({ state: 'unavailable', reason: fact.reason });
    default:
      return assertNever(fact);
  }
}

/**
 * Source ids from creation evidence, plus the supplied KEV catalog metadata.
 * generationId and snapshotSha256 stay null when the caller does not know them.
 * Due dates, required action, and ransomware text are not copied.
 * Id arrays are empty when the snapshot has no ids.
 */
export function assembleRiskCalculationFactorSources(
  snapshot: FindingRiskSourceSnapshot,
  kev: RiskCalculationKevSourceV2,
): RiskCalculationFactorSourcesV2 {
  return Object.freeze({
    evidenceIds: uniqueIds(snapshot.creationEvidence.map((row) => row.evidenceId)),
    advisoryRevisionIds: uniqueIds(snapshot.creationEvidence.map((row) => row.advisoryRevisionId)),
    componentOccurrenceIds: uniqueIds(
      snapshot.creationEvidence.map((row) => row.componentOccurrenceId),
    ),
    intelligenceSourceRecordIds: Object.freeze([]),
    kev: copyKevSource(kev),
  });
}

function uniqueIds(values: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const value of values) {
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);
    unique.push(value);
  }
  return Object.freeze(unique);
}

function copyKevSource(kev: RiskCalculationKevSourceV2): RiskCalculationKevSourceV2 {
  switch (kev.state) {
    case 'unavailable':
      return Object.freeze({ state: 'unavailable', reason: kev.reason });
    case 'catalog':
      return Object.freeze({
        state: 'catalog',
        catalogVersion: kev.catalogVersion,
        catalogReleasedAt: kev.catalogReleasedAt,
        freshness: kev.freshness,
        generationId: kev.generationId,
        snapshotSha256: kev.snapshotSha256,
      });
    default:
      return assertNever(kev);
  }
}

export function findingRiskKevMembershipError(
  code: FindingRiskKevMembershipErrorCode,
): FindingRiskKevMembershipError {
  return Object.freeze({ code });
}
