/**
 * Closed fact document for one priority evaluation. All ten factor keys are
 * required. This is the unbranded input. The injected engine accepts only
 * facts it has parsed.
 */

import type {
  PriorityAdvisoryWithdrawnToken,
  PriorityAssetDataClassificationToken,
  PriorityAssetDataClassificationUnknownToken,
  PriorityBusinessCriticalityToken,
  PriorityBusinessCriticalityUnknownToken,
  PriorityDirectDependencyToken,
  PriorityEnvironmentSensitivityToken,
  PriorityFixAvailableToken,
  PriorityFixAvailableUnknownToken,
  PriorityInternetExposureToken,
  PriorityInternetExposureUnknownToken,
  PriorityKevObservedToken,
  PriorityKevUnavailableReason,
  PriorityKevUnknownToken,
  PrioritySeverityRating,
  PrioritySeverityUnknownToken,
} from './catalog.js';

type UnavailableFact = { readonly state: 'unavailable' };

export type PrioritySourceSeverityFact =
  | { readonly state: 'observed'; readonly values: readonly PrioritySeverityRating[] }
  | { readonly state: 'unknown'; readonly value: PrioritySeverityUnknownToken }
  | UnavailableFact;

export type PriorityKevListedFact =
  | { readonly state: 'observed'; readonly value: PriorityKevObservedToken }
  | { readonly state: 'unknown'; readonly value: PriorityKevUnknownToken }
  | { readonly state: 'unavailable'; readonly reason: PriorityKevUnavailableReason };

export type PriorityEnvironmentSensitivityFact =
  | { readonly state: 'observed'; readonly value: PriorityEnvironmentSensitivityToken }
  | UnavailableFact;

export type PriorityInternetExposureFact =
  | { readonly state: 'observed'; readonly value: PriorityInternetExposureToken }
  | { readonly state: 'unknown'; readonly value: PriorityInternetExposureUnknownToken }
  | UnavailableFact;

export type PriorityBusinessCriticalityFact =
  | { readonly state: 'observed'; readonly value: PriorityBusinessCriticalityToken }
  | { readonly state: 'unknown'; readonly value: PriorityBusinessCriticalityUnknownToken }
  | UnavailableFact;

export type PriorityAssetDataClassificationFact =
  | { readonly state: 'observed'; readonly value: PriorityAssetDataClassificationToken }
  | { readonly state: 'unknown'; readonly value: PriorityAssetDataClassificationUnknownToken }
  | UnavailableFact;

export type PriorityDirectDependencyFact =
  { readonly state: 'observed'; readonly value: PriorityDirectDependencyToken } | UnavailableFact;

export type PriorityFixAvailableFact =
  | { readonly state: 'observed'; readonly value: PriorityFixAvailableToken }
  | { readonly state: 'unknown'; readonly value: PriorityFixAvailableUnknownToken }
  | UnavailableFact;

export type PriorityFindingAgeDaysFact =
  { readonly state: 'observed'; readonly value: number } | UnavailableFact;

export type PriorityAdvisoryWithdrawnFact =
  { readonly state: 'observed'; readonly value: PriorityAdvisoryWithdrawnToken } | UnavailableFact;

export type PriorityFactInput = {
  readonly source_severity: PrioritySourceSeverityFact;
  readonly kev_listed: PriorityKevListedFact;
  readonly environment_sensitivity: PriorityEnvironmentSensitivityFact;
  readonly internet_exposure: PriorityInternetExposureFact;
  readonly business_criticality: PriorityBusinessCriticalityFact;
  readonly asset_data_classification: PriorityAssetDataClassificationFact;
  readonly direct_dependency: PriorityDirectDependencyFact;
  readonly fix_available: PriorityFixAvailableFact;
  readonly finding_age_days: PriorityFindingAgeDaysFact;
  readonly advisory_withdrawn: PriorityAdvisoryWithdrawnFact;
};
