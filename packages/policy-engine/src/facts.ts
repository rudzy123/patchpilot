import {
  ADVISORY_WITHDRAWN_TOKENS,
  ASSET_DATA_CLASSIFICATION_TOKENS,
  ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS,
  BUSINESS_CRITICALITY_TOKENS,
  BUSINESS_CRITICALITY_UNKNOWN_TOKENS,
  DIRECT_DEPENDENCY_TOKENS,
  ENVIRONMENT_SENSITIVITY_TOKENS,
  FACTOR_IDS,
  FACTOR_INPUT_STATES,
  FINDING_AGE_DAYS_MAX,
  FIX_AVAILABLE_TOKENS,
  FIX_AVAILABLE_UNKNOWN_TOKENS,
  INTERNET_EXPOSURE_TOKENS,
  INTERNET_EXPOSURE_UNKNOWN_TOKENS,
  KEV_OBSERVED_TOKENS,
  KEV_UNAVAILABLE_REASONS,
  KEV_UNKNOWN_TOKENS,
  SEVERITY_MAX_VALUES,
  SEVERITY_RATINGS,
  SEVERITY_UNKNOWN_TOKENS,
  factorOrdinal,
  type AdvisoryWithdrawnToken,
  type AssetDataClassificationToken,
  type BusinessCriticalityToken,
  type DirectDependencyToken,
  type EnvironmentSensitivityToken,
  type FactorId,
  type FactorInputState,
  type FixAvailableToken,
  type InternetExposureToken,
  type KevObservedToken,
  type KevUnavailableReason,
  type KevUnknownToken,
  type SeverityRating,
} from './catalog.js';
import { deepFreeze } from './deep-freeze.js';
import { isOneOf, readPlainArray, readPlainRecord } from './plain-data.js';
import { err, ok, type Result } from './result.js';

type Unavailable = { readonly state: 'unavailable' };

export type SourceSeverityFact =
  | { readonly state: 'observed'; readonly values: readonly SeverityRating[] }
  | { readonly state: 'unknown'; readonly value: 'unrated' }
  | Unavailable;

export type KevListedFact =
  | { readonly state: 'observed'; readonly value: KevObservedToken }
  | { readonly state: 'unknown'; readonly value: KevUnknownToken }
  | { readonly state: 'unavailable'; readonly reason: KevUnavailableReason };

export type EnvironmentSensitivityFact =
  { readonly state: 'observed'; readonly value: EnvironmentSensitivityToken } | Unavailable;

export type InternetExposureFact =
  | { readonly state: 'observed'; readonly value: InternetExposureToken }
  | { readonly state: 'unknown'; readonly value: 'unknown' }
  | Unavailable;

export type BusinessCriticalityFact =
  | { readonly state: 'observed'; readonly value: BusinessCriticalityToken }
  | { readonly state: 'unknown'; readonly value: 'unspecified' }
  | Unavailable;

export type AssetDataClassificationFact =
  | { readonly state: 'observed'; readonly value: AssetDataClassificationToken }
  | { readonly state: 'unknown'; readonly value: 'unspecified' }
  | Unavailable;

export type DirectDependencyFact =
  { readonly state: 'observed'; readonly value: DirectDependencyToken } | Unavailable;

export type FixAvailableFact =
  | { readonly state: 'observed'; readonly value: FixAvailableToken }
  | { readonly state: 'unknown'; readonly value: 'undetermined' }
  | Unavailable;

export type FindingAgeDaysFact =
  { readonly state: 'observed'; readonly value: number } | Unavailable;

export type AdvisoryWithdrawnFact =
  { readonly state: 'observed'; readonly value: AdvisoryWithdrawnToken } | Unavailable;

export type PriorityFactInput = {
  readonly source_severity: SourceSeverityFact;
  readonly kev_listed: KevListedFact;
  readonly environment_sensitivity: EnvironmentSensitivityFact;
  readonly internet_exposure: InternetExposureFact;
  readonly business_criticality: BusinessCriticalityFact;
  readonly asset_data_classification: AssetDataClassificationFact;
  readonly direct_dependency: DirectDependencyFact;
  readonly fix_available: FixAvailableFact;
  readonly finding_age_days: FindingAgeDaysFact;
  readonly advisory_withdrawn: AdvisoryWithdrawnFact;
};

declare const parsedFactInputBrand: unique symbol;

/** Facts produced only by `parseFactInput`: a deep-frozen canonical copy. */
export type ParsedPriorityFactInput = PriorityFactInput & {
  readonly [parsedFactInputBrand]: true;
};

export const FACT_INPUT_ISSUE_CODES = [
  'facts_not_plain_object',
  'facts_not_parsed',
  'missing_factor',
  'unknown_factor',
  'factor_not_plain_object',
  'missing_state',
  'invalid_state',
  'state_not_accepted',
  'unexpected_property',
  'missing_value',
  'invalid_value',
  'value_not_integer',
  'value_out_of_range',
  'values_count_out_of_range',
  'missing_reason',
  'invalid_reason',
] as const;
export type FactInputIssueCode = (typeof FACT_INPUT_ISSUE_CODES)[number];

/** Issues never carry the rejected value or an unrecognized key name. */
export type FactInputIssue = {
  readonly factorId: FactorId | null;
  readonly code: FactInputIssueCode;
};

export type FactInputError = {
  readonly kind: 'invalid_fact_input';
  readonly issues: readonly FactInputIssue[];
};

type FactorSpec =
  | { readonly kind: 'severity' }
  | { readonly kind: 'age' }
  | {
      readonly kind: 'token';
      readonly observed: readonly string[];
      readonly unknown: readonly string[];
      readonly unavailableReasons: readonly string[];
    };

const NONE: readonly string[] = [];

const FACTOR_SPECS: { readonly [K in FactorId]: FactorSpec } = {
  source_severity: { kind: 'severity' },
  kev_listed: {
    kind: 'token',
    observed: KEV_OBSERVED_TOKENS,
    unknown: KEV_UNKNOWN_TOKENS,
    unavailableReasons: KEV_UNAVAILABLE_REASONS,
  },
  environment_sensitivity: {
    kind: 'token',
    observed: ENVIRONMENT_SENSITIVITY_TOKENS,
    unknown: NONE,
    unavailableReasons: NONE,
  },
  internet_exposure: {
    kind: 'token',
    observed: INTERNET_EXPOSURE_TOKENS,
    unknown: INTERNET_EXPOSURE_UNKNOWN_TOKENS,
    unavailableReasons: NONE,
  },
  business_criticality: {
    kind: 'token',
    observed: BUSINESS_CRITICALITY_TOKENS,
    unknown: BUSINESS_CRITICALITY_UNKNOWN_TOKENS,
    unavailableReasons: NONE,
  },
  asset_data_classification: {
    kind: 'token',
    observed: ASSET_DATA_CLASSIFICATION_TOKENS,
    unknown: ASSET_DATA_CLASSIFICATION_UNKNOWN_TOKENS,
    unavailableReasons: NONE,
  },
  direct_dependency: {
    kind: 'token',
    observed: DIRECT_DEPENDENCY_TOKENS,
    unknown: NONE,
    unavailableReasons: NONE,
  },
  fix_available: {
    kind: 'token',
    observed: FIX_AVAILABLE_TOKENS,
    unknown: FIX_AVAILABLE_UNKNOWN_TOKENS,
    unavailableReasons: NONE,
  },
  finding_age_days: { kind: 'age' },
  advisory_withdrawn: {
    kind: 'token',
    observed: ADVISORY_WITHDRAWN_TOKENS,
    unknown: NONE,
    unavailableReasons: NONE,
  },
};

function acceptsUnknown(spec: FactorSpec): boolean {
  if (spec.kind === 'severity') {
    return true;
  }
  if (spec.kind === 'age') {
    return false;
  }
  return spec.unknown.length > 0;
}

function payloadKey(
  spec: FactorSpec,
  state: FactorInputState,
): 'value' | 'values' | 'reason' | null {
  if (state === 'unavailable') {
    return spec.kind === 'token' && spec.unavailableReasons.length > 0 ? 'reason' : null;
  }
  return spec.kind === 'severity' && state === 'observed' ? 'values' : 'value';
}

type FactorParse = { readonly fact: unknown } | { readonly issues: readonly FactInputIssueCode[] };

type PayloadParse = Result<unknown, FactInputIssueCode>;

function parseSeverityValues(raw: unknown): PayloadParse {
  const values = readPlainArray(raw, SEVERITY_MAX_VALUES);
  if (values === 'not_array') {
    return err('invalid_value');
  }
  if (values === 'too_long' || values.length === 0) {
    return err('values_count_out_of_range');
  }
  const ratings: SeverityRating[] = [];
  for (const value of values) {
    if (!isOneOf(value, SEVERITY_RATINGS)) {
      return err('invalid_value');
    }
    ratings.push(value);
  }
  return ok(ratings);
}

function parseAgeDays(raw: unknown): PayloadParse {
  if (typeof raw !== 'number') {
    return err('invalid_value');
  }
  if (!Number.isInteger(raw)) {
    return err('value_not_integer');
  }
  if (raw < 0 || raw > FINDING_AGE_DAYS_MAX) {
    return err('value_out_of_range');
  }
  return ok(raw);
}

function parseToken(
  raw: unknown,
  allowed: readonly string[],
  code: FactInputIssueCode,
): PayloadParse {
  return isOneOf(raw, allowed) ? ok(raw) : err(code);
}

function parsePayload(
  spec: FactorSpec,
  state: FactorInputState,
  key: 'value' | 'values' | 'reason',
  raw: unknown,
): PayloadParse {
  if (key === 'values') {
    return parseSeverityValues(raw);
  }
  if (spec.kind === 'age') {
    return parseAgeDays(raw);
  }
  if (spec.kind === 'severity') {
    return parseToken(raw, SEVERITY_UNKNOWN_TOKENS, 'invalid_value');
  }
  if (key === 'reason') {
    return parseToken(raw, spec.unavailableReasons, 'invalid_reason');
  }
  return parseToken(raw, state === 'observed' ? spec.observed : spec.unknown, 'invalid_value');
}

const MISSING_PAYLOAD_CODE = {
  value: 'missing_value',
  values: 'missing_value',
  reason: 'missing_reason',
} as const satisfies Record<string, FactInputIssueCode>;

function parseFactor(spec: FactorSpec, raw: unknown): FactorParse {
  const record = readPlainRecord(raw);
  if (record === null) {
    return { issues: ['factor_not_plain_object'] };
  }
  if (!record.has('state')) {
    return { issues: ['missing_state'] };
  }
  const state = record.get('state');
  if (!isOneOf(state, FACTOR_INPUT_STATES)) {
    return { issues: ['invalid_state'] };
  }
  if (state === 'unknown' && !acceptsUnknown(spec)) {
    return { issues: ['state_not_accepted'] };
  }

  const issues: FactInputIssueCode[] = [];
  const key = payloadKey(spec, state);
  for (const property of record.keys()) {
    if (property !== 'state' && property !== key) {
      issues.push('unexpected_property');
      break;
    }
  }

  if (key === null) {
    return issues.length > 0 ? { issues } : { fact: { state } };
  }
  if (!record.has(key)) {
    issues.push(MISSING_PAYLOAD_CODE[key]);
    return { issues };
  }
  const payload = parsePayload(spec, state, key, record.get(key));
  if (!payload.ok) {
    issues.push(payload.error);
  }
  return issues.length > 0 || !payload.ok ? { issues } : { fact: { state, [key]: payload.value } };
}

function compareIssues(left: FactInputIssue, right: FactInputIssue): number {
  const leftOrdinal = left.factorId === null ? FACTOR_IDS.length + 1 : factorOrdinal(left.factorId);
  const rightOrdinal =
    right.factorId === null ? FACTOR_IDS.length + 1 : factorOrdinal(right.factorId);
  if (leftOrdinal !== rightOrdinal) {
    return leftOrdinal - rightOrdinal;
  }
  if (left.code === right.code) {
    return 0;
  }
  return left.code < right.code ? -1 : 1;
}

function factInputError(issues: readonly FactInputIssue[]): FactInputError {
  const unique = new Map<string, FactInputIssue>();
  for (const issue of issues) {
    unique.set(`${issue.factorId ?? ''}:${issue.code}`, issue);
  }
  return deepFreeze({
    kind: 'invalid_fact_input',
    issues: [...unique.values()].sort(compareIssues),
  });
}

const parsedFactInputs = new WeakSet<object>();

export function isParsedPriorityFactInput(value: unknown): value is ParsedPriorityFactInput {
  return typeof value === 'object' && value !== null && parsedFactInputs.has(value);
}

export function factsNotParsedError(): FactInputError {
  return factInputError([{ factorId: null, code: 'facts_not_parsed' }]);
}

/**
 * Parses untrusted facts into a deep-frozen canonical copy. The input must
 * carry exactly the 10 catalog factors. Any violation rejects the whole input
 * with closed issue codes ordered by catalog ordinal, then code.
 */
export function parseFactInput(input: unknown): Result<ParsedPriorityFactInput, FactInputError> {
  const record = readPlainRecord(input);
  if (record === null) {
    return err(factInputError([{ factorId: null, code: 'facts_not_plain_object' }]));
  }

  const issues: FactInputIssue[] = [];
  for (const key of record.keys()) {
    if (!isOneOf(key, FACTOR_IDS)) {
      issues.push({ factorId: null, code: 'unknown_factor' });
    }
  }

  const facts: Partial<Record<FactorId, unknown>> = {};
  for (const factorId of FACTOR_IDS) {
    if (!record.has(factorId)) {
      issues.push({ factorId, code: 'missing_factor' });
      continue;
    }
    const parsed = parseFactor(FACTOR_SPECS[factorId], record.get(factorId));
    if ('issues' in parsed) {
      for (const code of parsed.issues) {
        issues.push({ factorId, code });
      }
    } else {
      facts[factorId] = parsed.fact;
    }
  }

  if (issues.length > 0) {
    return err(factInputError(issues));
  }
  const parsed = deepFreeze(facts) as ParsedPriorityFactInput;
  parsedFactInputs.add(parsed);
  return ok(parsed);
}
