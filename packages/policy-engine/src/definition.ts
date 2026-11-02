import {
  DUE_DATE_RECOMMENDATION_DAYS_MAX,
  DUE_DATE_RECOMMENDATION_DAYS_MIN,
  FACTOR_DESCRIPTION_MAX_LENGTH,
  FACTOR_IDS,
  FINDING_AGE_BUCKETS_MAX,
  FINDING_AGE_DAYS_MAX,
  INFORMATIONAL_FACTOR_ID,
  KEV_ESCALATION_RULE,
  NORMALIZATION_KEYS,
  NORMALIZED_TOKEN_FACTORS,
  NORMALIZED_TOKEN_FACTOR_IDS,
  OVERRIDE_WEIGHT_BOUNDS,
  PERCENT_MAX,
  POLICY_KEY_MAX_LENGTH,
  PRIORITY_BANDS,
  PRIORITY_ENGINE_CONTRACT,
  PRIORITY_MAX,
  PRIORITY_POLICY_SCHEMA_VERSION,
  WEIGHT_SUM,
  type FactorId,
  type NormalizedTokenFactorId,
  type PriorityBand,
} from './catalog.js';
import { deepFreeze } from './deep-freeze.js';
import { isOneOf, readPlainArray, readPlainRecord } from './plain-data.js';
import { err, ok, type Result } from './result.js';

export type FactorCatalogEntry = {
  readonly factorId: FactorId;
  readonly description: string;
};

export type PolicyWeights = { readonly [K in FactorId]: number };

export type AgeBucket = {
  readonly minDays: number;
  readonly percent: number;
};

export type PolicyNormalization = {
  readonly [F in NormalizedTokenFactorId]: {
    readonly [T in (typeof NORMALIZED_TOKEN_FACTORS)[F][number]]: number;
  };
} & {
  readonly finding_age_days: readonly AgeBucket[];
};

export type PolicyBand = {
  readonly band: PriorityBand;
  readonly minPriority: number;
  readonly dueDateRecommendationDays: number;
};

export type PolicyRules = {
  readonly kevMinimumBand: PriorityBand;
  readonly kevEscalation: typeof KEV_ESCALATION_RULE;
};

/** Policy definition document v2. The policy version is a column, not a field. */
export type PriorityPolicyDefinition = {
  readonly schemaVersion: typeof PRIORITY_POLICY_SCHEMA_VERSION;
  readonly policyKey: string;
  readonly engineContract: typeof PRIORITY_ENGINE_CONTRACT;
  readonly factorCatalog: readonly FactorCatalogEntry[];
  readonly weights: PolicyWeights;
  readonly normalization: PolicyNormalization;
  readonly bands: readonly PolicyBand[];
  readonly rules: PolicyRules;
};

declare const validatedPolicyDefinitionBrand: unique symbol;

/** Definitions produced only by validation: a deep-frozen canonical copy. */
export type ValidatedPriorityPolicyDefinition = PriorityPolicyDefinition & {
  readonly [validatedPolicyDefinitionBrand]: true;
};

export const POLICY_DEFINITION_ISSUE_CODES = [
  'not_plain_object',
  'definition_not_validated',
  'missing_key',
  'unexpected_key',
  'invalid_type',
  'unsupported_schema_version',
  'engine_contract_mismatch',
  'invalid_policy_key',
  'invalid_description',
  'unknown_factor',
  'missing_factor',
  'duplicate_factor',
  'catalog_order_mismatch',
  'count_out_of_range',
  'non_finite_number',
  'not_integer',
  'out_of_range',
  'weight_sum_not_100',
  'withdrawn_weight_not_zero',
  'unknown_token',
  'missing_token',
  'percent_order_violation',
  'favorable_extreme_not_zero',
  'age_bucket_start_not_zero',
  'age_bucket_order_violation',
  'band_order_mismatch',
  'band_threshold_order_violation',
  'lowest_band_minimum_not_zero',
  'due_days_order_violation',
  'invalid_rule',
] as const;
export type PolicyDefinitionIssueCode = (typeof POLICY_DEFINITION_ISSUE_CODES)[number];

/** Paths are built from engine-known keys and indices only. */
export type PolicyDefinitionIssue = {
  readonly path: string;
  readonly code: PolicyDefinitionIssueCode;
};

export type PolicyDefinitionError = {
  readonly kind: 'invalid_policy_definition';
  readonly issues: readonly PolicyDefinitionIssue[];
};

export const POLICY_OVERRIDE_ISSUE_CODES = [
  'parent_not_validated',
  'differs_from_parent',
  'weight_outside_override_bounds',
] as const;
export type PolicyOverrideIssueCode = (typeof POLICY_OVERRIDE_ISSUE_CODES)[number];

export type PolicyOverrideIssue = {
  readonly path: string;
  readonly code: PolicyOverrideIssueCode;
};

export type PolicyOverrideError = {
  readonly kind: 'invalid_policy_override';
  readonly issues: readonly PolicyOverrideIssue[];
};

const ROOT = '$';
const TOP_LEVEL_KEYS = [
  'schemaVersion',
  'policyKey',
  'engineContract',
  'factorCatalog',
  'weights',
  'normalization',
  'bands',
  'rules',
] as const;
const CATALOG_ENTRY_KEYS = ['factorId', 'description'] as const;
const AGE_BUCKET_KEYS = ['minDays', 'percent'] as const;
const BAND_KEYS = ['band', 'minPriority', 'dueDateRecommendationDays'] as const;
const RULE_KEYS = ['kevMinimumBand', 'kevEscalation'] as const;
const CATALOG_SCAN_MAX = FACTOR_IDS.length * 4;
const POLICY_KEY_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return true;
    }
  }
  return false;
}

class IssueCollector {
  readonly #issues: PolicyDefinitionIssue[] = [];
  readonly #seen = new Set<string>();

  add(path: string, code: PolicyDefinitionIssueCode): void {
    const key = `${path}:${code}`;
    if (!this.#seen.has(key)) {
      this.#seen.add(key);
      this.#issues.push({ path, code });
    }
  }

  get count(): number {
    return this.#issues.length;
  }

  toError(): PolicyDefinitionError {
    return deepFreeze({ kind: 'invalid_policy_definition', issues: [...this.#issues] });
  }
}

function readRecordWithKeys(
  value: unknown,
  keys: readonly string[],
  path: string,
  issues: IssueCollector,
  unexpectedCode: PolicyDefinitionIssueCode = 'unexpected_key',
): ReadonlyMap<string, unknown> | null {
  const record = readPlainRecord(value);
  if (record === null) {
    issues.add(path, 'not_plain_object');
    return null;
  }
  for (const key of record.keys()) {
    if (!keys.includes(key)) {
      issues.add(path, unexpectedCode);
    }
  }
  let complete = true;
  for (const key of keys) {
    if (!record.has(key)) {
      issues.add(`${path}.${key}`, 'missing_key');
      complete = false;
    }
  }
  return complete ? record : null;
}

function readInteger(
  value: unknown,
  min: number,
  max: number,
  path: string,
  issues: IssueCollector,
): number | null {
  if (typeof value !== 'number') {
    issues.add(path, 'invalid_type');
    return null;
  }
  if (!Number.isFinite(value)) {
    issues.add(path, 'non_finite_number');
    return null;
  }
  if (!Number.isInteger(value)) {
    issues.add(path, 'not_integer');
    return null;
  }
  if (value < min || value > max) {
    issues.add(path, 'out_of_range');
    return null;
  }
  return value;
}

function isNonIncreasing(values: readonly number[]): boolean {
  return values.every((value, index) => index === 0 || value <= (values[index - 1] ?? value));
}

function isNonDecreasing(values: readonly number[]): boolean {
  return values.every((value, index) => index === 0 || value >= (values[index - 1] ?? value));
}

function isStrictlyIncreasing(values: readonly number[]): boolean {
  return values.every((value, index) => index === 0 || value > (values[index - 1] ?? value));
}

function isStrictlyDecreasing(values: readonly number[]): boolean {
  return values.every((value, index) => index === 0 || value < (values[index - 1] ?? value));
}

function validatePolicyKey(value: unknown, issues: IssueCollector): string | null {
  if (
    typeof value !== 'string' ||
    value.length > POLICY_KEY_MAX_LENGTH ||
    !POLICY_KEY_PATTERN.test(value)
  ) {
    issues.add('policyKey', 'invalid_policy_key');
    return null;
  }
  return value;
}

function validateDescription(value: unknown, path: string, issues: IssueCollector): string | null {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > FACTOR_DESCRIPTION_MAX_LENGTH ||
    hasControlCharacter(value)
  ) {
    issues.add(path, 'invalid_description');
    return null;
  }
  return value;
}

function validateFactorCatalog(
  value: unknown,
  issues: IssueCollector,
): readonly FactorCatalogEntry[] | null {
  const entries = readPlainArray(value, CATALOG_SCAN_MAX);
  if (entries === 'not_array') {
    issues.add('factorCatalog', 'invalid_type');
    return null;
  }
  if (entries === 'too_long') {
    issues.add('factorCatalog', 'count_out_of_range');
    return null;
  }

  const before = issues.count;
  const catalog: FactorCatalogEntry[] = [];
  const seen = new Set<FactorId>();
  entries.forEach((entry, index) => {
    const path = `factorCatalog[${index}]`;
    const record = readRecordWithKeys(entry, CATALOG_ENTRY_KEYS, path, issues);
    if (record === null) {
      return;
    }
    const factorId = record.get('factorId');
    const description = validateDescription(
      record.get('description'),
      `${path}.description`,
      issues,
    );
    if (!isOneOf(factorId, FACTOR_IDS)) {
      issues.add('factorCatalog', 'unknown_factor');
      return;
    }
    if (seen.has(factorId)) {
      issues.add('factorCatalog', 'duplicate_factor');
      return;
    }
    seen.add(factorId);
    if (description !== null) {
      catalog.push({ factorId, description });
    }
  });
  for (const factorId of FACTOR_IDS) {
    if (!seen.has(factorId)) {
      issues.add(`factorCatalog.${factorId}`, 'missing_factor');
    }
  }
  if (issues.count > before) {
    return null;
  }
  if (catalog.some((entry, index) => entry.factorId !== FACTOR_IDS[index])) {
    issues.add('factorCatalog', 'catalog_order_mismatch');
    return null;
  }
  return catalog;
}

function validateWeights(value: unknown, issues: IssueCollector): PolicyWeights | null {
  const record = readRecordWithKeys(value, FACTOR_IDS, 'weights', issues, 'unknown_factor');
  if (record === null) {
    return null;
  }
  const before = issues.count;
  const weights: Partial<Record<FactorId, number>> = {};
  for (const factorId of FACTOR_IDS) {
    const weight = readInteger(record.get(factorId), 0, WEIGHT_SUM, `weights.${factorId}`, issues);
    if (weight !== null) {
      weights[factorId] = weight;
    }
  }
  if (issues.count > before) {
    return null;
  }
  const complete = weights as PolicyWeights;
  if (complete[INFORMATIONAL_FACTOR_ID] !== 0) {
    issues.add(`weights.${INFORMATIONAL_FACTOR_ID}`, 'withdrawn_weight_not_zero');
  }
  const sum = FACTOR_IDS.reduce((total, factorId) => total + complete[factorId], 0);
  if (sum !== WEIGHT_SUM) {
    issues.add('weights', 'weight_sum_not_100');
  }
  return issues.count > before ? null : complete;
}

function validateTokenPercents(
  factorId: NormalizedTokenFactorId,
  value: unknown,
  issues: IssueCollector,
): Readonly<Record<string, number>> | null {
  const path = `normalization.${factorId}`;
  const tokens: readonly string[] = NORMALIZED_TOKEN_FACTORS[factorId];
  const record = readPlainRecord(value);
  if (record === null) {
    issues.add(path, 'not_plain_object');
    return null;
  }
  const before = issues.count;
  for (const key of record.keys()) {
    if (!tokens.includes(key)) {
      issues.add(path, 'unknown_token');
    }
  }
  const percents: Record<string, number> = {};
  const ordered: number[] = [];
  for (const token of tokens) {
    if (!record.has(token)) {
      issues.add(`${path}.${token}`, 'missing_token');
      continue;
    }
    const percent = readInteger(record.get(token), 0, PERCENT_MAX, `${path}.${token}`, issues);
    if (percent !== null) {
      percents[token] = percent;
      ordered.push(percent);
    }
  }
  if (issues.count > before) {
    return null;
  }
  if (!isNonIncreasing(ordered)) {
    issues.add(path, 'percent_order_violation');
  }
  if (ordered[ordered.length - 1] !== 0) {
    issues.add(path, 'favorable_extreme_not_zero');
  }
  return issues.count > before ? null : percents;
}

function validateAgeBuckets(value: unknown, issues: IssueCollector): readonly AgeBucket[] | null {
  const path = 'normalization.finding_age_days';
  const entries = readPlainArray(value, FINDING_AGE_BUCKETS_MAX);
  if (entries === 'not_array') {
    issues.add(path, 'invalid_type');
    return null;
  }
  if (entries === 'too_long' || entries.length === 0) {
    issues.add(path, 'count_out_of_range');
    return null;
  }
  const before = issues.count;
  const buckets: AgeBucket[] = [];
  entries.forEach((entry, index) => {
    const entryPath = `${path}[${index}]`;
    const record = readRecordWithKeys(entry, AGE_BUCKET_KEYS, entryPath, issues);
    if (record === null) {
      return;
    }
    const minDays = readInteger(
      record.get('minDays'),
      0,
      FINDING_AGE_DAYS_MAX,
      `${entryPath}.minDays`,
      issues,
    );
    const percent = readInteger(
      record.get('percent'),
      0,
      PERCENT_MAX,
      `${entryPath}.percent`,
      issues,
    );
    if (minDays !== null && percent !== null) {
      buckets.push({ minDays, percent });
    }
  });
  if (issues.count > before) {
    return null;
  }
  const first = buckets[0];
  if (first?.minDays !== 0) {
    issues.add(path, 'age_bucket_start_not_zero');
  }
  if (first?.percent !== 0) {
    issues.add(path, 'favorable_extreme_not_zero');
  }
  if (!isStrictlyIncreasing(buckets.map((bucket) => bucket.minDays))) {
    issues.add(path, 'age_bucket_order_violation');
  }
  if (!isNonDecreasing(buckets.map((bucket) => bucket.percent))) {
    issues.add(path, 'percent_order_violation');
  }
  return issues.count > before ? null : buckets;
}

function validateNormalization(value: unknown, issues: IssueCollector): PolicyNormalization | null {
  const record = readRecordWithKeys(value, NORMALIZATION_KEYS, 'normalization', issues);
  if (record === null) {
    return null;
  }
  const before = issues.count;
  const normalization: Record<string, unknown> = {};
  for (const factorId of NORMALIZED_TOKEN_FACTOR_IDS) {
    normalization[factorId] = validateTokenPercents(factorId, record.get(factorId), issues);
  }
  normalization['finding_age_days'] = validateAgeBuckets(record.get('finding_age_days'), issues);
  return issues.count > before ? null : (normalization as PolicyNormalization);
}

function validateBands(value: unknown, issues: IssueCollector): readonly PolicyBand[] | null {
  const entries = readPlainArray(value, PRIORITY_BANDS.length);
  if (entries === 'not_array') {
    issues.add('bands', 'invalid_type');
    return null;
  }
  if (entries === 'too_long' || entries.length !== PRIORITY_BANDS.length) {
    issues.add('bands', 'count_out_of_range');
    return null;
  }
  const before = issues.count;
  const bands: PolicyBand[] = [];
  entries.forEach((entry, index) => {
    const path = `bands[${index}]`;
    const record = readRecordWithKeys(entry, BAND_KEYS, path, issues);
    if (record === null) {
      return;
    }
    const band = record.get('band');
    if (band !== PRIORITY_BANDS[index]) {
      issues.add(`${path}.band`, 'band_order_mismatch');
    }
    const minPriority = readInteger(
      record.get('minPriority'),
      0,
      PRIORITY_MAX,
      `${path}.minPriority`,
      issues,
    );
    const dueDays = readInteger(
      record.get('dueDateRecommendationDays'),
      DUE_DATE_RECOMMENDATION_DAYS_MIN,
      DUE_DATE_RECOMMENDATION_DAYS_MAX,
      `${path}.dueDateRecommendationDays`,
      issues,
    );
    if (isOneOf(band, PRIORITY_BANDS) && minPriority !== null && dueDays !== null) {
      bands.push({ band, minPriority, dueDateRecommendationDays: dueDays });
    }
  });
  if (issues.count > before) {
    return null;
  }
  if (!isStrictlyDecreasing(bands.map((band) => band.minPriority))) {
    issues.add('bands', 'band_threshold_order_violation');
  }
  if (bands[bands.length - 1]?.minPriority !== 0) {
    issues.add('bands', 'lowest_band_minimum_not_zero');
  }
  if (!isNonDecreasing(bands.map((band) => band.dueDateRecommendationDays))) {
    issues.add('bands', 'due_days_order_violation');
  }
  return issues.count > before ? null : bands;
}

function validateRules(value: unknown, issues: IssueCollector): PolicyRules | null {
  const record = readRecordWithKeys(value, RULE_KEYS, 'rules', issues);
  if (record === null) {
    return null;
  }
  const kevMinimumBand = record.get('kevMinimumBand');
  const kevEscalation = record.get('kevEscalation');
  let valid = true;
  if (!isOneOf(kevMinimumBand, PRIORITY_BANDS)) {
    issues.add('rules.kevMinimumBand', 'invalid_rule');
    valid = false;
  }
  if (kevEscalation !== KEV_ESCALATION_RULE) {
    issues.add('rules.kevEscalation', 'invalid_rule');
    valid = false;
  }
  return valid && isOneOf(kevMinimumBand, PRIORITY_BANDS)
    ? { kevMinimumBand, kevEscalation: KEV_ESCALATION_RULE }
    : null;
}

const validatedDefinitions = new WeakSet<object>();

export function isValidatedPriorityPolicyDefinition(
  value: unknown,
): value is ValidatedPriorityPolicyDefinition {
  return typeof value === 'object' && value !== null && validatedDefinitions.has(value);
}

export function definitionNotValidatedError(): PolicyDefinitionError {
  return deepFreeze({
    kind: 'invalid_policy_definition',
    issues: [{ path: ROOT, code: 'definition_not_validated' }],
  });
}

/**
 * Validates an untrusted v2 policy definition and returns a deep-frozen
 * canonical copy. Key order in the input does not affect the result.
 */
export function validatePolicyDefinition(
  input: unknown,
): Result<ValidatedPriorityPolicyDefinition, PolicyDefinitionError> {
  const issues = new IssueCollector();
  const record = readPlainRecord(input);
  if (record === null) {
    issues.add(ROOT, 'not_plain_object');
    return err(issues.toError());
  }
  if (record.get('schemaVersion') !== PRIORITY_POLICY_SCHEMA_VERSION) {
    issues.add('schemaVersion', 'unsupported_schema_version');
    return err(issues.toError());
  }
  for (const key of record.keys()) {
    if (!isOneOf(key, TOP_LEVEL_KEYS)) {
      issues.add(ROOT, 'unexpected_key');
    }
  }
  for (const key of TOP_LEVEL_KEYS) {
    if (!record.has(key)) {
      issues.add(key, 'missing_key');
    }
  }
  if (record.has('engineContract') && record.get('engineContract') !== PRIORITY_ENGINE_CONTRACT) {
    issues.add('engineContract', 'engine_contract_mismatch');
  }

  const policyKey = record.has('policyKey')
    ? validatePolicyKey(record.get('policyKey'), issues)
    : null;
  const factorCatalog = record.has('factorCatalog')
    ? validateFactorCatalog(record.get('factorCatalog'), issues)
    : null;
  const weights = record.has('weights') ? validateWeights(record.get('weights'), issues) : null;
  const normalization = record.has('normalization')
    ? validateNormalization(record.get('normalization'), issues)
    : null;
  const bands = record.has('bands') ? validateBands(record.get('bands'), issues) : null;
  const rules = record.has('rules') ? validateRules(record.get('rules'), issues) : null;

  if (
    issues.count > 0 ||
    policyKey === null ||
    factorCatalog === null ||
    weights === null ||
    normalization === null ||
    bands === null ||
    rules === null
  ) {
    return err(issues.toError());
  }

  const definition: PriorityPolicyDefinition = {
    schemaVersion: PRIORITY_POLICY_SCHEMA_VERSION,
    policyKey,
    engineContract: PRIORITY_ENGINE_CONTRACT,
    factorCatalog,
    weights,
    normalization,
    bands,
    rules,
  };
  const validated = deepFreeze(definition) as ValidatedPriorityPolicyDefinition;
  validatedDefinitions.add(validated);
  return ok(validated);
}

function canonicalSection(value: unknown): string {
  return JSON.stringify(value);
}

/**
 * Validates an organization override against its validated parent. Only
 * weights may differ, each inside `OVERRIDE_WEIGHT_BOUNDS`. Every other field,
 * including catalog descriptions, must equal the parent.
 */
export function validatePolicyOverride(
  parent: ValidatedPriorityPolicyDefinition,
  candidate: unknown,
): Result<ValidatedPriorityPolicyDefinition, PolicyDefinitionError | PolicyOverrideError> {
  if (!isValidatedPriorityPolicyDefinition(parent)) {
    return err(
      deepFreeze({
        kind: 'invalid_policy_override',
        issues: [{ path: ROOT, code: 'parent_not_validated' }],
      }),
    );
  }
  const validated = validatePolicyDefinition(candidate);
  if (!validated.ok) {
    return validated;
  }
  const override = validated.value;
  const issues: PolicyOverrideIssue[] = [];
  const sections = ['policyKey', 'factorCatalog', 'normalization', 'bands', 'rules'] as const;
  for (const section of sections) {
    if (canonicalSection(override[section]) !== canonicalSection(parent[section])) {
      issues.push({ path: section, code: 'differs_from_parent' });
    }
  }
  for (const factorId of FACTOR_IDS) {
    const [min, max] = OVERRIDE_WEIGHT_BOUNDS[factorId];
    const weight = override.weights[factorId];
    if (weight < min || weight > max) {
      issues.push({ path: `weights.${factorId}`, code: 'weight_outside_override_bounds' });
    }
  }
  if (issues.length > 0) {
    return err(deepFreeze({ kind: 'invalid_policy_override', issues }));
  }
  return ok(override);
}
