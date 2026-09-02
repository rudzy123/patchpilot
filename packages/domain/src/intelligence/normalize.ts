import { err, ok, type Result } from '../result.js';
import {
  CALENDAR_DATE_PATTERN,
  CANONICAL_CVE_PATTERN,
  CANONICAL_CWE_PATTERN,
  INTELLIGENCE_CWE_MAX_COUNT,
  INTELLIGENCE_CWE_MAX_LENGTH,
  INTELLIGENCE_RAW_RANSOMWARE_MAX_LENGTH,
  INTELLIGENCE_TEXT_FIELD_MAX_BYTES,
  UTC_INSTANT_PATTERN,
  type KnownRansomwareCampaignUse,
} from './constants.js';
import { intelligenceValidationError } from './errors.js';

const JSON_STRING_WHITESPACE = new Set([' ', '\t', '\n', '\r']);

export type CanonicalCve = string & { readonly __canonicalCve: unique symbol };
export type CalendarDate = string & { readonly __calendarDate: unique symbol };

export function isNonNegativeSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

export function isPositiveSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

export function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function isAscii(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code > 0x7f) {
      return false;
    }
  }
  return true;
}

function trimJsonStringWhitespace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && JSON_STRING_WHITESPACE.has(value[start] ?? '')) {
    start += 1;
  }
  while (end > start && JSON_STRING_WHITESPACE.has(value[end - 1] ?? '')) {
    end -= 1;
  }
  return value.slice(start, end);
}

function asciiUppercase(value: string): string {
  let result = '';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0x61 && code <= 0x7a) {
      result += String.fromCharCode(code - 0x20);
    } else {
      result += value[index] ?? '';
    }
  }
  return result;
}

/**
 * Canonical KEV CVE parser. Surrounding JSON-string whitespace may be trimmed.
 * Unicode lookalikes, embedded whitespace, and control characters fail as
 * malformed_cve. This does not look up CVEs or create Vulnerability rows.
 */
export function normalizeKevCve(value: string): Result<CanonicalCve> {
  if (!isAscii(value)) {
    return err(intelligenceValidationError('malformed_cve'));
  }
  const trimmed = trimJsonStringWhitespace(value);
  if (trimmed.length === 0 || trimmed !== trimmed.trim()) {
    return err(intelligenceValidationError('malformed_cve'));
  }
  for (let index = 0; index < trimmed.length; index += 1) {
    const code = trimmed.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) {
      return err(intelligenceValidationError('malformed_cve'));
    }
  }
  const canonical = asciiUppercase(trimmed);
  if (!CANONICAL_CVE_PATTERN.test(canonical)) {
    return err(intelligenceValidationError('malformed_cve'));
  }
  return ok(canonical as CanonicalCve);
}

export function isCanonicalCve(value: string): value is CanonicalCve {
  return CANONICAL_CVE_PATTERN.test(value);
}

const daysInMonth = (year: number, month: number): number => {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  if ([4, 6, 9, 11].includes(month)) {
    return 30;
  }
  return 31;
};

/**
 * Calendar dates are canonical YYYY-MM-DD strings. They are not Date objects
 * and must not be interpreted in a local timezone.
 */
export function parseCalendarDate(value: string): Result<CalendarDate> {
  if (!CALENDAR_DATE_PATTERN.test(value)) {
    return err(intelligenceValidationError('Calendar date must be canonical YYYY-MM-DD.'));
  }
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
    return err(intelligenceValidationError('Calendar date is not a valid Gregorian date.'));
  }
  return ok(value as CalendarDate);
}

export function calendarDateEquals(left: CalendarDate, right: CalendarDate): boolean {
  return left === right;
}

export function parseUtcInstant(value: string): Result<Date> {
  if (!UTC_INSTANT_PATTERN.test(value)) {
    return err(intelligenceValidationError('Timestamp must be a UTC ISO-8601 instant.'));
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return err(intelligenceValidationError('Timestamp must be a UTC ISO-8601 instant.'));
  }
  return ok(parsed);
}

export function formatUtcInstant(value: Date): string {
  return value.toISOString();
}

export type NormalizedRansomwareCampaignUse = {
  knownRansomwareCampaignUse: KnownRansomwareCampaignUse;
  rawKnownRansomwareCampaignUse: string | null;
};

/**
 * Official KEV values Known and Unknown map to closed normalized values.
 * Unrecognized provider text maps to other and retains the bounded raw value.
 * Unrecognized values are never silently converted to unknown.
 */
export function normalizeKnownRansomwareCampaignUse(
  raw: string,
): Result<NormalizedRansomwareCampaignUse> {
  if (!isAscii(raw)) {
    return retainAsOther(raw);
  }
  const trimmed = trimJsonStringWhitespace(raw);
  const canonical = asciiUppercase(trimmed);
  if (canonical === 'KNOWN') {
    return ok({
      knownRansomwareCampaignUse: 'known',
      rawKnownRansomwareCampaignUse: null,
    });
  }
  if (canonical === 'UNKNOWN') {
    return ok({
      knownRansomwareCampaignUse: 'unknown',
      rawKnownRansomwareCampaignUse: null,
    });
  }
  return retainAsOther(trimmed.length === 0 ? raw : trimmed);
}

function retainAsOther(raw: string): Result<NormalizedRansomwareCampaignUse> {
  if (raw.length === 0 || utf8ByteLength(raw) > INTELLIGENCE_RAW_RANSOMWARE_MAX_LENGTH) {
    return err(intelligenceValidationError('text_field_limit'));
  }
  return ok({
    knownRansomwareCampaignUse: 'other',
    rawKnownRansomwareCampaignUse: raw,
  });
}

export function parseCweIdentifier(value: string): Result<string> {
  if (!isAscii(value) || !CANONICAL_CWE_PATTERN.test(value)) {
    return err(intelligenceValidationError('CWE identifier is not canonical.'));
  }
  if (value.length > INTELLIGENCE_CWE_MAX_LENGTH) {
    return err(intelligenceValidationError('text_field_limit'));
  }
  return ok(value);
}

export function parseCweList(values: readonly string[]): Result<readonly string[]> {
  if (values.length > INTELLIGENCE_CWE_MAX_COUNT) {
    return err(intelligenceValidationError('cwe_count_limit'));
  }
  const parsed: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const cwe = parseCweIdentifier(value);
    if (!cwe.ok) {
      return cwe;
    }
    if (seen.has(cwe.value)) {
      continue;
    }
    seen.add(cwe.value);
    parsed.push(cwe.value);
  }
  return ok(parsed);
}

/**
 * Provider text is untrusted plain text. Contracts fail rather than truncate.
 * Callers must not interpret the value as HTML or Markdown.
 */
export function parseUntrustedPlainText(
  value: string,
  maxBytes: number = INTELLIGENCE_TEXT_FIELD_MAX_BYTES,
): Result<string> {
  if (utf8ByteLength(value) > maxBytes) {
    return err(intelligenceValidationError('text_field_limit'));
  }
  return ok(value);
}

export function findDuplicateNormalizedCves(
  entries: readonly { normalizedCve: string }[],
): readonly string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.normalizedCve)) {
      duplicates.add(entry.normalizedCve);
    }
    seen.add(entry.normalizedCve);
  }
  return [...duplicates];
}
