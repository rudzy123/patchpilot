import { describe, expect, it } from 'vitest';

import {
  calendarDateEquals,
  findDuplicateNormalizedCves,
  normalizeKevCve,
  normalizeKnownRansomwareCampaignUse,
  parseCalendarDate,
  parseUntrustedPlainText,
  utf8ByteLength,
} from './normalize.js';

describe('KEV CVE canonicalization', () => {
  it('uppercases lowercase ASCII CVE identifiers after trimming JSON whitespace', () => {
    const parsed = normalizeKevCve('  cve-2024-12345\n');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value).toBe('CVE-2024-12345');
    }
  });

  it('rejects malformed, lookalike, and whitespace-embedded values', () => {
    expect(normalizeKevCve('CVE-24-1234').ok).toBe(false);
    expect(normalizeKevCve('CVE-2024-123').ok).toBe(false);
    expect(normalizeKevCve('CVE-2024-1234 ').ok).toBe(true);
    expect(normalizeKevCve('CVE-2024- 1234').ok).toBe(false);
    expect(normalizeKevCve('CVE-2024-1234\u0000').ok).toBe(false);
    expect(normalizeKevCve('СVE-2024-1234').ok).toBe(false);
    expect(normalizeKevCve('https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234').ok).toBe(
      false,
    );
  });

  it('detects duplicate normalized CVEs', () => {
    expect(
      findDuplicateNormalizedCves([
        { normalizedCve: 'CVE-2024-1111' },
        { normalizedCve: 'CVE-2024-2222' },
        { normalizedCve: 'CVE-2024-1111' },
      ]),
    ).toEqual(['CVE-2024-1111']);
  });
});

describe('calendar dates and untrusted text', () => {
  it('parses YYYY-MM-DD without using local midnight Date conversion', () => {
    const parsed = parseCalendarDate('2024-01-15');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value).toBe('2024-01-15');
      expect(calendarDateEquals(parsed.value, parsed.value)).toBe(true);
      expect(new Date(parsed.value).toString()).not.toBe(parsed.value);
    }
    expect(parseCalendarDate('2024-13-01').ok).toBe(false);
    expect(parseCalendarDate('2024/01/15').ok).toBe(false);
  });

  it('retains untrusted provider text without HTML interpretation', () => {
    const html = '<script>alert(1)</script>';
    const parsed = parseUntrustedPlainText(html);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value).toBe(html);
      expect(parsed.value).toContain('<script>');
    }
    expect(parseUntrustedPlainText('a'.repeat(utf8ByteLength('a') + 20_000)).ok).toBe(false);
  });
});

describe('ransomware campaign use', () => {
  it('maps Known and Unknown without treating Unknown as known false', () => {
    expect(normalizeKnownRansomwareCampaignUse('Known')).toEqual({
      ok: true,
      value: { knownRansomwareCampaignUse: 'known', rawKnownRansomwareCampaignUse: null },
    });
    expect(normalizeKnownRansomwareCampaignUse('Unknown')).toEqual({
      ok: true,
      value: { knownRansomwareCampaignUse: 'unknown', rawKnownRansomwareCampaignUse: null },
    });
  });

  it('maps unrecognized values to other and preserves the raw value', () => {
    const parsed = normalizeKnownRansomwareCampaignUse('Suspected');
    expect(parsed).toEqual({
      ok: true,
      value: {
        knownRansomwareCampaignUse: 'other',
        rawKnownRansomwareCampaignUse: 'Suspected',
      },
    });
    expect(parsed.ok && parsed.value.knownRansomwareCampaignUse).not.toBe('unknown');
  });
});
