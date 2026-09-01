import { describe, expect, it } from 'vitest';

import type { IntelligenceKevParsedEntry } from './ports.js';
import type { KevNormalizedEntryRecord } from './records.js';
import { parsedEntryMatchesStaged, verifyDenseStagedPrefix } from './staging-resume.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');

function parsed(ordinal: number, cve: string): IntelligenceKevParsedEntry {
  return {
    ordinal,
    normalizedCve: cve,
    vendorProject: 'Northwind',
    product: 'Widget',
    vulnerabilityName: 'Synthetic',
    dateAdded: '2099-01-02',
    shortDescription: 'desc',
    requiredAction: 'patch',
    dueDate: '2099-01-16',
    knownRansomwareCampaignUse: 'known',
    rawKnownRansomwareCampaignUse: 'Known',
    notes: null,
    cwes: ['CWE-79'],
  };
}

function staged(ordinal: number, cve: string): KevNormalizedEntryRecord {
  return {
    id: `00000000-0000-4000-8000-${ordinal.toString().padStart(12, '0')}`,
    generationId: '11111111-1111-4111-8111-111111111111',
    snapshotId: '22222222-2222-4222-8222-222222222222',
    ordinal,
    normalizedCve: cve as KevNormalizedEntryRecord['normalizedCve'],
    vendorProject: 'Northwind',
    product: 'Widget',
    vulnerabilityName: 'Synthetic',
    dateAdded: '2099-01-02' as KevNormalizedEntryRecord['dateAdded'],
    shortDescription: 'desc',
    requiredAction: 'patch',
    dueDate: '2099-01-16' as KevNormalizedEntryRecord['dueDate'],
    knownRansomwareCampaignUse: 'known',
    rawKnownRansomwareCampaignUse: 'Known',
    notes: null,
    cwes: ['CWE-79'],
    createdAt: NOW,
  };
}

describe('dense-prefix staging resume', () => {
  it('resumes at the next ordinal when the prefix matches exactly', () => {
    const result = verifyDenseStagedPrefix({
      staged: [staged(0, 'CVE-2099-0001')],
      parsed: [parsed(0, 'CVE-2099-0001'), parsed(1, 'CVE-2099-0002')],
      authoritativeCount: 1,
    });
    expect(result).toEqual({ ok: true, resumeOrdinal: 1 });
    expect(parsedEntryMatchesStaged(parsed(0, 'CVE-2099-0001'), staged(0, 'CVE-2099-0001'))).toBe(
      true,
    );
  });

  it('fails on gaps, count mismatch, or field disagreement', () => {
    expect(
      verifyDenseStagedPrefix({
        staged: [staged(1, 'CVE-2099-0002')],
        parsed: [parsed(0, 'CVE-2099-0001'), parsed(1, 'CVE-2099-0002')],
        authoritativeCount: 1,
      }).ok,
    ).toBe(false);
    expect(
      verifyDenseStagedPrefix({
        staged: [staged(0, 'CVE-2099-0001')],
        parsed: [parsed(0, 'CVE-2099-0001')],
        authoritativeCount: 2,
      }).ok,
    ).toBe(false);
    const mismatchedCwe = staged(0, 'CVE-2099-0001');
    mismatchedCwe.cwes = ['CWE-89'];
    expect(
      verifyDenseStagedPrefix({
        staged: [mismatchedCwe],
        parsed: [parsed(0, 'CVE-2099-0001')],
        authoritativeCount: 1,
      }).ok,
    ).toBe(false);
  });
});
