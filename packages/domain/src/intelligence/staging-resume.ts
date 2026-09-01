import type { IntelligenceKevParsedEntry } from './ports.js';
import type { KevNormalizedEntryRecord } from './records.js';

export type StagedPrefixVerification =
  { ok: true; resumeOrdinal: number } | { ok: false; code: 'generation_incomplete' };

function cwesEqual(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

export function parsedEntryMatchesStaged(
  parsed: IntelligenceKevParsedEntry,
  staged: KevNormalizedEntryRecord,
): boolean {
  if (parsed.ordinal !== staged.ordinal) {
    return false;
  }
  if (parsed.normalizedCve !== staged.normalizedCve) {
    return false;
  }
  if (parsed.vendorProject !== staged.vendorProject) {
    return false;
  }
  if (parsed.product !== staged.product) {
    return false;
  }
  if (parsed.vulnerabilityName !== staged.vulnerabilityName) {
    return false;
  }
  if (parsed.dateAdded !== staged.dateAdded) {
    return false;
  }
  if (parsed.shortDescription !== staged.shortDescription) {
    return false;
  }
  if (parsed.requiredAction !== staged.requiredAction) {
    return false;
  }
  if (parsed.dueDate !== staged.dueDate) {
    return false;
  }
  if (parsed.knownRansomwareCampaignUse !== staged.knownRansomwareCampaignUse) {
    return false;
  }
  if (parsed.rawKnownRansomwareCampaignUse !== staged.rawKnownRansomwareCampaignUse) {
    return false;
  }
  if (parsed.notes !== staged.notes) {
    return false;
  }
  return cwesEqual(parsed.cwes, staged.cwes);
}

export function verifyDenseStagedPrefix(input: {
  staged: readonly KevNormalizedEntryRecord[];
  parsed: readonly IntelligenceKevParsedEntry[];
  authoritativeCount: number;
}): StagedPrefixVerification {
  if (input.staged.length !== input.authoritativeCount) {
    return { ok: false, code: 'generation_incomplete' };
  }
  for (let index = 0; index < input.staged.length; index += 1) {
    const staged = input.staged[index];
    const parsed = input.parsed[index];
    if (staged === undefined || parsed === undefined || staged.ordinal !== index) {
      return { ok: false, code: 'generation_incomplete' };
    }
    if (!parsedEntryMatchesStaged(parsed, staged)) {
      return { ok: false, code: 'generation_incomplete' };
    }
  }
  return { ok: true, resumeOrdinal: input.staged.length };
}
