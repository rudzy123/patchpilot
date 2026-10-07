/**
 * Tenant-scoped Finding inspection.
 * Construction performs no I/O. The read does not update a Finding.
 */

import { parseFindingInspectionCommand } from './command.js';
import { FINDING_INSPECTION_STATUSES, type FindingInspectionStatus } from './policy.js';
import type { FindingInspectionEvidenceBundle, FindingInspectionPort } from './port.js';
import {
  findingInspectionFailure,
  projectFindingInspection,
  type FindingInspectionResult,
} from './projection.js';

const LOAD_FAILURES = [
  'not_found',
  'evidence_unavailable',
  'malformed_persisted_state',
  'database_unavailable',
  'internal_failure',
] as const;

export function openFindingInspection(port: FindingInspectionPort) {
  return {
    async inspect(input: unknown): Promise<FindingInspectionResult> {
      const parsed = parseFindingInspectionCommand(input);
      if (!parsed.ok) {
        return findingInspectionFailure('internal_failure');
      }
      try {
        const loaded = await port.load({
          organizationId: parsed.command.organizationId,
          findingId: parsed.command.findingId,
        });
        if (!isClosedLoad(loaded)) {
          return findingInspectionFailure('internal_failure');
        }
        if (loaded.status !== 'ready') {
          return findingInspectionFailure(loaded.status);
        }
        return projectFindingInspection(loaded.bundle, parsed.command.findingId);
      } catch {
        return findingInspectionFailure('internal_failure');
      }
    },
  };
}

function isClosedLoad(
  value: unknown,
): value is
  | { readonly status: (typeof LOAD_FAILURES)[number] }
  | { readonly status: 'ready'; readonly bundle: FindingInspectionEvidenceBundle } {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const status = Object.getOwnPropertyDescriptor(value, 'status')?.value;
  if (status === 'ready') {
    return Object.getOwnPropertyDescriptor(value, 'bundle')?.value !== undefined;
  }
  return typeof status === 'string' && (LOAD_FAILURES as readonly string[]).includes(status);
}

export function isFindingInspectionStatus(value: unknown): value is FindingInspectionStatus {
  return (
    typeof value === 'string' && (FINDING_INSPECTION_STATUSES as readonly string[]).includes(value)
  );
}
