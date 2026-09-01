import { describe, expect, it } from 'vitest';

import {
  FORBIDDEN_AUDIT_METADATA_KEYS,
  auditMetadataContainsForbiddenField,
  intelligenceAuditActions,
  intelligenceKevUpdatedAudit,
  intelligenceNormalizationCompletedAudit,
  intelligenceSnapshotStoredAudit,
  intelligenceSyncCompletedAudit,
  intelligenceSyncFailedAudit,
  intelligenceSyncNotModifiedAudit,
  intelligenceSyncQuarantinedAudit,
  intelligenceSyncRequestedAudit,
  intelligenceSyncStartedAudit,
} from './audit.js';

const SYNC_RUN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SNAPSHOT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const GENERATION_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const CORRELATION_ID = 'corr-intel-1';
const NOW = new Date('2026-08-31T16:00:00.000Z');

const metadata = {
  provider: 'cisa_kev' as const,
  sourceIdentifier: 'cisa_kev_json_catalog' as const,
  syncRunId: SYNC_RUN_ID,
  snapshotId: SNAPSHOT_ID,
  generationId: GENERATION_ID,
  byteLength: 2048,
  responseSha256: 'a'.repeat(64),
  entryCount: 3,
  parserVersion: '0.1.0',
  normalizationVersion: '1',
};

describe('intelligence audit commands', () => {
  it('emits system actor global subjects with safe counts and no membership', () => {
    const commands = [
      intelligenceSyncRequestedAudit(metadata, CORRELATION_ID, NOW),
      intelligenceSyncStartedAudit(metadata, CORRELATION_ID, NOW),
      intelligenceSnapshotStoredAudit(
        { ...metadata, snapshotId: SNAPSHOT_ID },
        CORRELATION_ID,
        NOW,
      ),
      intelligenceNormalizationCompletedAudit(
        { ...metadata, generationId: GENERATION_ID },
        CORRELATION_ID,
        NOW,
      ),
      intelligenceSyncCompletedAudit(metadata, CORRELATION_ID, NOW),
      intelligenceSyncNotModifiedAudit(metadata, CORRELATION_ID, NOW),
      intelligenceSyncFailedAudit(
        { ...metadata, failureCode: 'processing_failed' },
        CORRELATION_ID,
        NOW,
      ),
      intelligenceSyncQuarantinedAudit(
        { ...metadata, failureCode: 'schema_invalid' },
        CORRELATION_ID,
        NOW,
      ),
      intelligenceKevUpdatedAudit(metadata, CORRELATION_ID, NOW),
    ];
    expect(Object.values(intelligenceAuditActions)).toHaveLength(9);
    for (const command of commands) {
      expect(command.actorType).toBe('system');
      expect(command.correlationId).toBe(CORRELATION_ID);
      expect(command.actorMembershipId).toBeUndefined();
      expect(command.organizationId).toBeUndefined();
      expect(
        command.payload.metadata['entryCount'] === undefined ||
          typeof command.payload.metadata['entryCount'] === 'number',
      ).toBe(true);
      expect(command.payload.metadata).not.toHaveProperty('cves');
      expect(command.payload.metadata).not.toHaveProperty('objectKey');
      expect(command.payload.metadata).not.toHaveProperty('url');
      expect(command.payload.metadata).not.toHaveProperty('findingId');
    }
  });

  it('rejects forbidden metadata keys including CVE lists and Findings', () => {
    expect(FORBIDDEN_AUDIT_METADATA_KEYS).toContain('cves');
    expect(FORBIDDEN_AUDIT_METADATA_KEYS).toContain('findings');
    expect(auditMetadataContainsForbiddenField({ cves: ['CVE-2024-1'] })).toBe(true);
    expect(auditMetadataContainsForbiddenField({ entryCount: 1 })).toBe(false);
  });
});
