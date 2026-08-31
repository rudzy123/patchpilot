import { UnrecoverableError } from 'bullmq';
import { describe, expect, it } from 'vitest';

import { SBOM_INGEST_JOB_TYPE } from '@patchpilot/domain';

import { processSbomIngestQueueJob } from './sbom-ingest-processor.js';
import {
  BACKGROUND_JOB_WORKER_IDENTIFIER_MAX_LENGTH,
  createBackgroundJobWorkerIdentifier,
} from './worker-identifier.js';

describe('SBOM ingest queue processor', () => {
  it('completes skipped, completed, and terminal outcomes without throwing', async () => {
    const logs: Array<{ level: string; bindings: Record<string, unknown>; message: string }> = [];
    const logger = {
      info(bindings: Record<string, unknown>, message: string) {
        logs.push({ level: 'info', bindings, message });
      },
      warn(bindings: Record<string, unknown>, message: string) {
        logs.push({ level: 'warn', bindings, message });
      },
    };

    await processSbomIngestQueueJob(
      { name: SBOM_INGEST_JOB_TYPE, id: 'job-1', data: { invalid: true } },
      async () => ({ kind: 'skipped' }),
      logger,
    );
    await processSbomIngestQueueJob(
      { name: SBOM_INGEST_JOB_TYPE, id: 'job-2', data: {} },
      async () => ({ kind: 'completed' }),
      logger,
    );
    await processSbomIngestQueueJob(
      { name: SBOM_INGEST_JOB_TYPE, id: 'job-3', data: {} },
      async () => ({ kind: 'rejected', code: 'schema_invalid' }),
      logger,
    );

    expect(logs.map((row) => row.bindings['outcome'])).toEqual([
      'skipped',
      'completed',
      'rejected',
    ]);
    expect(JSON.stringify(logs)).not.toMatch(/objectKey|filename|bomFormat/);
  });

  it('throws so BullMQ retries retryable infrastructure failures', async () => {
    await expect(
      processSbomIngestQueueJob(
        { name: SBOM_INGEST_JOB_TYPE, id: 'job-4', data: {} },
        async () => ({ kind: 'retry', code: 'storage_timeout' }),
        {
          info() {
            return;
          },
          warn() {
            return;
          },
        },
      ),
    ).rejects.toThrow(/will retry/);
  });

  it('does not retry unexpected job types', async () => {
    await expect(
      processSbomIngestQueueJob(
        { name: 'other.job', id: 'job-5', data: {} },
        async () => ({ kind: 'completed' }),
        {
          info() {
            return;
          },
          warn() {
            return;
          },
        },
      ),
    ).rejects.toBeInstanceOf(UnrecoverableError);
  });
});

describe('background job worker identifier', () => {
  it('stays within the VARCHAR(128) column', () => {
    const identifier = createBackgroundJobWorkerIdentifier('a'.repeat(200), 1);
    expect(identifier.length).toBe(BACKGROUND_JOB_WORKER_IDENTIFIER_MAX_LENGTH);
    expect(createBackgroundJobWorkerIdentifier('host', 42)).toBe('host:42');
  });
});
