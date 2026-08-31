import type {
  BackgroundJobExecutionPort,
  ComponentGraphPersistencePort,
  OutboxRelayPersistencePort,
  SbomIngestionPersistencePort,
  SbomMetadataPersistencePort,
  SbomUploadIdempotencyPort,
} from '@patchpilot/domain';

import { PrismaBackgroundJobExecution } from './background-job-execution.js';
import { PrismaComponentGraphPersistence } from './component-graph-persistence.js';
import type { PrismaClientLike } from './guards.js';
import { PrismaOutboxRelayPersistence } from './outbox-relay-persistence.js';
import { PrismaSbomIngestionPersistence } from './sbom-ingestion-persistence.js';
import { PrismaSbomMetadataPersistence } from './sbom-metadata-persistence.js';
import { PrismaSbomUploadIdempotency } from './sbom-upload-idempotency.js';

export type SbomPersistenceAdapters = {
  sbomMetadata: SbomMetadataPersistencePort;
  ingestions: SbomIngestionPersistencePort;
  uploadIdempotency: SbomUploadIdempotencyPort;
  outboxRelay: OutboxRelayPersistencePort;
  backgroundJobs: BackgroundJobExecutionPort;
  componentGraph: ComponentGraphPersistencePort;
};

export function createSbomPersistence(client: PrismaClientLike): SbomPersistenceAdapters {
  return {
    sbomMetadata: new PrismaSbomMetadataPersistence(client),
    ingestions: new PrismaSbomIngestionPersistence(client),
    uploadIdempotency: new PrismaSbomUploadIdempotency(client),
    outboxRelay: new PrismaOutboxRelayPersistence(client),
    backgroundJobs: new PrismaBackgroundJobExecution(client),
    componentGraph: new PrismaComponentGraphPersistence(client),
  };
}
