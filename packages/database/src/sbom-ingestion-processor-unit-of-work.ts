import type {
  SbomIngestionProcessorRepositories,
  SbomIngestionProcessorUnitOfWork,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { isRootPrismaClient } from './guards.js';
import { createRepositories } from './repositories.js';
import { createSbomPersistence } from './sbom-persistence.js';

export function createSbomIngestionProcessorUnitOfWork(
  client: PrismaClientLike,
): SbomIngestionProcessorUnitOfWork {
  if (!isRootPrismaClient(client)) {
    throw new Error('SBOM ingestion processor unit of work requires the root Prisma client.');
  }

  return {
    async runInTransaction(work) {
      return client.$transaction(async (tx) => {
        const sbom = createSbomPersistence(tx);
        const repos = createRepositories(tx);
        const bundle: SbomIngestionProcessorRepositories = {
          ingestions: sbom.ingestions,
          backgroundJobs: sbom.backgroundJobs,
          auditEvents: repos.auditEvents,
        };
        return work(bundle);
      });
    },
  };
}
