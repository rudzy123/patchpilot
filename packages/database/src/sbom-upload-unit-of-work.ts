import type { SbomUploadRepositories, SbomUploadUnitOfWork } from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { isRootPrismaClient } from './guards.js';
import { createRepositories } from './repositories.js';
import { createSbomPersistence } from './sbom-persistence.js';

export function createSbomUploadUnitOfWork(client: PrismaClientLike): SbomUploadUnitOfWork {
  if (!isRootPrismaClient(client)) {
    throw new Error('SBOM upload unit of work requires the root Prisma client.');
  }

  return {
    async runInTransaction(work) {
      return client.$transaction(async (tx) => {
        const sbom = createSbomPersistence(tx);
        const repos = createRepositories(tx);
        const bundle: SbomUploadRepositories = {
          assets: repos.assets,
          sbomMetadata: sbom.sbomMetadata,
          ingestions: sbom.ingestions,
          uploadIdempotency: sbom.uploadIdempotency,
          auditEvents: repos.auditEvents,
          outboxEvents: repos.outboxEvents,
        };
        return work(bundle);
      });
    },
  };
}
