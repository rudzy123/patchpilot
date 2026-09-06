/**
 * Session 11 Batch 6B resume-inspection adapter. Read-only lookups required by
 * disabled acquisition orchestration. No schema change. No catalog activation.
 */

import type { PrismaClient } from '@prisma/client';
import { OSV_PROVIDER_IDENTIFIER } from '@patchpilot/vulnerability-intelligence';
import type {
  OsvParsedAdvisoryRevision,
  OsvParserAttempt,
  OsvQuarantineRecord,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';
import { mapParsedRevision, mapParserAttempt, mapQuarantine } from './osv-acquisition-mappers.js';

const ROOT_CLIENT_REQUIRED = 'OSV acquisition inspection requires the root Prisma client.';

export class OsvAcquisitionInspectionFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvAcquisitionInspectionFailure';
  }
}

export function createOsvAcquisitionResumeInspection(client: PrismaClient): {
  findProviderObjectId(input: { readonly providerObjectKeyDigest: string }): Promise<string | null>;
  findParserAttemptsBySnapshot(snapshotId: string): Promise<readonly OsvParserAttempt[]>;
  findParsedRevisionBySnapshot(snapshotId: string): Promise<OsvParsedAdvisoryRevision | null>;
  findQuarantinesForDigest(input: {
    readonly catalogGenerationId: string;
    readonly providerObjectKeyDigest: string;
  }): Promise<readonly OsvQuarantineRecord[]>;
} {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvAcquisitionInspectionFailure(ROOT_CLIENT_REQUIRED);
  }

  return {
    async findProviderObjectId(input) {
      const row = await client.osvProviderObject.findUnique({
        where: {
          providerIdentifier_providerObjectKeyDigest: {
            providerIdentifier: OSV_PROVIDER_IDENTIFIER,
            providerObjectKeyDigest: input.providerObjectKeyDigest,
          },
        },
        select: { id: true },
      });
      return row?.id ?? null;
    },

    async findParserAttemptsBySnapshot(snapshotId) {
      const rows = await client.osvParserAttempt.findMany({
        where: { snapshotId },
        orderBy: { attemptNumber: 'asc' },
      });
      return rows.map((row) => mapParserAttempt(row));
    },

    async findParsedRevisionBySnapshot(snapshotId) {
      const row = await client.osvParsedAdvisoryRevision.findFirst({
        where: { snapshotId },
        include: { documentAttachment: true, providerGeneration: true },
      });
      if (row === null) {
        return null;
      }
      return mapParsedRevision({
        ...row,
        providerObjectId: row.providerGeneration.providerObjectId,
        providerObjectKeyDigest: row.providerGeneration.providerObjectKeyDigest,
        providerGeneration: row.providerGeneration.providerGeneration,
      });
    },

    async findQuarantinesForDigest(input) {
      const rows = await client.osvQuarantineRecord.findMany({
        where: {
          catalogGenerationId: input.catalogGenerationId,
          providerObjectKeyDigest: input.providerObjectKeyDigest,
        },
        orderBy: { recordedAt: 'asc' },
      });
      return rows.map((row) => mapQuarantine(row));
    },
  };
}
