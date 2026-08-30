import {
  SBOM_LIST_DEFAULT_LIMIT,
  SBOM_LIST_MAX_LIMIT,
  SBOM_LIST_MIN_LIMIT,
  err,
  ok,
  type PersistSbomMetadataInput,
  type Result,
  type SbomListPage,
  type SbomListQuery,
  type SbomMetadataPersistencePort,
  type SbomRecord,
} from '@patchpilot/domain';

import {
  isUuid,
  requirePositiveByteLength,
  requireSha256,
  requireVersionLabel,
  type PrismaClientLike,
} from './guards.js';
import { mapSbom, toSbomSummary } from './sbom-mappers.js';

export class PrismaSbomMetadataPersistence implements SbomMetadataPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async insert(input: PersistSbomMetadataInput): Promise<SbomRecord> {
    const row = await this.client.sbom.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.assetId,
        objectKey: input.objectKey,
        sha256: requireSha256(input.sha256, 'sha256'),
        byteLength: requirePositiveByteLength(input.byteLength, 'byteLength'),
        declaredContentType: input.declaredContentType,
        specificationType: input.specificationType,
        source: input.source,
        receivedAt: input.receivedAt,
        uploadedByMembershipId: input.uploadedByMembershipId,
        capturedAt: input.capturedAt,
      },
    });
    return mapSbom(row);
  }

  public async findById(organizationId: string, sbomId: string): Promise<SbomRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(sbomId)) {
      return undefined;
    }
    const row = await this.client.sbom.findFirst({
      where: { organizationId, id: sbomId },
    });
    return row === null ? undefined : mapSbom(row);
  }

  public async findByAssetAndId(
    organizationId: string,
    assetId: string,
    sbomId: string,
  ): Promise<SbomRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(assetId) || !isUuid(sbomId)) {
      return undefined;
    }
    const row = await this.client.sbom.findFirst({
      where: { organizationId, assetId, id: sbomId },
    });
    return row === null ? undefined : mapSbom(row);
  }

  public async findByAssetAndHash(
    organizationId: string,
    assetId: string,
    sha256: string,
  ): Promise<SbomRecord | undefined> {
    if (!isUuid(organizationId) || !isUuid(assetId)) {
      return undefined;
    }
    const row = await this.client.sbom.findFirst({
      where: {
        organizationId,
        assetId,
        sha256: requireSha256(sha256, 'sha256'),
      },
    });
    return row === null ? undefined : mapSbom(row);
  }

  public async listForAsset(
    organizationId: string,
    assetId: string,
    query?: SbomListQuery,
  ): Promise<SbomListPage> {
    if (!isUuid(organizationId) || !isUuid(assetId)) {
      return { items: [], nextCursor: undefined };
    }

    const limit = boundSbomListLimit(query?.limit);
    const cursor = query?.cursor;
    const rows = await this.client.sbom.findMany({
      where: {
        organizationId,
        assetId,
        ...(cursor === undefined
          ? {}
          : {
              OR: [
                { receivedAt: { lt: new Date(cursor.r) } },
                { receivedAt: new Date(cursor.r), id: { lt: cursor.i } },
              ],
            }),
      },
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
    });

    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const last = pageRows[pageRows.length - 1];
    return {
      items: pageRows.map((row) => toSbomSummary(mapSbom(row))),
      nextCursor:
        hasMore && last !== undefined
          ? { v: 1, r: last.receivedAt.toISOString(), i: last.id }
          : undefined,
    };
  }

  public async recordSuccessfulParser(
    organizationId: string,
    sbomId: string,
    parserVersion: string,
    specificationVersion: SbomRecord['specificationVersion'],
  ): Promise<Result<SbomRecord>> {
    if (!isUuid(organizationId) || !isUuid(sbomId)) {
      return err({ code: 'not_found', message: 'SBOM was not found.' });
    }

    const updated = await this.client.sbom.updateMany({
      where: { organizationId, id: sbomId },
      data: {
        parserVersionLastSucceeded: requireVersionLabel(parserVersion, 'parserVersion'),
        specificationVersion,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'not_found', message: 'SBOM was not found.' });
    }

    const row = await this.findById(organizationId, sbomId);
    if (row === undefined) {
      return err({ code: 'not_found', message: 'SBOM was not found.' });
    }
    return ok(row);
  }
}

export { isRootPrismaClient } from './guards.js';

function boundSbomListLimit(limit: number | undefined): number {
  if (limit === undefined) {
    return SBOM_LIST_DEFAULT_LIMIT;
  }
  if (!Number.isInteger(limit) || limit < SBOM_LIST_MIN_LIMIT) {
    return SBOM_LIST_MIN_LIMIT;
  }
  if (limit > SBOM_LIST_MAX_LIMIT) {
    return SBOM_LIST_MAX_LIMIT;
  }
  return limit;
}
