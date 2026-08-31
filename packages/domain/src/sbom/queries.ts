import type { AssetRepository } from '../ports.js';
import type { SbomIngestionRecord, SbomRecord } from '../records.js';
import { err, ok, type Result } from '../result.js';
import { authorizeSbomRead, type SbomActor } from './authorization.js';
import { ASSET_NOT_FOUND, SBOM_INGESTION_NOT_FOUND, SBOM_NOT_FOUND } from './errors.js';
import type { SbomIngestionPersistencePort, SbomMetadataPersistencePort } from './ports.js';
import type { SbomListCursor, SbomListQuery, SbomSummaryRecord } from './types.js';

export type SbomListItemRecord = {
  summary: SbomSummaryRecord;
  ingestion: SbomIngestionRecord;
};

export type SbomQueryListPage = {
  items: SbomListItemRecord[];
  nextCursor: SbomListCursor | undefined;
};

export type SbomDetailRecord = {
  sbom: SbomRecord;
  currentIngestion: SbomIngestionRecord;
};

export type ListSbomsInput = {
  actor: SbomActor;
  assetId: string;
  query: SbomListQuery;
};

export type GetSbomInput = {
  actor: SbomActor;
  assetId: string;
  sbomId: string;
};

export type GetSbomIngestionInput = {
  actor: SbomActor;
  assetId: string;
  ingestionId: string;
};

export type SbomQueryDependencies = {
  assets: Pick<AssetRepository, 'findById'>;
  sbomMetadata: Pick<SbomMetadataPersistencePort, 'listForAsset' | 'findByAssetAndId'>;
  ingestions: Pick<SbomIngestionPersistencePort, 'findCurrentForSbom' | 'findByAssetAndId'>;
};

export function createListSbomsUseCase(dependencies: SbomQueryDependencies) {
  return {
    execute(input: ListSbomsInput): Promise<Result<SbomQueryListPage>> {
      return executeListSboms(dependencies, input);
    },
  };
}

export function createGetSbomUseCase(dependencies: SbomQueryDependencies) {
  return {
    execute(input: GetSbomInput): Promise<Result<SbomDetailRecord>> {
      return executeGetSbom(dependencies, input);
    },
  };
}

export function createGetSbomIngestionUseCase(dependencies: SbomQueryDependencies) {
  return {
    execute(input: GetSbomIngestionInput): Promise<Result<SbomIngestionRecord>> {
      return executeGetSbomIngestion(dependencies, input);
    },
  };
}

async function executeListSboms(
  dependencies: SbomQueryDependencies,
  input: ListSbomsInput,
): Promise<Result<SbomQueryListPage>> {
  const authorized = authorizeSbomRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const asset = await dependencies.assets.findById(authorized.value.organizationId, input.assetId);
  if (asset === undefined) {
    return err(ASSET_NOT_FOUND);
  }

  const page = await dependencies.sbomMetadata.listForAsset(
    authorized.value.organizationId,
    input.assetId,
    input.query,
  );
  const items: SbomListItemRecord[] = [];
  for (const summary of page.items) {
    const ingestion = await dependencies.ingestions.findCurrentForSbom(
      authorized.value.organizationId,
      summary.id,
    );
    if (ingestion === undefined) {
      continue;
    }
    items.push({ summary, ingestion });
  }

  return ok({
    items,
    nextCursor: page.nextCursor,
  });
}

async function executeGetSbom(
  dependencies: SbomQueryDependencies,
  input: GetSbomInput,
): Promise<Result<SbomDetailRecord>> {
  const authorized = authorizeSbomRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const asset = await dependencies.assets.findById(authorized.value.organizationId, input.assetId);
  if (asset === undefined) {
    return err(ASSET_NOT_FOUND);
  }

  const sbom = await dependencies.sbomMetadata.findByAssetAndId(
    authorized.value.organizationId,
    input.assetId,
    input.sbomId,
  );
  if (sbom === undefined) {
    return err(SBOM_NOT_FOUND);
  }

  const currentIngestion = await dependencies.ingestions.findCurrentForSbom(
    authorized.value.organizationId,
    sbom.id,
  );
  if (currentIngestion === undefined) {
    return err(SBOM_NOT_FOUND);
  }

  return ok({ sbom, currentIngestion });
}

async function executeGetSbomIngestion(
  dependencies: SbomQueryDependencies,
  input: GetSbomIngestionInput,
): Promise<Result<SbomIngestionRecord>> {
  const authorized = authorizeSbomRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const asset = await dependencies.assets.findById(authorized.value.organizationId, input.assetId);
  if (asset === undefined) {
    return err(ASSET_NOT_FOUND);
  }

  const ingestion = await dependencies.ingestions.findByAssetAndId(
    authorized.value.organizationId,
    input.assetId,
    input.ingestionId,
  );
  if (ingestion === undefined) {
    return err(SBOM_INGESTION_NOT_FOUND);
  }

  return ok(ingestion);
}
