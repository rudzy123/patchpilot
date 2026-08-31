import {
  createGetSbomIngestionUseCase,
  createGetSbomUseCase,
  createListSbomsUseCase,
  createUploadSbomUseCase,
  type AssetRepository,
  type Clock,
  type SbomIngestionPersistencePort,
  type SbomMetadataPersistencePort,
  type SbomObjectStoragePort,
  type SbomQueryDependencies,
  type SbomUploadIdempotencyPort,
  type SbomUploadLogger,
  type SbomUploadUnitOfWork,
  type UploadSbomDependencies,
} from '@patchpilot/domain';

export type SbomRuntime = {
  upload: ReturnType<typeof createUploadSbomUseCase>;
  list: ReturnType<typeof createListSbomsUseCase>;
  get: ReturnType<typeof createGetSbomUseCase>;
  getIngestion: ReturnType<typeof createGetSbomIngestionUseCase>;
};

export function createSbomRuntime(dependencies: {
  clock: Clock;
  createId: () => string;
  assets: Pick<AssetRepository, 'findById'>;
  uploadIdempotency: SbomUploadIdempotencyPort;
  sbomMetadata: Pick<
    SbomMetadataPersistencePort,
    'findByAssetAndHash' | 'findByAssetAndId' | 'listForAsset'
  >;
  ingestions: Pick<SbomIngestionPersistencePort, 'findByAssetAndId' | 'findCurrentForSbom'>;
  storage: SbomObjectStoragePort;
  unitOfWork: SbomUploadUnitOfWork;
  logger?: SbomUploadLogger;
}): SbomRuntime {
  const uploadDependencies: UploadSbomDependencies = {
    clock: dependencies.clock,
    createId: dependencies.createId,
    assets: dependencies.assets,
    uploadIdempotency: dependencies.uploadIdempotency,
    sbomMetadata: dependencies.sbomMetadata,
    ingestions: dependencies.ingestions,
    storage: dependencies.storage,
    unitOfWork: dependencies.unitOfWork,
    ...(dependencies.logger === undefined ? {} : { logger: dependencies.logger }),
  };
  const queries: SbomQueryDependencies = {
    assets: dependencies.assets,
    sbomMetadata: dependencies.sbomMetadata,
    ingestions: dependencies.ingestions,
  };

  return {
    upload: createUploadSbomUseCase(uploadDependencies),
    list: createListSbomsUseCase(queries),
    get: createGetSbomUseCase(queries),
    getIngestion: createGetSbomIngestionUseCase(queries),
  };
}
