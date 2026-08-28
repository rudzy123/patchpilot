import {
  createArchiveAssetUseCase,
  createCreateAssetUseCase,
  createGetAssetUseCase,
  createListAssetEnvironmentsUseCase,
  createListAssetMembershipsUseCase,
  createListAssetTeamsUseCase,
  createListAssetsUseCase,
  createUpdateAssetUseCase,
  type AssetRepository,
  type Clock,
  type EnvironmentRepository,
  type MembershipRepository,
  type PersistenceUnitOfWork,
  type TeamRepository,
} from '@patchpilot/domain';

export type AssetRuntime = {
  list: ReturnType<typeof createListAssetsUseCase>;
  get: ReturnType<typeof createGetAssetUseCase>;
  create: ReturnType<typeof createCreateAssetUseCase>;
  update: ReturnType<typeof createUpdateAssetUseCase>;
  archive: ReturnType<typeof createArchiveAssetUseCase>;
  listEnvironments: ReturnType<typeof createListAssetEnvironmentsUseCase>;
  listTeams: ReturnType<typeof createListAssetTeamsUseCase>;
  listMemberships: ReturnType<typeof createListAssetMembershipsUseCase>;
};

export function createAssetRuntime(dependencies: {
  assets: Pick<AssetRepository, 'findDetailById' | 'listForOrganization'>;
  environments: Pick<EnvironmentRepository, 'listActiveOptions'>;
  teams: Pick<TeamRepository, 'listActiveOptions'>;
  memberships: Pick<MembershipRepository, 'listActiveOptions'>;
  unitOfWork: PersistenceUnitOfWork;
  clock: Clock;
}): AssetRuntime {
  const mutations = {
    unitOfWork: dependencies.unitOfWork,
    clock: dependencies.clock,
  };

  return {
    list: createListAssetsUseCase({ assets: dependencies.assets }),
    get: createGetAssetUseCase({ assets: dependencies.assets }),
    create: createCreateAssetUseCase(mutations),
    update: createUpdateAssetUseCase(mutations),
    archive: createArchiveAssetUseCase(mutations),
    listEnvironments: createListAssetEnvironmentsUseCase({
      environments: dependencies.environments,
    }),
    listTeams: createListAssetTeamsUseCase({ teams: dependencies.teams }),
    listMemberships: createListAssetMembershipsUseCase({
      memberships: dependencies.memberships,
    }),
  };
}
