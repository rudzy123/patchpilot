import { describe, expect, it } from 'vitest';

import {
  auditActorTypes,
  boundPageSize,
  DEFAULT_PAGE_SIZE,
  err,
  errorCodes,
  evidenceKinds,
  findingStates,
  graphCompletenessValues,
  intelligenceProviders,
  intelligenceSyncRunStates,
  intelligenceSyncRunTerminalStates,
  kevGenerationStates,
  kevMembershipStatuses,
  forbiddenIdentityFieldNames,
  CVE_IDENTITY_BATCH_LOOKUP_MAX,
  MAX_PAGE_SIZE,
  membershipRoles,
  MIN_PAGE_SIZE,
  ok,
  organizationStatuses,
  passwordHashAlgorithms,
  riskPolicyScopes,
  sbomSpecificationVersions,
  session8IngestionStages,
  session8IngestionTerminalStates,
  session8UnusedIngestionStages,
  sessionAuthenticationMethods,
  type AssetRepository,
  type EnvironmentRepository,
  type FindingRepository,
  type MembershipRepository,
  type OrganizationRepository,
  type TeamRepository,
} from './index.js';

describe('result boundary', () => {
  it('wraps success and failure without product entities', () => {
    expect(ok(1)).toEqual({ ok: true, value: 1 });
    expect(err({ code: 'internal', message: 'boom' }).ok).toBe(false);
  });

  it('exposes the API error taxonomy', () => {
    expect(errorCodes).toContain('validation');
    expect(errorCodes).not.toContain('organization');
  });
});

describe('lifecycle catalogs', () => {
  it('uses canonical organization and membership states', () => {
    expect(organizationStatuses).toEqual(['active', 'archived']);
    expect(membershipRoles).toEqual(['owner', 'admin', 'member', 'viewer']);
    expect(findingStates).not.toContain('reopened');
    expect(findingStates).not.toContain('assigned');
    expect(riskPolicyScopes).toEqual(['builtin', 'organization']);
    expect(evidenceKinds).toContain('export_snapshot');
    expect(auditActorTypes).toEqual(['user', 'system', 'instance_operator', 'anonymous']);
    expect(passwordHashAlgorithms).toEqual(['argon2id']);
    expect(sessionAuthenticationMethods).toEqual(['password']);
  });

  it('closes Session 8 graph completeness and ingestion stages', () => {
    expect(graphCompletenessValues).toEqual(['empty', 'no_dependencies', 'partial', 'complete']);
    expect(session8IngestionStages).toEqual(['validate', 'parse', 'persist_graph']);
    expect(session8UnusedIngestionStages).toEqual(['correlate', 'enrich', 'score']);
    expect(session8IngestionTerminalStates).toEqual([
      'completed',
      'rejected',
      'quarantined',
      'failed',
    ]);
    expect(sbomSpecificationVersions).not.toContain('1.7');
  });

  it('closes Session 9 intelligence providers, sync-run states, and generation states', () => {
    expect(intelligenceProviders).toEqual(['cisa_kev', 'osv']);
    expect(intelligenceSyncRunStates[0]).toBe('requested');
    expect(intelligenceSyncRunTerminalStates).toEqual([
      'completed',
      'not_modified',
      'failed',
      'quarantined',
    ]);
    expect(kevGenerationStates).toEqual([
      'staging',
      'complete',
      'active',
      'superseded',
      'abandoned',
    ]);
    expect(intelligenceSyncRunStates).not.toContain('match');
  });

  it('exposes canonical CVE identity without Finding or tenant fields', () => {
    expect(CVE_IDENTITY_BATCH_LOOKUP_MAX).toBe(100);
    expect(kevMembershipStatuses).toEqual(['unavailable', 'absent', 'listedInActiveKev']);
    expect(forbiddenIdentityFieldNames).toContain('organizationId');
    expect(forbiddenIdentityFieldNames).toContain('findingId');
    expect(forbiddenIdentityFieldNames).toContain('osvId');
  });

  it('exports the active-catalog membership use case and closed freshness values', async () => {
    const domainPublic = await import('./index.js');
    expect('createQueryActiveKevMembershipUseCase' in domainPublic).toBe(true);
    expect('parseQueryActiveKevMembershipInput' in domainPublic).toBe(true);
    expect('deriveActiveKevCatalogFreshness' in domainPublic).toBe(true);
    expect('boundCveIdentityListLimit' in domainPublic).toBe(false);
    expect(domainPublic.activeKevCatalogFreshnessValues).toEqual([
      'current',
      'stale',
      'disabled_with_history',
    ]);
  });
});

describe('page size bounds', () => {
  it('defaults and clamps page size', () => {
    expect(boundPageSize(undefined)).toBe(DEFAULT_PAGE_SIZE);
    expect(boundPageSize(0)).toBe(MIN_PAGE_SIZE);
    expect(boundPageSize(1000)).toBe(MAX_PAGE_SIZE);
    expect(boundPageSize(37)).toBe(37);
  });
});

describe('tenant repository ports', () => {
  it('require organizationId as the first argument on tenant-owned lookups', () => {
    const organizationRepo: Pick<OrganizationRepository, 'findById'> = {
      findById: async (organizationId: string, id: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
    };
    const findingRepo: Pick<FindingRepository, 'findById'> = {
      findById: async (organizationId: string, id: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
    };

    void organizationRepo.findById('org', 'id');
    void findingRepo.findById('org', 'id');
    expect(organizationRepo.findById.length).toBe(2);
    expect(findingRepo.findById.length).toBe(2);
  });

  it('requires organizationId on asset detail, list, and option queries', () => {
    const assets: Pick<
      AssetRepository,
      'findDetailById' | 'listForOrganization' | 'createAggregate' | 'compareAndSetUpdate'
    > = {
      findDetailById: async (organizationId: string, id: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
      listForOrganization: async (organizationId: string, _query?) => {
        expect(organizationId.length).toBeGreaterThan(0);
        return { items: [], nextCursor: undefined };
      },
      createAggregate: async (organizationId: string, command) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(command.name.length).toBeGreaterThan(0);
        return err({ code: 'forbidden', message: 'Organization context is required.' });
      },
      compareAndSetUpdate: async (organizationId: string, assetId: string, command) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(assetId.length).toBeGreaterThan(0);
        expect(command.expectedVersion).toBeGreaterThan(0);
        return err({ code: 'forbidden', message: 'Organization context is required.' });
      },
    };
    const environments: Pick<EnvironmentRepository, 'listActiveOptions'> = {
      listActiveOptions: async (organizationId: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        return { items: [], nextCursor: undefined };
      },
    };
    const teams: Pick<TeamRepository, 'listActiveOptions'> = {
      listActiveOptions: async (organizationId: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        return { items: [], nextCursor: undefined };
      },
    };
    const memberships: Pick<MembershipRepository, 'listActiveOptions'> = {
      listActiveOptions: async (organizationId: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        return { items: [], nextCursor: undefined };
      },
    };

    void assets.findDetailById('org', 'asset');
    void assets.listForOrganization('org');
    void assets.createAggregate('org', {
      name: 'demo',
      assetType: 'application',
      businessCriticality: 'unspecified',
      internetExposure: 'unknown',
      dataClassification: 'unspecified',
      owners: [],
      tags: [],
      externalIdentifiers: [],
    });
    void assets.compareAndSetUpdate('org', 'asset', { expectedVersion: 1, name: 'demo' });
    void environments.listActiveOptions('org');
    void teams.listActiveOptions('org');
    void memberships.listActiveOptions('org');
    expect(assets.findDetailById.length).toBe(2);
    expect(assets.listForOrganization.length).toBe(2);
    expect(assets.createAggregate.length).toBe(2);
    expect(assets.compareAndSetUpdate.length).toBe(3);
    expect(environments.listActiveOptions.length).toBe(1);
    expect(teams.listActiveOptions.length).toBe(1);
    expect(memberships.listActiveOptions.length).toBe(1);
  });
});
