import { describe, expect, it } from 'vitest';

import type { AssetRecord } from '../records.js';
import type { SbomIngestionRecord, SbomRecord } from '../records.js';
import {
  createGetSbomIngestionUseCase,
  createGetSbomUseCase,
  createListSbomsUseCase,
} from './queries.js';
import type { SbomListQuery, SbomSummaryRecord } from './types.js';
import type { SbomActor } from './authorization.js';
import { ASSET_NOT_FOUND, ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from './errors.js';
import { SBOM_INGESTION_NOT_FOUND, SBOM_NOT_FOUND } from './errors.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ASSET_A = '33333333-3333-4333-8333-333333333333';
const ASSET_B = '44444444-4444-4444-8444-444444444444';
const SBOM_A = '55555555-5555-4555-8555-555555555555';
const SBOM_B = '66666666-6666-4666-8666-666666666666';
const INGESTION_A = '77777777-7777-4777-8777-777777777777';
const INGESTION_B = '88888888-8888-4888-8888-888888888888';
const USER = '99999999-9999-4999-8999-999999999999';
const SESSION = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const MEMBERSHIP = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOW = new Date('2026-08-31T12:00:00.000Z');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

describe('SBOM query use cases', () => {
  it('denies reads without organization context or sbom:read', async () => {
    const harness = createHarness();
    const missingOrg = await harness.list.execute({
      actor: actor({ organizationId: null, membershipId: null, permissions: ['sbom:read'] }),
      assetId: ASSET_A,
      query: { limit: 20 },
    });
    const viewerDenied = await harness.list.execute({
      actor: actor({ permissions: ['sbom:upload'] }),
      assetId: ASSET_A,
      query: { limit: 20 },
    });
    expect(missingOrg).toEqual({ ok: false, error: ORGANIZATION_CONTEXT_REQUIRED });
    expect(viewerDenied).toEqual({ ok: false, error: PERMISSION_DENIED });
  });

  it('hides foreign assets and SBOMs behind tenant-safe not-found', async () => {
    const harness = createHarness();
    const listed = await harness.list.execute({
      actor: actor(),
      assetId: ASSET_B,
      query: { limit: 20 },
    });
    const detail = await harness.get.execute({
      actor: actor(),
      assetId: ASSET_A,
      sbomId: SBOM_B,
    });
    const ingestion = await harness.getIngestion.execute({
      actor: actor(),
      assetId: ASSET_A,
      ingestionId: INGESTION_B,
    });
    const missingAsset = await harness.get.execute({
      actor: actor(),
      assetId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      sbomId: SBOM_A,
    });

    expect(listed).toEqual({ ok: false, error: ASSET_NOT_FOUND });
    expect(detail).toEqual({ ok: false, error: SBOM_NOT_FOUND });
    expect(ingestion).toEqual({ ok: false, error: SBOM_INGESTION_NOT_FOUND });
    expect(missingAsset).toEqual({ ok: false, error: ASSET_NOT_FOUND });
  });

  it('lists and reads only the authorized organization asset graph', async () => {
    const harness = createHarness();
    const listed = await harness.list.execute({
      actor: actor(),
      assetId: ASSET_A,
      query: { limit: 20 } satisfies SbomListQuery,
    });
    const detail = await harness.get.execute({
      actor: actor(),
      assetId: ASSET_A,
      sbomId: SBOM_A,
    });
    const ingestion = await harness.getIngestion.execute({
      actor: actor(),
      assetId: ASSET_A,
      ingestionId: INGESTION_A,
    });

    expect(listed.ok).toBe(true);
    if (!listed.ok) {
      return;
    }
    expect(listed.value.items.map((item) => item.summary.id)).toEqual([SBOM_A]);
    expect(listed.value.items[0]?.ingestion.id).toBe(INGESTION_A);
    expect(detail.ok).toBe(true);
    if (!detail.ok) {
      return;
    }
    expect(detail.value.sbom.id).toBe(SBOM_A);
    expect(detail.value.currentIngestion.id).toBe(INGESTION_A);
    expect(ingestion).toEqual({ ok: true, value: harness.ingestions.get(INGESTION_A) });
  });
});

function actor(
  overrides: {
    organizationId?: string | null;
    membershipId?: string | null;
    permissions?: readonly string[];
  } = {},
): SbomActor {
  return {
    userId: USER,
    sessionId: SESSION,
    organizationId: overrides.organizationId === undefined ? ORG_A : overrides.organizationId,
    membershipId: overrides.membershipId === undefined ? MEMBERSHIP : overrides.membershipId,
    permissions: overrides.permissions ?? ['sbom:read'],
  };
}

function createHarness() {
  const assets = new Map<string, AssetRecord>([
    [`${ORG_A}:${ASSET_A}`, asset(ORG_A, ASSET_A)],
    [`${ORG_B}:${ASSET_B}`, asset(ORG_B, ASSET_B)],
  ]);
  const sboms = new Map<string, SbomRecord>([
    [SBOM_A, sbom(ORG_A, ASSET_A, SBOM_A, SHA_A)],
    [SBOM_B, sbom(ORG_B, ASSET_B, SBOM_B, SHA_B)],
  ]);
  const ingestions = new Map<string, SbomIngestionRecord>([
    [INGESTION_A, ingestion(ORG_A, ASSET_A, SBOM_A, INGESTION_A)],
    [INGESTION_B, ingestion(ORG_B, ASSET_B, SBOM_B, INGESTION_B)],
  ]);
  const dependencies = {
    assets: {
      async findById(organizationId: string, id: string) {
        return assets.get(`${organizationId}:${id}`);
      },
    },
    sbomMetadata: {
      async listForAsset(organizationId: string, assetId: string) {
        const items = [...sboms.values()]
          .filter((row) => row.organizationId === organizationId && row.assetId === assetId)
          .map(toSummary);
        return { items, nextCursor: undefined };
      },
      async findByAssetAndId(organizationId: string, assetId: string, sbomId: string) {
        const row = sboms.get(sbomId);
        if (row === undefined || row.organizationId !== organizationId || row.assetId !== assetId) {
          return undefined;
        }
        return row;
      },
    },
    ingestions: {
      async findCurrentForSbom(organizationId: string, sbomId: string) {
        return [...ingestions.values()].find(
          (row) => row.organizationId === organizationId && row.sbomId === sbomId,
        );
      },
      async findByAssetAndId(organizationId: string, assetId: string, ingestionId: string) {
        const row = ingestions.get(ingestionId);
        if (row === undefined || row.organizationId !== organizationId || row.assetId !== assetId) {
          return undefined;
        }
        return row;
      },
    },
  };

  return {
    ingestions,
    list: createListSbomsUseCase(dependencies),
    get: createGetSbomUseCase(dependencies),
    getIngestion: createGetSbomIngestionUseCase(dependencies),
  };
}

function asset(organizationId: string, id: string): AssetRecord {
  return {
    id,
    organizationId,
    name: 'App',
    description: null,
    assetType: 'application',
    lifecycleStatus: 'active',
    environmentId: null,
    owningTeamId: null,
    businessCriticality: 'unspecified',
    internetExposure: 'unknown',
    dataClassification: 'unspecified',
    repositoryUrl: null,
    deploymentContext: null,
    lastObservedAt: null,
    lastSuccessfulSbomIngestionId: null,
    lastSuccessfulSbomIngestionAt: null,
    archivedAt: null,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function sbom(organizationId: string, assetId: string, id: string, sha256: string): SbomRecord {
  return {
    id,
    organizationId,
    assetId,
    objectKey: `org/${organizationId}/assets/${assetId}/sboms/sha256/${sha256}`,
    sha256,
    byteLength: 32,
    declaredContentType: 'application/json',
    specificationType: 'cyclonedx',
    specificationVersion: '1.6',
    source: 'upload',
    originalFilename: 'secret.cdx.json',
    uploadedByMembershipId: MEMBERSHIP,
    capturedAt: null,
    receivedAt: NOW,
    parserVersionLastSucceeded: '0.1.0',
    createdAt: NOW,
  };
}

function ingestion(
  organizationId: string,
  assetId: string,
  sbomId: string,
  id: string,
): SbomIngestionRecord {
  return {
    id,
    organizationId,
    sbomId,
    assetId,
    state: 'accepted',
    stage: 'validate',
    attemptNumber: 1,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    idempotencyKey: null,
    startedAt: null,
    completedAt: null,
    graphCompleteness: null,
    componentCount: null,
    dependencyEdgeCount: null,
    warningCount: null,
    failureCategory: null,
    failureCode: null,
    quarantineReason: null,
    leaseExpiresAt: new Date('2099-01-01T00:00:00.000Z'),
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function toSummary(row: SbomRecord): SbomSummaryRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    assetId: row.assetId,
    sha256: row.sha256,
    byteLength: row.byteLength,
    specificationType: row.specificationType,
    specificationVersion: row.specificationVersion,
    source: row.source,
    receivedAt: row.receivedAt,
    capturedAt: row.capturedAt,
    parserVersionLastSucceeded: row.parserVersionLastSucceeded,
  };
}
