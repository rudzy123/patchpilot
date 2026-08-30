import { randomUUID } from 'node:crypto';

import type { PrismaClient } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  buildComponentIdentityKey,
  type NormalizedComponent,
  type NormalizedComponentGraph,
} from '@patchpilot/domain';

export const SHA_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const SHA_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
export const PARSER_VERSION = '0.1.0';
export const NORMALIZATION_VERSION = '1';

export async function createOrg(prisma: PrismaClient, slug: string) {
  return prisma.organization.create({ data: { slug, name: `Org ${slug}` } });
}

export async function createAsset(prisma: PrismaClient, organizationId: string, name: string) {
  return prisma.asset.create({
    data: { organizationId, name, assetType: 'application' },
  });
}

export async function createSbom(
  prisma: PrismaClient,
  input: {
    organizationId: string;
    assetId: string;
    sha256: string;
    receivedAt: Date;
    objectKey?: string;
  },
) {
  return prisma.sbom.create({
    data: {
      organizationId: input.organizationId,
      assetId: input.assetId,
      objectKey:
        input.objectKey ??
        `org/${input.organizationId}/assets/${input.assetId}/sboms/sha256/${input.sha256}`,
      sha256: input.sha256,
      byteLength: 32,
      declaredContentType: 'application/json',
      receivedAt: input.receivedAt,
    },
  });
}

export async function createProcessingIngestion(
  prisma: PrismaClient,
  input: {
    organizationId: string;
    sbomId: string;
    assetId: string;
    createdAt?: Date;
    parserVersion?: string;
    id?: string;
  },
) {
  return prisma.sbomIngestion.create({
    data: {
      ...(input.id === undefined ? {} : { id: input.id }),
      organizationId: input.organizationId,
      sbomId: input.sbomId,
      assetId: input.assetId,
      parserVersion: input.parserVersion ?? PARSER_VERSION,
      normalizationVersion: NORMALIZATION_VERSION,
      state: 'processing',
      stage: 'persist_graph',
      startedAt: new Date('2026-08-30T12:00:00.000Z'),
      ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
    },
  });
}

export function resolvedComponent(input: {
  name: string;
  bomRef: string;
  version: string;
  ecosystem?: string | null;
}): NormalizedComponent {
  const ecosystem = input.ecosystem === undefined ? 'npm' : input.ecosystem;
  const identity = buildComponentIdentityKey({
    identityState: ecosystem === null ? 'unsupported' : 'resolved',
    versionlessPurl: ecosystem === null ? null : `pkg:npm/${input.name}`,
    ecosystem,
    namespace: null,
    name: input.name,
    bomRef: input.bomRef,
  });
  if (!identity.ok) {
    throw new Error(identity.error.message);
  }
  return {
    bomRef: input.bomRef,
    name: input.name,
    namespace: null,
    ecosystem,
    identityState: ecosystem === null ? 'unsupported' : 'resolved',
    versionlessPurl: ecosystem === null ? null : `pkg:npm/${input.name}`,
    versionedPurl: ecosystem === null ? null : `pkg:npm/${input.name}@${input.version}`,
    version: { kind: 'known', value: input.version },
    isDirect: true,
    identityKey: identity.value,
  };
}

export function unknownVersionComponent(name: string, bomRef: string): NormalizedComponent {
  const identity = buildComponentIdentityKey({
    identityState: 'unsupported',
    versionlessPurl: null,
    ecosystem: null,
    namespace: null,
    name,
    bomRef,
  });
  if (!identity.ok) {
    throw new Error(identity.error.message);
  }
  return {
    bomRef,
    name,
    namespace: null,
    ecosystem: null,
    identityState: 'unsupported',
    versionlessPurl: null,
    versionedPurl: null,
    version: { kind: 'unknown' },
    isDirect: null,
    identityKey: identity.value,
  };
}

export function graphOf(
  components: readonly NormalizedComponent[],
  edges: NormalizedComponentGraph['edges'] = [],
  completeness: NormalizedComponentGraph['graphCompleteness'] = 'complete',
): NormalizedComponentGraph {
  return {
    specificationVersion: '1.6',
    graphCompleteness: completeness,
    components,
    edges,
    warnings: [],
    componentCount: components.length,
    dependencyEdgeCount: edges.length,
    warningCount: 0,
    capturedAt: null,
    parserVersion: PARSER_VERSION,
    normalizationVersion: NORMALIZATION_VERSION,
  };
}

export function newCorrelationId(): string {
  return `corr-${randomUUID()}`;
}

export function outboxPayload() {
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    ids: { sbomId: randomUUID() },
    metadata: { reason: 'test' },
  };
}
